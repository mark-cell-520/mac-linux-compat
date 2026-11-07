#!/bin/bash
# MLC v1 验证脚本：构建测试载荷并逐项检查兼容层能力
set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REAL_SRC="$PROJECT_ROOT/src"
TESTS="$PROJECT_ROOT/tests"
PASS=0; FAIL=0

# ---------- 看门狗包装器（2026-11-07 审计追加）----------
# macOS 没有 timeout 命令，而 mlc-core 偶发无限空转（客户机 sh -c 执行外部命令
# 那条路径）。2026-11-07 实测：一个 rootfs 冒烟循环因此跑了 6 小时，泄漏出 36 个
# 各占约 30% CPU 的孤儿进程，load average 37.59，只能手工清理。
# 套件里有 35 个调用点，逐个包看门狗改动太大且容易漏。这里在临时目录放两个
# 同名包装器，把 SRC 指过去，所有调用点自动获得超时保护，无需逐处改写。
# 超时按进程组整组强杀（子进程自己 setpgrp），绝不留孤儿。
# 超时值可用 MLC_CALL_TIMEOUT 调，单位秒。
WRAP="${TMPDIR:-/tmp}/mlc-verify-wrap"
rm -rf "$WRAP"; mkdir -p "$WRAP"
for t in mlc-core mlc; do
    sed -e "s|@REAL@|$PROJECT_ROOT/src/$t|g" > "$WRAP/$t" <<'EOF'
#!/bin/bash
# 自动生成的看门狗包装器：给 @REAL@ 加超时保护，超时整组强杀。
real="@REAL@"
tmo="${MLC_CALL_TIMEOUT:-120}"
perl -e '
    my $tmo = shift @ARGV;
    my $pid = fork;
    if (!$pid) { setpgrp(0,0); exec @ARGV; exit 127; }
    my $to = 0;
    local $SIG{ALRM} = sub {
        $to = 1;
        kill "TERM", -$pid;
        sleep 1;
        kill "KILL", -$pid;
    };
    alarm $tmo;
    waitpid($pid, 0);
    my $rc = $?;
    alarm 0;
    if ($to) { print STDERR "[mlc][看门狗] 超过 ${tmo}s 未结束，已整组强杀\n"; exit 124; }
    exit $rc >> 8;
' "$tmo" "$real" "$@"
EOF
    chmod +x "$WRAP/$t"
done
SRC="$WRAP"
trap 'rm -rf "$WRAP"' EXIT

ok()   { echo "  [通过] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [失败] $1"; FAIL=$((FAIL+1)); }

echo "=== MLC v1 验证 ==="

# 0. 构建核心
# REAL_SRC 是真实源码目录：$SRC 已被上面的看门狗包装器占用，构建必须落到真身上，
# 否则 clang 会去包装器目录里找 mlc-core.c。
echo "[0] 构建 mlc-core"
if clang -O2 -Wall -o "$REAL_SRC/mlc-core" "$REAL_SRC/mlc-core.c" 2>"$TESTS/.build.err"; then
    ok "编译"
else
    bad "编译"
    echo "  --- clang 输出 ---"
    sed 's/^/  /' "$TESTS/.build.err"
    rm -f "$TESTS/.build.err"
    exit 1
fi
rm -f "$TESTS/.build.err"

# 1. 构建测试载荷（位置无关 ET_DYN ELF）
echo "[1] 构建测试载荷"
python3 "$TESTS/mkelf.py" "$TESTS/test.s" "$TESTS/test.elf" >/dev/null 2>&1 && ok "mkelf 生成" || bad "mkelf 生成"
python3 "$TESTS/mkelf.py" "$TESTS/regs.s" "$TESTS/regs.elf" >/dev/null 2>&1 && ok "regs 载荷生成" || bad "regs 载荷生成"
python3 "$TESTS/mkelf.py" "$TESTS/tp.s" "$TESTS/tp.elf" >/dev/null 2>&1 && ok "tp 载荷生成" || bad "tp 载荷生成"
python3 "$TESTS/mkelf.py" "$TESTS/poll.s" "$TESTS/poll.elf" >/dev/null 2>&1 && ok "poll 载荷生成" || bad "poll 载荷生成"
# 目录列举与文件读入的目标用 rootfs 内的自建子目录：
# 客户机看到的 / 就是 rootfs（v1.2 路径重写语义），不能写真实 /tmp
GUEST_TMP="$PROJECT_ROOT/rootfs/sysroot/tmp/mlc-dent-test"
rm -rf "$GUEST_TMP" && mkdir -p "$GUEST_TMP"
echo "MLC v1 测试内容" > "$GUEST_TMP/mlc-test.txt"

# 2. 运行并逐项检查输出
echo "[2] 运行客户机"
OUT=$("$SRC/mlc-core" "$TESTS/test.elf" 2>/dev/null)
RC=$?
[ $RC -eq 0 ] && ok "客户机退出码 0" || bad "客户机退出码 $RC"

echo "$OUT" | grep -q "MLC: hello!" && ok "write 系统调用" || bad "write 系统调用"
echo "$OUT" | grep -q "aarch64"     && ok "uname（报告 Linux/aarch64）" || bad "uname"
echo "$OUT" | grep -q "MLC v1 测试内容" && ok "openat+read 文件读入" || bad "文件读入"
echo "$OUT" | grep -q "mlc-test.txt" && ok "getdents64 目录列举" || bad "getdents64"

# 2b. M1 客户机指针与地址空间约束、M3 mmap/munmap
echo "$OUT" | grep -q "MLC: eguard ok"   && ok "M1 野指针 clock_gettime 返回 EFAULT" || bad "M1 野指针校验"
echo "$OUT" | grep -q "MLC: mpguard ok"  && ok "M1 mprotect 越界拒绝" || bad "M1 mprotect 约束"
echo "$OUT" | grep -q "MLC: mmap ok"     && ok "M3 mmap 写入读回 + munmap 卸载" || bad "M3 mmap/munmap"

# 3. 系统调用追踪（MLC_DEBUG）
# 必须先落盘再 grep：管道版配 set -o pipefail 时，grep -q 命中即退出会让写入端
# 收到 SIGPIPE，整条管道返回 141，断言随机变红（2026-11-06 审计修）
echo "[3] 系统调用追踪"
MLC_DEBUG=1 "$SRC/mlc-core" "$TESTS/test.elf" >/dev/null 2>"$TESTS/.trace.err"
grep -q "nr=94" "$TESTS/.trace.err" && ok "exit_group 被捕获" || bad "exit_group"
rm -f "$TESTS/.trace.err"

# 4. 动态链接冒烟（v1.2 新增）：真实 Ubuntu 24.04 PIE + ld.so + libc 全链
# 静态载荷证明不了加载器，这里必须跑真二进制
echo "[4] 动态链接冒烟（rootfs 真实二进制）"
DYN_OUT=$("$SRC/mlc" ls 2>/dev/null); DRC=$?
[ $DRC -eq 0 ] && echo "$DYN_OUT" | grep -q "README.md" && ok "mlc ls 跑通动态链接并列出目录" || bad "mlc ls（退出码 ${DRC}）"
CAT_OUT=$("$SRC/mlc" cat /etc/hostname 2>/dev/null); CRC=$?
[ $CRC -eq 0 ] && [ -n "$CAT_OUT" ] && ok "mlc cat 读 rootfs 文件" || bad "mlc cat（退出码 ${CRC}）"
"$SRC/mlc" ls /definitely-not-here-xyz >/dev/null 2>&1
[ $? -eq 2 ] && ok "客户机退出码 2 原样透传" || bad "退出码透传"
"$SRC/mlc" --list 2>/dev/null | grep -q "^/usr/bin/ls$" && ok "mlc --list 按客户机 PATH 找到程序" || bad "mlc --list"

# 5. 审计回归（v1.3）：F37 宿主栈溢出、F42 区域表上限、F33 之后的 RELRO 收尾
# 这三项都是"客户机可控输入直接打到宿主数据结构上"的缺陷，必须留常驻回归
echo "[5] 审计回归（宿主栈边界与区域表）"
"$SRC/mlc-core" "$TESTS/test.elf" $(seq 1 129) >/dev/null 2>"$TESTS/.audit.err"
grep -q "参数过多" "$TESTS/.audit.err" && ok "F37 参数超上限被拒（不溢出宿主栈）" || bad "F37 参数上限未生效"
"$SRC/mlc-core" "$TESTS/test.elf" $(seq 1 100) >/dev/null 2>&1
[ $? -eq 0 ] && ok "F37 上限内参数照常运行" || bad "F37 上限内参数被误拒"
BIGENV=$(python3 -c 'print("x"*60000)') "$SRC/mlc" echo ok >/dev/null 2>&1
[ $? -eq 0 ] && ok "F37 超大环境变量不再写穿栈预留（64KB 留白）" || bad "F37 超大环境变量"
# 区域表用量只有走到 exit_group 的诊断行才拿得到，coreutils 的 ls/cat 不走那条路，
# 这里用 rootfs 里的 sh（实测会打该行）
MLC_DEBUG=1 "$SRC/mlc" sh -c true >/dev/null 2>"$TESTS/.audit2.err"
grep -q "区域表已满" "$TESTS/.audit2.err" && bad "F42 区域表写满" || ok "F42 区域表未写满（上限 512）"
REG=$(sed -n 's/.*区域表 \([0-9]*\)\/.*/\1/p' "$TESTS/.audit2.err" | head -1)
[ -n "$REG" ] && [ "$REG" -lt 512 ] && ok "F42 区域表用量可观测（当前 $REG/512）" || bad "F42 区域表用量不可观测"
grep -q "cannot apply additional memory protection" "$TESTS/.audit2.err" && bad "F33 RELRO 回归" || ok "F33 RELRO 收尾仍正常"
rm -f "$TESTS/.audit.err" "$TESTS/.audit2.err"

# 6. 客户机寄存器跨系统调用保存（v5 蹦桌）
# Linux aarch64 系统调用 ABI 规定除 x0 外所有寄存器原样保留。蹦桌 v4 及以前
# 漏存 x10-x15、x24-x27、x29，blr 进 C 处理器会踩掉 x10-x15 且不还原，
# 客户机放在这些寄存器里的活值被抹。regs.elf 把 11 个寄存器填哨兵值后发一次
# getpid 再逐一比对，任一被改动就以该寄存器编号为退出码失败。
# 这条断言有牙：把 ML_STUB 里 ldp x10,x11 的还原指令换成 nop，退出码立刻变 10。
echo "[6] 客户机寄存器跨系统调用保存"
"$SRC/mlc-core" "$TESTS/regs.elf" >/dev/null 2>&1
RC=$?
[ $RC -eq 0 ] && ok "x10-x15/x24-x27/x29 跨系统调用原样保留" || bad "寄存器保存回归（退出码 ${RC}）"

# 7. 客户机线程指针跨 msr/mrs 的完整性（v1.5 F55，缺陷 K1 的收口）
# tp.elf 端到端钉住：msr 记下有效 TCB、野值被顶替、mrs 读回有效 TCB、
# 七种目标寄存器（x0/x1/x9/x10/x19/x28/x30）都拿到同一个值、邻存寄存器不被踩、
# 跨一次系统调用之后仍成立、以及「有效 TCB 未建立时 mrs 必须原样返回现场值」。
# 去牙实测（把对应站点识别关掉后重跑）：
#   msr 不拦截        → 退出码 4
#   cbz 抹掉现场值    → 退出码 11
#   movk 编码少写一位 → 退出码 99（存根本身崩溃）
# 唯一没有牙的是「mrs 站点完全不拦截」：替换只在宿主越界写 TPIDR_EL0 时才触发，
# 而客户机自己的写入全被 msr 存根接管，所以从载荷内部观测不到——那条路径的
# 证据是 tests/stability.sh 的崩溃率归零，不是本断言。
echo "[7] 客户机线程指针跨 msr/mrs 完整"
"$SRC/mlc-core" "$TESTS/tp.elf" >/dev/null 2>&1
RC=$?
[ $RC -eq 0 ] && ok "msr 记下/顶替、mrs 读回有效 TCB，七种目标寄存器一致" || bad "线程指针回归（退出码 ${RC}）"

# 8. fork/exec（v1.6 B7）：sh 里的外部命令要真的跑起来
# 以前 clone(CLONE_VM|CLONE_VFORK|SIGCHLD) 返回 ENOSYS，glibc 的 posix_spawn
# 直接失败，sh -c '任何外部命令' 都跑不了。现在 clone 走 fork()、execve 走
# longjmp 回加载循环换镜像、wait4 走 waitpid 并翻译状态编码。
# 两条断言分别盯「命令真的执行了」和「参数真的传进去了」——只测输出为空时
# 退出码仍可能是 0，那样断言是假的。
echo "[8] fork/exec：外部命令经 sh 执行"
EXEC_OUT=$("$SRC/mlc" sh -c '/usr/bin/echo MLC_EXEC_OK' 2>/dev/null); ERC=$?
case "$EXEC_OUT" in
    *MLC_EXEC_OK*) [ $ERC -eq 0 ] && ok "sh -c 执行外部命令并拿到输出" || bad "外部命令输出对但退出码 ${ERC}" ;;
    *) bad "外部命令没跑起来（退出码 ${ERC}，输出 [$EXEC_OUT]）" ;;
esac
ARG_OUT=$("$SRC/mlc" sh -c '/usr/bin/uname -s' 2>/dev/null); ARC=$?
case "$ARG_OUT" in
    Linux) [ $ARC -eq 0 ] && ok "外部命令的 argv 正确透传" || bad "外部命令 argv 退出码 ${ARC}" ;;
    *) bad "外部命令 argv 没传对（退出码 ${ARC}，输出 [$ARG_OUT]）" ;;
esac
# 退出码透传：子进程非零退出要让 sh 原样交给外层
"$SRC/mlc" sh -c '/usr/bin/ls /definitely-not-here-xyz' >/dev/null 2>&1
XRC=$?
[ $XRC -eq 2 ] && ok "外部命令的退出码经 wait4 透传（ls 的 ENOENT 是 2）" || bad "外部命令退出码透传（得到 ${XRC}，应为 2）"

# 8b. newfstatat 的 statbuf 必须真的被填（v1.6 F59）
# 曾经的 bug：把 a2 当 flags、a3 当 statbuf，而 ABI 是 a2=statbuf、a3=flags。
# 后果是 statbuf 从来没被写过，而返回值一直是 0（成功）——客户机看到的是
# 「stat 成功但整个结构体全零」。实测症状：dash 的 test -f / -d 恒为假
# （st_mode 为 0），PATH 搜索把找到的可执行文件全判成「非常规文件」而跳过，
# sh -c 'ls /' 报 Permission denied、退出码 127。
# ls/cat/stat 不受影响是因为 glibc 2.39 优先走 statx，所以必须用 newfstatat
# 这条路上的消费者（dash 的 test 内建）来钉。
echo "[8b] newfstatat 的 statbuf 真被填（文件类型位）"
F_OUT=$("$SRC/mlc" sh -c '[ -f /usr/bin/ls ] && echo regular' 2>/dev/null); FRC=$?
case "$F_OUT" in
    regular) [ $FRC -eq 0 ] && ok "test -f 认得常规文件（st_mode 类型位正确）" || bad "test -f 退出码 ${FRC}" ;;
    *) bad "test -f 不认常规文件（退出码 ${FRC}，输出 [$F_OUT]）——newfstatat 的 statbuf 没填" ;;
esac
D_OUT=$("$SRC/mlc" sh -c '[ -d /usr/bin ] && echo dir' 2>/dev/null); DRC=$?
case "$D_OUT" in
    dir) [ $DRC -eq 0 ] && ok "test -d 认得目录" || bad "test -d 退出码 ${DRC}" ;;
    *) bad "test -d 不认目录（退出码 ${DRC}，输出 [$D_OUT]）" ;;
esac
# 负向：不存在的路径必须仍然返回失败，不能因为修 statbuf 把失败也变成成功
N_OUT=$("$SRC/mlc" sh -c '[ -f /definitely-not-here-xyz ] && echo bad' 2>/dev/null); NRC=$?
[ -z "$N_OUT" ] && [ $NRC -ne 0 ] && ok "不存在的路径 test -f 仍为假" || bad "不存在的路径被误判为常规文件（输出 [$N_OUT]）"
# 这条同时是 PATH 搜索能否走通的判据：dash 靠 S_ISREG 决定要不要 exec
P_OUT=$("$SRC/mlc" sh -c 'ls /' 2>/dev/null | head -1); PRC=${PIPESTATUS[0]}
[ -n "$P_OUT" ] && ok "PATH 搜索能定位并执行外部命令" || bad "PATH 搜索仍然失败（退出码 ${PRC}）"

# 9. 装到别处之后的 mlc 仍能跑（v1.6 之后发现的产品缺陷 F60）
# MLC.command 与 src/install.sh 都会把 src/mlc 拷到 ~/.local/bin/mlc。拷过去之后
# "脚本上一级"是 ~/.local 而不是项目根，MLC_HOME 会算成 ~/.local/src/mlc-core，
# 于是一运行就退 127。以前从没被发现，因为安装完都是在项目里直接调 src/mlc。
# 去牙实测（把 INSTALL_HOME 写死那行删掉后重跑）：下面两条立刻变红。
echo "[9] mlc 拷到别处后仍能定位项目根"
FAKE_BIN="$TESTS/.fakebin"
rm -rf "$FAKE_BIN" && mkdir -p "$FAKE_BIN"
# 用 REAL_SRC：这里要拷的是 src/mlc 那个真脚本本身（拷过去还要 sed 改
# INSTALL_HOME），$SRC 已经指向看门狗包装器，拷它没有任何意义。
cp "$REAL_SRC/mlc" "$FAKE_BIN/mlc"
chmod +x "$FAKE_BIN/mlc"
# 复刻安装脚本的动作：把真实项目根写进 INSTALL_HOME
sed -i '' "s|^INSTALL_HOME=\"\"|INSTALL_HOME=\"$PROJECT_ROOT\"|" "$FAKE_BIN/mlc"
FB_OUT=$("$FAKE_BIN/mlc" echo INSTALL_PATH_OK 2>/dev/null); FBRC=$?
case "$FB_OUT" in
    *INSTALL_PATH_OK*) [ $FBRC -eq 0 ] && ok "拷贝后的 mlc 经 INSTALL_HOME 找到项目根" || bad "拷贝后的 mlc 输出对但退出码 ${FBRC}" ;;
    *) bad "拷贝后的 mlc 找不到项目根（退出码 ${FBRC}，输出 [$FB_OUT]）" ;;
esac
# 反向：环境变量 MLC_HOME 优先，必须压过 INSTALL_HOME
ENV_OUT=$(MLC_HOME="$PROJECT_ROOT" "$FAKE_BIN/mlc" echo ENV_OVERRIDE_OK 2>/dev/null); ENVRC=$?
case "$ENV_OUT" in
    *ENV_OVERRIDE_OK*) [ $ENVRC -eq 0 ] && ok "MLC_HOME 环境变量优先生效" || bad "MLC_HOME 覆盖后退出码 ${ENVRC}" ;;
    *) bad "MLC_HOME 覆盖无效（退出码 ${ENVRC}，输出 [$ENV_OUT]）" ;;
esac
rm -rf "$FAKE_BIN"

# 10. glibc 真正的 fork 与 fcntl F_DUPFD（2026-11-06 用户试用时发现）
# 两个缺陷都是从"装好之后真的去用"暴露出来的，前 32 项全都绿着：
# (a) clone 只认 0x4111（posix_spawn）与裸 0x0011，漏了 glibc 2.39 真正的
#     fork()：SIGCHLD|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID = 0x1200011。
#     于是 dash 的命令替换、反引号、管道、以及任何带重定向的外部命令全部
#     Cannot fork、退出码 2。posix_spawn 与 fork 是两条不同的 clone 调用，
#     只测通前者会把后者整条遮住。
# (b) fcntl(F_DUPFD) 直接把宿主 fd 号递回客户机，而客户机的 fd 表里没有这个号。
#     dash 保存 stdout 用的正是它，于是 dup3 还原时 EBADF，stdout 永久留在
#     重定向目标上：sh -c 'echo a; echo b > /dev/null; echo c' 只打印 a。
echo "[10] glibc fork 与 fcntl F_DUPFD"
CS_OUT=$("$SRC/mlc" sh -c 'echo $(echo SUBS_OK)' 2>/dev/null); CSRC=$?
case "$CS_OUT" in
    *SUBS_OK*) [ $CSRC -eq 0 ] && ok "命令替换 \$(...) 能 fork（clone 0x1200011）" || bad "命令替换输出对但退出码 ${CSRC}" ;;
    *) bad "命令替换失败（退出码 ${CSRC}，输出 [$CS_OUT]）——clone 漏了 glibc 的 fork 标志" ;;
esac
PIPE_OUT=$("$SRC/mlc" sh -c 'echo p | cat' 2>/dev/null); PRC2=$?
case "$PIPE_OUT" in
    p) [ $PRC2 -eq 0 ] && ok "管道两侧都 fork 成功" || bad "管道退出码 ${PRC2}" ;;
    *) bad "管道失败（退出码 ${PRC2}，输出 [$PIPE_OUT]）" ;;
esac
# 去牙实测（把 clone 的 is_fork 判据改回只认 0x0011）：前两条立刻变红
RED_OUT=$("$SRC/mlc" sh -c 'echo a; echo b > /dev/null; echo c' 2>/dev/null); RRRC=$?
case "$RED_OUT" in
    a*c*) [ $RRRC -eq 0 ] && ok "重定向之后 stdout 被还原（fcntl F_DUPFD 建了客户机 fd）" || bad "重定向还原后退出码 ${RRRC}" ;;
    *) bad "重定向后 stdout 没还原（退出码 ${RRRC}，输出 [$RED_OUT]）——F_DUPFD 返回的是宿主 fd 号" ;;
esac
# 反向：重定向必须真的生效，不能因为修还原就把重定向本身修没了
SUP_OUT=$("$SRC/mlc" sh -c 'ls /definitely-not-here-xyz > /dev/null; echo "passed"' 2>/dev/null); SRC2=$?
case "$SUP_OUT" in
    passed) [ $SRC2 -eq 0 ] && ok "重定向本身仍生效（stdout 真的被换过）" || bad "重定向生效但退出码 ${SRC2}" ;;
    *) bad "重定向没生效（退出码 ${SRC2}，输出 [$SUP_OUT]）" ;;
esac

echo
echo "[11] readlinkat 与 /dev 设备（F64、F65）"
# F64：readlinkat 原本只认 /proc/self/exe，其余一律 ENOENT，
# 于是任何含符号链接的目录 ls -l 必失败、退出码 1。判据看两件事：
# 退出码为 0，且输出里没有 "cannot read symbolic link"。
for d in /etc / /usr/bin; do
    OUT=$("$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/ls" -l "$d" 2>/dev/null)
    rc=$?
    nbad=$(printf '%s\n' "$OUT" | grep -c 'cannot read symbolic link')
    if [ $rc -eq 0 ] && [ "$nbad" -eq 0 ]; then
        ok "ls -l $d 退出码 0 且无 cannot read symbolic link"
    else
        bad "ls -l $d 退出码 ${rc}，cannot read symbolic link ${nbad} 处"
    fi
done
# 符号链接的目标名要真的解析出来（/etc 里 rmt 指向 /usr/sbin/rmt）
if printf '%s\n' "$("$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/ls" -l /etc 2>/dev/null)" | grep -q 'rmt -> /usr/sbin/rmt'; then
    ok "符号链接目标被正确解析"
else
    bad "符号链接目标没解析出来"
fi
# F65：rootfs 原先没有 /dev/urandom 与 /dev/zero，打开一律 ENOENT
UR=$("$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/head" -c 16 /dev/urandom 2>/dev/null | wc -c | tr -d ' ')
if [ "$UR" = "16" ]; then
    ok "/dev/urandom 能读出 16 字节"
else
    bad "/dev/urandom 只读出 ${UR:-0} 字节"
fi
ZR=$("$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/head" -c 32 /dev/zero 2>/dev/null | wc -c | tr -d ' ')
if [ "$ZR" = "32" ]; then
    ok "/dev/zero 能读出 32 字节"
else
    bad "/dev/zero 只读出 ${ZR:-0} 字节"
fi
# dd 会 dup3 再 fstat，覆盖设备 fd 有真后备 fd 那条路
if "$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/dd" if=/dev/urandom bs=8 count=1 >/dev/null 2>&1; then
    ok "dd 从 /dev/urandom 取数成功（dup3 与 fstat 都通）"
else
    bad "dd 从 /dev/urandom 取数失败"
fi

echo
echo "[12] poll / ppoll 的 pollfd 布局（2026-11-07 审计追加）"
# 为什么值得单列一段：第七轮补 ppoll 时把客户机 struct pollfd 的跨距写成 12、
# revents 偏移写成 8，而两侧真实布局都是跨距 8、revents 在偏移 6
# （实测 sizeof(struct pollfd)==8、offsetof(revents)==6）。
# 后果有两个，此前没有任何测试覆盖，所以套件一直绿着：
#   1. nfds>1 时从第 2 项起读到的 fd/events 全是错位垃圾；
#   2. revents 写在第 8 字节，正好落到下一个 pollfd 的 fd 字段上，
#      最后一项还会写出数组末端两字节。
# poll.elf 用 /dev/zero（引擎里的虚拟设备，恒就绪）做被 poll 的 fd，
# revents 是确定值，不依赖 stdout 是管道还是终端。六项判据按位累加进退出码：
#   bit0/bit1 就绪个数不是 2；bit2/bit3 revents 不是 POLLIN；
#   bit4 pfds[1].fd 被踩坏；bit5 数组后的哨兵被改写。
# 去牙实测：把源码里 G_POLLFD_SIZE 改回 12，退出码立刻变 60。
POLL_OUT=$("$SRC/mlc-core" "$TESTS/poll.elf" 2>/dev/null); POLL_RC=$?
case "$POLL_OUT" in
    *"MLC: poll ok"*) [ $POLL_RC -eq 0 ] && ok "poll 与 ppoll 的 pollfd 布局正确（6 项判据全过）" \
        || bad "poll 布局回归（退出码 ${POLL_RC}，按位：1=poll就绪数 2=ppoll就绪数 4=revents[0] 8=revents[1] 16=fd被踩 32=哨兵被写）" ;;
    *) bad "poll 载荷没跑起来（退出码 ${POLL_RC}，输出 [$POLL_OUT]）" ;;
esac

echo
echo "[13] ripgrep 冒烟（第七轮加，需 rootfs 里有 rg）"
# 为什么值得单列一段：ripgrep 15.2.0 是第一个暴露出三处真实缺陷的客户机——
#   ppoll（nr=73）整条没实现，启动即断；
#   sigaltstack 挂错号（43 是 statfs64，132 才是），那个分支从来没被触发过；
#   statx 不认 AT_EMPTY_PATH，Rust 的 std 拿 ENOTDIR 后 close(1) 再重开，
#   最后 write(1) 拿到 EBADF，搜索成功而 stdout 一个字节都不出。
# 这三个都不在原有 45 项的覆盖面里，所以留下这一组常驻判据。
RG="$PROJECT_ROOT/rootfs/sysroot/usr/bin/rg"
if [ ! -x "$RG" ]; then
    echo "  [跳过] rootfs 里没有 rg（ripgrep）。装一个 aarch64 动态版到该路径即可启用本段："
    echo "         https://github.com/BurntSushi/ripgrep/releases （aarch64-unknown-linux-gnu）"
else
    # 单文件搜索：退出码 0、输出里有行号、stdout 非空（第三条专盯 AT_EMPTY_PATH 那条）
    RG_OUT=$("$SRC/mlc-core" "$RG" --threads 1 -n root /etc/passwd 2>/dev/null); RG_RC=$?
    case "$RG_OUT" in
        1:root:*) [ $RG_RC -eq 0 ] && ok "rg 单文件搜索（行号 + 内容）" || bad "rg 搜索成功但退出码 ${RG_RC}" ;;
        "") bad "rg 有匹配却零输出——statx AT_EMPTY_PATH 很可能又坏了（客户机 close(1) 后 write 拿 EBADF）" ;;
        *) bad "rg 输出形状不对：[$RG_OUT]" ;;
    esac
    # 递归 + 只列文件名：考验 getdents64 与目录遍历
    RG_L=$("$SRC/mlc-core" "$RG" --threads 1 --no-ignore -l root /etc 2>/dev/null | wc -l | tr -d ' ')
    if [ "${RG_L:-0}" -gt 5 ]; then
        ok "rg 递归搜 /etc 列出 ${RG_L} 个文件"
    else
        bad "rg 递归只列出 ${RG_L:-0} 个文件（预期 >5）"
    fi
    # 计数模式：-c 走的是同一条读路径，但输出形状不同（数字而非行）
    RG_C=$("$SRC/mlc-core" "$RG" --threads 1 -c root /etc/passwd 2>/dev/null)
    if [ "${RG_C:-0}" = "1" ]; then
        ok "rg -c 计数为 1"
    else
        bad "rg -c 计数是 ${RG_C:-空}（预期 1）"
    fi
    # 多线程模式必然失败：M3（CLONE_THREAD）没实现。这一条记的是**已知边界**，
    # 不是回归判据，所以只提示不算失败——ripgrep 默认按 CPU 核数开线程。
    if "$SRC/mlc-core" "$RG" -n root /etc/passwd >/dev/null 2>&1; then
        ok "rg 多线程模式也能跑（M3 已实现？把这条从提示改成判据）"
    else
        echo "  [提示] rg 多线程模式失败，符合预期：clone 的 CLONE_THREAD 归 M3，未实现。"
    fi
fi

echo
# 审计修正（2026-11-07）：原实现在重跑时直接 exec 覆盖整个进程，第一轮的
# 失败项只留在日志中间，最终一行只印第二轮的 PASS/FAIL——看上去「失败 0 项」，
# 而上一轮刚刚有 5 项真红。2026-11-07 实测正是如此：第一轮 5 项全红
# （全是退出码 127），第二轮全绿，最终一行报「通过 49 项, 失败 0 项」。
# 一个会把真实失败洗成绿色的门禁，比随机红的门禁更糟。
# 现在第一轮的数字必须被带出来，最终一行同时显示两轮。
# 退出码仍只看本轮：重跑的意义就是吸收 K2 的偶发，若改成看合计，
# 每次 K2 抖动都会把门禁打红，重跑就白做了。洗白与打红之间取前者可查、
# 后者可用——数字全部摆出来，人来判断那 5 项是不是真回归。
if [ -n "${MLC_VERIFY_PREV:-}" ] && [ -f "${MLC_VERIFY_PREV}" ]; then
    read -r PP PF < "${MLC_VERIFY_PREV}"
    rm -f "${MLC_VERIFY_PREV}"
    echo "=== 本轮: 通过 $PASS 项, 失败 $FAIL 项 ==="
    echo "=== 两轮合计（自动重跑前第一轮 通过 $PP 项, 失败 $PF 项）: 通过 $((PASS+PP)) 项, 失败 $((FAIL+PF)) 项 ==="
    if [ "$PF" -gt 0 ] && [ "$FAIL" -eq 0 ]; then
        echo "[提示] 第一轮有 $PF 项失败，重跑后归零。失败项若全是退出码 127，那是已知"
        echo "       缺陷 K2（docs/10）的偶发；否则就是被重跑吸收掉的真实回归，不要忽略。"
    fi
    [ "$FAIL" -eq 0 ]
    exit $?
fi
echo "=== 结果: 通过 $PASS 项, 失败 $FAIL 项 ==="
if [ $FAIL -ne 0 ]; then
    # 已知缺陷 K2（docs/10）会让个别客户机以约 0.5% 的概率失败：
    # 符号查找失败退出码 127，或永久挂起。它是环境性的、与本次改动无关，
    # 但会把门禁变成随机红——而随机失败的门禁比没有门禁更糟。
    # 因此这里自动重跑一次：确定性回归两次都会红，K2 的偶发第二次几乎必然绿。
    # 重跑次数可用 MLC_VERIFY_RETRY 调，设 0 关闭。
    if [ "${MLC_VERIFY_RETRY:-1}" -gt 0 ]; then
        PREV_FILE="${TMPDIR:-/tmp}/mlc-verify-prev.$$"
        echo "$PASS $FAIL" > "$PREV_FILE"
        echo "[提示] 有 $FAIL 项失败。已知缺陷 K2 会造成约 0.5% 的偶发失败，自动重跑一次。"
        echo "[提示] 重跑后会把第一轮的数字一并报出，不会洗白。"
        MLC_VERIFY_RETRY=0 MLC_VERIFY_PREV="$PREV_FILE" exec bash "$0" "$@"
    fi
    exit 1
fi
