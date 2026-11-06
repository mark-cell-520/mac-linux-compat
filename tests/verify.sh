#!/bin/bash
# MLC v1 验证脚本：构建测试载荷并逐项检查兼容层能力
set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$PROJECT_ROOT/src"
TESTS="$PROJECT_ROOT/tests"
PASS=0; FAIL=0

ok()   { echo "  [通过] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [失败] $1"; FAIL=$((FAIL+1)); }

echo "=== MLC v1 验证 ==="

# 0. 构建核心
echo "[0] 构建 mlc-core"
if clang -O2 -Wall -o "$SRC/mlc-core" "$SRC/mlc-core.c" 2>/dev/null; then ok "编译"; else bad "编译"; exit 1; fi

# 1. 构建测试载荷（位置无关 ET_DYN ELF）
echo "[1] 构建测试载荷"
python3 "$TESTS/mkelf.py" "$TESTS/test.s" "$TESTS/test.elf" >/dev/null 2>&1 && ok "mkelf 生成" || bad "mkelf 生成"
python3 "$TESTS/mkelf.py" "$TESTS/regs.s" "$TESTS/regs.elf" >/dev/null 2>&1 && ok "regs 载荷生成" || bad "regs 载荷生成"
python3 "$TESTS/mkelf.py" "$TESTS/tp.s" "$TESTS/tp.elf" >/dev/null 2>&1 && ok "tp 载荷生成" || bad "tp 载荷生成"
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
[ $RC -eq 0 ] && ok "x10-x15/x24-x27/x29 跨系统调用原样保留" || bad "寄存器保存回归（退出码 $RC）"

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

echo
echo "=== 结果: 通过 $PASS 项, 失败 $FAIL 项 ==="
[ $FAIL -eq 0 ] || exit 1
