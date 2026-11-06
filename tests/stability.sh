#!/bin/bash
# MLC 稳定性观测（不作为安装门禁）
#
# 用途：量化动态链接路径上的偶发失败率。已知缺陷 K1（见 docs/10-整改清单.md）：
# 客户机在错误路径上首次访问 errno 时，TPIDR_EL0 可能是 0x1006 一类的野值，
# 于是写入 TPIDR+0x100 触发 SIGSEGV，进程以退出码 99 结束。
#
# 为什么单独一个脚本而不进 verify.sh：
#   它是概率性的（实测 2% 到 5%），放进门禁会让一键安装随机失败，
#   而随机失败的门禁比没有门禁更糟（见 docs/06 审计报告第 6 节）。
#   所以这里只测量、只报告，不判定通过与否。
#
# 判据修正（2026-11-06 第二轮审计）：原脚本把「退出码非 0」一律算失败，
# 于是 `ls /nonexistent` 每次都被记失败 200/200——那个程序的正常退出码就是 2
# （ENOENT），不是崩溃。真正的崩溃签名是退出码 99（见 crash_handler 的 _exit）。
# 非 99 的非零退出码是客户机自己的语义，必须放过去。
#
# 看门狗（2026-11-06 第三轮）：v1.6 量化时发现部分客户机（id、hostname 一类）
# 有约 0.5% 的概率永久挂起，而 macOS 没有 timeout 命令，一次挂起就能把整个
# 观测脚本卡死。改用引擎自带的 MLC_WATCHDOG：超时的进程以 88 退出，
# 这里把它单列成「挂起」，既不冒充崩溃，也不把脚本卡住。
set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$PROJECT_ROOT/src"
N="${1:-200}"
CRASH_CODE=99          # crash_handler 的 _exit 码，K1 的唯一签名
HANG_CODE=88           # watchdog_handler 的 _exit 码，挂起签名
WATCHDOG_SECS="${MLC_WATCHDOG_SECS:-20}"

[ -x "$SRC/mlc-core" ] || { echo "先构建：clang -O2 -o src/mlc-core src/mlc-core.c"; exit 1; }

echo "=== MLC 稳定性观测：每个客户机跑 $N 次，崩溃判据是退出码 ${CRASH_CODE}，挂起判据是 ${HANG_CODE}（看门狗 ${WATCHDOG_SECS}s）==="
FAIL_TOTAL=0
HANG_TOTAL=0
RUN_TOTAL=0
for spec in "ls /nonexistent" "cat /etc/hostname" "sh -c true" "echo hi" "ls -la /" \
            "sh -c /usr/bin/echo hi" "sh -c /usr/bin/uname -s" "sh -c /usr/bin/id"; do
    set -- $spec
    prog="$1"; shift
    bad=0; hung=0
    for i in $(seq 1 "$N"); do
        MLC_WATCHDOG="$WATCHDOG_SECS" "$SRC/mlc-core" \
            "$PROJECT_ROOT/rootfs/sysroot/usr/bin/$prog" "$@" >/dev/null 2>&1
        rc=$?
        [ $rc -eq "$CRASH_CODE" ] && bad=$((bad+1))
        [ $rc -eq "$HANG_CODE" ] && hung=$((hung+1))
    done
    printf "  %-26s 崩溃 %d/%d，挂起 %d/%d\n" "$prog $*" "$bad" "$N" "$hung" "$N"
    FAIL_TOTAL=$((FAIL_TOTAL + bad))
    HANG_TOTAL=$((HANG_TOTAL + hung))
    RUN_TOTAL=$((RUN_TOTAL + N))
done

echo
echo "合计崩溃 ${FAIL_TOTAL} / ${RUN_TOTAL}，合计挂起 ${HANG_TOTAL} / ${RUN_TOTAL}"
if [ "$FAIL_TOTAL" -eq 0 ] && [ "$HANG_TOTAL" -eq 0 ]; then
    echo "本次未观测到偶发崩溃，也未观测到挂起。"
else
    echo "观测到异常。抓一次崩溃现场："
    echo "  for i in \$(seq 1 400); do ./src/mlc-core rootfs/sysroot/usr/bin/sh -c true >/dev/null 2>/tmp/f.txt; [ \$? -ne 99 ] && break; done"
    echo "  grep -E 'TPIDR|信号 |故障地址|TP 存根' /tmp/f.txt"
    echo "挂起现场用看门狗抓（会打出卡住时的 PC 与所在镜像）："
    echo "  MLC_WATCHDOG=8 ./src/mlc-core rootfs/sysroot/usr/bin/id"
    echo "判定口径见 docs/10-整改清单.md 的 K1 与 K2。"
fi
