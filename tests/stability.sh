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
set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$PROJECT_ROOT/src"
N="${1:-200}"
CRASH_CODE=99          # crash_handler 的 _exit 码，K1 的唯一签名

[ -x "$SRC/mlc-core" ] || { echo "先构建：clang -O2 -o src/mlc-core src/mlc-core.c"; exit 1; }

echo "=== MLC 稳定性观测：每个客户机跑 $N 次，判据是退出码 $CRASH_CODE ==="
FAIL_TOTAL=0
RUN_TOTAL=0
for spec in "ls /nonexistent" "cat /etc/hostname" "sh -c true" "echo hi" "ls -la /"; do
    set -- $spec
    prog="$1"; shift
    bad=0
    for i in $(seq 1 "$N"); do
        "$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/$prog" "$@" >/dev/null 2>&1
        [ $? -eq "$CRASH_CODE" ] && bad=$((bad+1))
    done
    printf "  %-22s 崩溃 %d/%d\n" "$prog $*" "$bad" "$N"
    FAIL_TOTAL=$((FAIL_TOTAL + bad))
    RUN_TOTAL=$((RUN_TOTAL + N))
done

echo
echo "合计崩溃 $FAIL_TOTAL / $RUN_TOTAL"
if [ "$FAIL_TOTAL" -eq 0 ]; then
    echo "本次未观测到偶发崩溃。"
else
    echo "观测到偶发崩溃。抓一次现场："
    echo "  for i in \$(seq 1 400); do ./src/mlc-core rootfs/sysroot/usr/bin/sh -c true >/dev/null 2>/tmp/f.txt; [ \$? -ne 99 ] && break; done"
    echo "  grep -E 'TPIDR|信号 |故障地址|TP 存根' /tmp/f.txt"
    echo "判定口径见 docs/10-整改清单.md 的 K1。"
fi
