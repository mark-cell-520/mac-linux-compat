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
set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$PROJECT_ROOT/src"
N="${1:-200}"

[ -x "$SRC/mlc-core" ] || { echo "先构建：clang -O2 -o src/mlc-core src/mlc-core.c"; exit 1; }

echo "=== MLC 稳定性观测：每个客户机跑 $N 次 ==="
FAIL_TOTAL=0
for spec in "ls /nonexistent" "cat /etc/hostname" "sh -c true"; do
    set -- $spec
    prog="$1"; shift
    bad=0
    for i in $(seq 1 "$N"); do
        "$SRC/mlc-core" "$PROJECT_ROOT/rootfs/sysroot/usr/bin/$prog" "$@" >/dev/null 2>&1
        [ $? -ne 0 ] && bad=$((bad+1))
    done
    printf "  %-22s 失败 %d/%d\n" "$prog $*" "$bad" "$N"
    FAIL_TOTAL=$((FAIL_TOTAL + bad))
done

echo
echo "合计失败 $FAIL_TOTAL / $((N * 3))"
if [ "$FAIL_TOTAL" -eq 0 ]; then
    echo "本次未观测到偶发失败。"
else
    echo "观测到偶发失败。抓一次现场："
    echo "  for i in \$(seq 1 400); do ./src/mlc-core rootfs/sysroot/usr/bin/ls /nonexistent >/dev/null 2>/tmp/f.txt; [ \$? -ne 2 ] && break; done"
    echo "  grep -E 'TPIDR|信号 |故障地址' /tmp/f.txt"
    echo "判定口径见 docs/10-整改清单.md 的 K1。"
fi
