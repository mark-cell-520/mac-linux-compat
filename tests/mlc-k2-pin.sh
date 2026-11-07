#!/usr/bin/env bash
# 钉死客户机窗口基址，验证失败是否与客户机内存布局有关。
#
# 背景：上一轮用 MLC_WIN_ADDR 钉死窗口基址，五个基址各 12 轮失败
# 0/12、2/12、3/12、1/12、5/12，据此得出「布局无关」的结论。
#
# 本轮复查发现那个探针本身不干净：MLC_WIN_ADDR 只钉窗口，而 brk 预留区
# 与客户机栈是引擎另外两次独立 mmap(NULL)，不受它约束。实测
# MLC_WIN_ADDR=0x10000000000 时窗口落在 0x10001000000（约 1.1TB），
# brk 却自选在 0x1050ec000（约 4.3GB），两者相距约两千倍——正常情况下
# brk 紧贴在窗口末之后约 4MB。也就是说那个探针把引擎自身的布局假设
# 整个打破了，「布局无关」这个结论要重新审视。
#
# 本脚本同时记录窗口、ld.so 基址、brk、客户机栈四项，先把「钉窗口之后
# 到底还有哪些地址在变」这件事量化出来，再谈结论。
#
# 用法：mlc-k2-pin.sh [轮数] [窗口地址]
set -u
PROJECT="${PROJECT:-/Users/mm/Pictures/mac-linux-compat}"
N="${1:-30}"
WIN="${2:-0x10000000000}"
cd "$PROJECT" || exit 1
rm -f /tmp/k2pin.txt
for i in $(seq 1 "$N"); do
  out=$(MLC_WIN_ADDR="$WIN" ./src/mlc-core rootfs/sysroot/usr/bin/perl -e 'print 6*7' 2>&1 >/dev/null)
  rc=$?
  win=$(printf '%s\n' "$out" | grep -o '客户机窗口 0x[0-9a-f]*' | head -1 | grep -o '0x[0-9a-f]*')
  ld=$(printf '%s\n' "$out" | grep -o 'ld-linux-aarch64.so.1：基址 0x[0-9a-f]*' | grep -o '0x[0-9a-f]*')
  brk=$(printf '%s\n' "$out" | grep -o 'brk 预留区 0x[0-9a-f]*' | grep -o '0x[0-9a-f]*')
  sp=$(printf '%s\n' "$out" | grep -o '客户机栈就绪 sp=0x[0-9a-f]*' | grep -o '0x[0-9a-f]*')
  echo "$rc ${win:-none} ${ld:-none} ${brk:-none} ${sp:-none}" >> /tmp/k2pin.txt
done
python3 - "$N" <<'PYEOF'
import sys
rows = [l.split() for l in open("/tmp/k2pin.txt") if l.strip()]
fails = [r for r in rows if r[0] == "127"]
print("总 %d 轮，失败 %d 轮（%.1f%%）" % (len(rows), len(fails), 100.0 * len(fails) / max(1, len(rows))))
names = ["窗口", "ld.so 基址", "brk 预留区", "客户机栈 sp"]
for i, nm in enumerate(names, start=1):
    vals = sorted(set(r[i] for r in rows))
    fv = sorted(set(r[i] for r in fails))
    print("%-12s 共 %2d 种取值%s" % (nm, len(vals),
          "（已钉死）" if len(vals) == 1 else "（仍在变）"))
    if len(vals) <= 4:
        print("              全部取值：%s" % vals)
    else:
        print("              抽样：%s ..." % vals[:4])
    if fv:
        print("              失败轮取值：%s" % fv)
if len(fails) == 0:
    print()
    print("本轮没有失败样本，无法判断失败与哪一项相关；加大轮数重跑。")
PYEOF
