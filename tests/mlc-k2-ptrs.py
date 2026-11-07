#!/usr/bin/env python3
"""扫转储里所有等于某库基址的指针，据此定位 link_map 与 l_scope 数组。

用法：mlc-k2-ptrs.py <转储目录> <错误日志> <目标库的基址，十六进制>
"""
import os
import re
import struct
import sys

DUMP, ERRLOG = sys.argv[1], sys.argv[2]
TARGET = int(sys.argv[3], 16)


def load_regions():
    regs = []
    with open(ERRLOG) as f:
        for line in f:
            m = re.search(r"区域 (\d+) \[(0x[0-9a-f]+),(0x[0-9a-f]+)\) -> (\S+)", line)
            if not m:
                continue
            i = int(m.group(1))
            lo, hi = int(m.group(2), 16), int(m.group(3), 16)
            p = os.path.join(DUMP, "reg%02d.bin" % i)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    regs.append((i, lo, hi, fh.read()))
    return regs


def main():
    regs = load_regions()
    print("目标值 0x%x，转储区间 %d 个" % (TARGET, len(regs)))
    total = 0
    for i, lo, hi, blob in regs:
        hits = []
        for off in range(0, len(blob) - 8, 8):
            v, = struct.unpack_from("<Q", blob, off)
            if v == TARGET:
                hits.append(off)
        if hits:
            total += len(hits)
            print("区域 %d [0x%x,0x%x) 命中 %d 处：%s" % (
                i, lo, hi, len(hits),
                " ".join("0x%x" % (lo + o) for o in hits[:24])))
            # 打印第一处命中的前后文，用来认 link_map 的字段布局
            o = hits[0]
            base = max(0, o - 0x40)
            print("   第一处命中前后各 0x40 字节（按 qword）：")
            for k in range(0, 0x80, 8):
                addr = lo + base + k
                v, = struct.unpack_from("<Q", blob, base + k)
                mark = "  <<< 命中" if lo + base + k in [lo + x for x in hits] else ""
                print("     0x%x: 0x%016x%s" % (addr, v, mark))
    print("合计命中 %d 处" % total)


if __name__ == "__main__":
    main()
