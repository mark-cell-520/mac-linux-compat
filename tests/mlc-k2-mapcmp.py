#!/usr/bin/env python3
"""对比两个转储里同一个 link_map 的关键字段。

地址绝对值每轮都变（客户机窗口基址随机），直接 diff 全是噪声。
这里只输出两类可比的东西：
  1. 小整数与布尔字段（nbuckets、shift、idxbits、scope 长度、标志位）；
  2. 指针字段换算成「相对本库基址的偏移」，偏移可比，绝对地址不可比。

用法：mlc-k2-mapcmp.py <dumpA> <errA> <mapA> <dumpB> <errB> <mapB>
"""
import os
import re
import struct
import sys

A = (sys.argv[1], sys.argv[2], int(sys.argv[3], 16))
B = (sys.argv[4], sys.argv[5], int(sys.argv[6], 16))
N = int(sys.argv[7], 16) if len(sys.argv) > 7 else 0x600


def load(dump, errlog):
    regs = []
    with open(errlog) as f:
        for line in f:
            m = re.search(r"区域 (\d+) \[(0x[0-9a-f]+),(0x[0-9a-f]+)\) -> (\S+)", line)
            if not m:
                continue
            i = int(m.group(1))
            lo, hi = int(m.group(2), 16), int(m.group(3), 16)
            p = os.path.join(dump, "reg%02d.bin" % i)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    regs.append((lo, hi, fh.read()))
    return regs


RA, RB = load(A[0], A[1]), load(B[0], B[1])


def mk(regs):
    def read(addr, n):
        for lo, hi, blob in regs:
            if lo <= addr and addr + n <= hi:
                return blob[addr - lo:addr - lo + n]
        return None
    return read


rdA, rdB = mk(RA), mk(RB)


def img_range(regs, map_addr):
    """map 的 l_addr 字段就是库基址，映像范围取 [l_addr, l_addr+64MB) 内最近的区域。"""
    b = None
    for lo, hi, blob in regs:
        if lo <= map_addr < hi:
            b = blob[map_addr - lo:map_addr - lo + 8]
    if not b:
        return None
    l_addr = struct.unpack("<Q", b)[0]
    best = None
    for lo, hi, blob in regs:
        if lo <= l_addr < hi and (best is None or (hi - lo) > (best[1] - best[0])):
            best = (lo, hi)
    return l_addr, best


IA, IB = img_range(RA, A[2]), img_range(RB, B[2])
print("A: map 0x%x，库基址 0x%x，映像 [0x%x,0x%x)" % (A[2], IA[0], IA[1][0], IA[1][1]))
print("B: map 0x%x，库基址 0x%x，映像 [0x%x,0x%x)" % (B[2], IB[0], IB[1][0], IB[1][1]))
print()
print("%-8s %-22s %-22s %s" % ("偏移", "A", "B", "差异类型"))
print("-" * 78)
for off in range(0, N, 8):
    ba = rdA(A[2] + off, 8)
    bb = rdB(B[2] + off, 8)
    if not ba or not bb:
        continue
    va, vb = struct.unpack("<Q", ba)[0], struct.unpack("<Q", bb)[0]
    kind = ""
    # 指针字段换算成相对本库基址的偏移
    def norm(v, I):
        lo, hi = I[1]
        if I[0] <= v < hi:
            return "lib+0x%x" % (v - I[0])
        if lo <= v < hi:
            return "reg+0x%x" % (v - lo)
        return None
    na, nb = norm(va, IA), norm(vb, IB)
    if na or nb:
        kind = "指针"
        sa, sb = na or hex(va), nb or hex(vb)
    elif va < 0x10000 and vb < 0x10000:
        kind = "小整数"
        sa, sb = hex(va), hex(vb)
    else:
        sa, sb = hex(va), hex(vb)
    flag = ""
    if kind == "小整数" and va != vb:
        flag = "  <<<<<< 小整数不同"
    elif kind == "指针" and na != nb:
        flag = "  <<<<<< 指针偏移不同"
    elif kind == "" and va != vb and not (va > 0x100000000 and vb > 0x100000000):
        flag = "  <<<<<< 形态不同"
    if flag or kind:
        print("0x%03x    %-22s %-22s %s%s" % (off, sa, sb, kind, flag))
