#!/usr/bin/env python3
"""把某个 link_map 的完整字段转储成人可读形式，用于两轮对比。

用法：mlc-k2-mapdump.py <转储目录> <错误日志> <map 地址，十六进制> [长度]
"""
import os
import re
import struct
import sys

DUMP, ERRLOG = sys.argv[1], sys.argv[2]
MAP = int(sys.argv[3], 16)
N = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x600


def load_regions():
    regs = []
    with open(ERRLOG) as f:
        for line in f:
            m = re.search(r"区域 (\d+) \[(0x[0-9a-f]+),(0x[0-9a-f]+)\) -> ([^\s，]+)", line)
            if not m:
                continue
            i = int(m.group(1))
            lo, hi = int(m.group(2), 16), int(m.group(3), 16)
            p = os.path.join(DUMP, "reg%02d.bin" % i)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    regs.append((i, lo, hi, fh.read()))
    return regs


REGS = load_regions()


def read(addr, n):
    for _, lo, hi, blob in REGS:
        if lo <= addr and addr + n <= hi:
            return blob[addr - lo:addr - lo + n]
    return None


def q(addr):
    b = read(addr, 8)
    return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None


def main():
    print("# link_map @ 0x%x，长度 0x%x" % (MAP, N))
    for off in range(0, N, 8):
        v = q(MAP + off)
        if v is None:
            print("0x%03x: <读不到>" % off)
            continue
        # 顺带把像指针的值解引用一层，看看指向什么
        extra = ""
        if 0x100000000 < v < 0x200000000:
            b = read(v, 16)
            if b:
                z = b.find(b"\0")
                txt = b[:z] if z > 0 else b
                if all(32 <= c < 127 for c in txt) and len(txt) >= 3:
                    extra = "  -> %r" % txt.decode()
                else:
                    qs = struct.unpack("<Q", b[:8])[0]
                    extra = "  -> 0x%x" % qs
        print("0x%03x: 0x%016x%s" % (off, v, extra))


if __name__ == "__main__":
    main()
