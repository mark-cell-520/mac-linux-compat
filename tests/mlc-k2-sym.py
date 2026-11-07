#!/usr/bin/env python3
"""读出 link_map 某个偏移处的指针目标，按 Elf64_Sym 解出符号名。

用法：mlc-k2-sym.py <dump> <err> <库基址 hex> <map hex> <偏移 hex>
"""
import os
import re
import struct
import sys

DUMP, ERRLOG = sys.argv[1], sys.argv[2]
BASE = int(sys.argv[3], 16)
MAP = int(sys.argv[4], 16)
OFF = int(sys.argv[5], 16)

PERL = "/Users/mm/Pictures/mac-linux-compat/rootfs/sysroot/usr/bin/perl"


def load():
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
                    regs.append((lo, hi, fh.read()))
    return regs


R = load()


def rd(addr, n):
    for lo, hi, blob in R:
        if lo <= addr and addr + n <= hi:
            return blob[addr - lo:addr - lo + n]
    return None


d = open(PERL, "rb").read()
DYNSYM, DYNSTR = 0x2bd0, 0xc248


def sym_name(idx):
    o = DYNSYM + idx * 24
    st_name, = struct.unpack_from("<I", d, o)
    e = d.index(b"\0", DYNSTR + st_name)
    return d[DYNSTR + st_name:e].decode("utf-8", "replace")


def main():
    pv = struct.unpack("<Q", rd(MAP + OFF, 8))[0]
    print("map+0x%x = 0x%x（相对库基址 +0x%x）" % (OFF, pv, pv - BASE))
    if not (BASE <= pv < BASE + 0x400000):
        print("目标不在库映像内")
        return
    tgt = rd(pv, 24)
    if tgt is None:
        print("目标读不到")
        return
    print("目标处 24 字节：%s" % tgt.hex())
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack("<IBBHQQ", tgt)
    print("按 Elf64_Sym 解：st_name=%d st_info=0x%02x st_shndx=%d st_value=0x%x st_size=0x%x"
          % (st_name, st_info, st_shndx, st_value, st_size))
    print("  -> 符号名 %r" % sym_name(st_name))
    # 也按 qword 序列看一眼
    qs = struct.unpack("<QQQ", tgt)
    print("按三个 qword 看：%s" % " ".join(hex(q) for q in qs))
    # 若它是 .dynsym 的一项，算出下标
    if DYNSYM <= pv - BASE < DYNSYM + 0x9678:
        idx = (pv - BASE - DYNSYM) // 24
        print("  相当于 .dynsym 第 %d 项（偏移余 %d）" % (idx, (pv - BASE - DYNSYM) % 24))
        print("  该项符号名 %r" % sym_name(idx))
        # 前后各两项
        for k in (-1, 0, 1):
            j = idx + k
            if 0 <= j * 24 < 0x9678:
                print("    [%d] %r" % (j, sym_name(j)))


if __name__ == "__main__":
    main()
