#!/usr/bin/env python3
"""把失败轮转储里某个库的映像与 ELF 文件原文逐字节比对，找出被改写的字节。

与引擎自带的 MLC_DUMP_DIR 元数据转储不同：那个转储从「可执行段起点 + 0x200」
开始，恰好跳过 .gnu.hash 所在的头部。这里按 PT_LOAD 逐段全量比对，不跳过任何字节。

用法：mlc-k2-imgcmp.py <dump> <err> <库文件> <库基址 hex>
"""
import os
import re
import struct
import sys

DUMP, ERRLOG, LIBFILE = sys.argv[1], sys.argv[2], sys.argv[3]
BASE = int(sys.argv[4], 16)


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


def main():
    regs = load_regions()
    d = open(LIBFILE, "rb").read()
    e_phoff, = struct.unpack_from("<Q", d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", d, 0x36)
    print("库 %s 基址 0x%x" % (os.path.basename(LIBFILE), BASE))
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from("<IIQQQQQQ", d, o)
        if p_type != 1 or p_filesz == 0:
            continue
        # 找客户机里对应的区间
        blob = None
        for i, lo, hi, b in regs:
            if lo <= BASE + p_vaddr and BASE + p_vaddr + p_filesz <= hi:
                blob = b
                break
        if blob is None:
            # 跨区间：逐段找
            print("  PT_LOAD flags=%d vaddr=0x%x filesz=0x%x：客户机区间不连续，跳过"
                  % (p_flags, p_vaddr, p_filesz))
            continue
        gstart = BASE + p_vaddr - lo
        guest = blob[gstart:gstart + p_filesz]
        want = d[p_offset:p_offset + p_filesz]
        diffs = [i for i in range(p_filesz) if guest[i] != want[i]]
        print("  PT_LOAD flags=%d vaddr=0x%x filesz=0x%x：差异 %d 字节"
              % (p_flags, p_vaddr, p_filesz, len(diffs)))
        if diffs:
            # 聚成连续段，每段报出运行期地址、原文、现值
            runs = []
            s = diffs[0]
            for a, b in zip(diffs, diffs[1:]):
                if b != a + 1:
                    runs.append((s, a))
                    s = b
            runs.append((s, diffs[-1]))
            print("    连续差异段 %d 个（运行期地址 / 文件原文 -> 客户机现值）：" % len(runs))
            for a, b in runs[:40]:
                addr = BASE + p_vaddr + a
                print("      0x%08x (+0x%-8x 长 %d)：%s -> %s"
                      % (addr, a, b - a + 1,
                         want[a:b + 1][:16].hex(),
                         guest[a:b + 1][:16].hex()))
            if len(runs) > 40:
                print("      ……其余 %d 段省略" % (len(runs) - 40))


if __name__ == "__main__":
    main()
