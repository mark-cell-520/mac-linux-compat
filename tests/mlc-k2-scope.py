#!/usr/bin/env python3
"""在转储里找 r_scope_elem，确认 perl 的查找范围里到底有哪些库。

r_scope_elem 的布局是 {dirs, r_list, r_nlist}，r_list 是 link_map 指针数组。
判据：某处 qword 是指针，+8 处是另一个指针，+16 处是个不大不小的整数，
且那个指针指向的数组里有至少两个已知 link_map 地址。

用法：mlc-k2-scope.py <dump> <err> <libc 基址 hex>
"""
import os
import re
import struct
import sys

DUMP, ERRLOG = sys.argv[1], sys.argv[2]
LIBC_BASE = int(sys.argv[3], 16)


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


R = load_regions()


def rd(addr, n):
    for _, lo, hi, blob in R:
        if lo <= addr and addr + n <= hi:
            return blob[addr - lo:addr - lo + n]
    return None


def q(addr):
    b = rd(addr, 8)
    return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None


def region_of(addr):
    for i, lo, hi, _ in R:
        if lo <= addr < hi:
            return i
    return None


def main():
    # 1. 找 libc 的 link_map
    libc_map = None
    for _, lo, hi, blob in R:
        for off in range(0, len(blob) - 0x40, 8):
            a, = struct.unpack_from("<Q", blob, off)
            if a == LIBC_BASE:
                libc_map = lo + off
                break
        if libc_map:
            break
    if not libc_map:
        print("没找到 libc 的 link_map")
        return 1
    print("libc link_map @ 0x%x" % libc_map)

    # 2. 沿 l_prev 走到链头，收集全部 map
    maps = {}
    cur = libc_map
    for _ in range(8):
        p = q(cur + 0x20)
        if not p or p in maps:
            break
        maps[p] = True
        cur = p
    head = cur
    chain = []
    cur = head
    for _ in range(8):
        chain.append(cur)
        n = q(cur + 0x18)
        if not n:
            break
        cur = n
    names = {}
    for m in chain:
        np = q(m + 0x08)
        b = rd(np, 64) if np else None
        names[m] = (b.split(b"\0")[0].decode("utf-8", "replace") if b else "<主程序>")
    print("链上 %d 个 map：%s" % (len(chain), ", ".join("0x%x(%s)" % (m, names[m]) for m in chain)))
    mapset = set(chain)

    # 3. 扫 r_scope_elem
    print("\n扫描 r_scope_elem：")
    found = 0
    for _, lo, hi, blob in R:
        for off in range(0, len(blob) - 0x20, 8):
            dirs, rlist, rnlist = struct.unpack_from("<QQQ", blob, off)
            if not (0x100000000 < rlist < 0x200000000):
                continue
            if not (0 < rnlist < 64):
                continue
            b = rd(rlist, rnlist * 8)
            if not b or len(b) < rnlist * 8:
                continue
            items = struct.unpack_from("<%dQ" % rnlist, b)
            hits = [x for x in items if x in mapset]
            if len(hits) < 2:
                continue
            found += 1
            where = lo + off
            # 这个 r_scope_elem 被谁的 l_scope 引用
            owner = None
            for m in chain:
                for k in range(4):
                    if q(m + 0x440 + k * 8) == where:
                        owner = (m, k)
                        break
                if owner:
                    break
            print("  r_scope_elem @ 0x%x（region%d）r_nlist=%d，属主 %s"
                  % (where, region_of(where) or -1, rnlist,
                     ("map 0x%x(%s) 的 l_scope[%d]" % (owner[0], names[owner[0]], owner[1]))
                     if owner else "未定位"))
            for j, it in enumerate(items):
                nm = names.get(it)
                print("      [%d] 0x%x %s" % (j, it, nm if nm else "(非链上 map)"))
    if not found:
        print("  一个都没找到。退一步：直接扫所有含 >=3 个链上 map 指针的 8 字节网格。")
        for _, lo, hi, blob in R:
            for off in range(0, len(blob) - 0x40, 8):
                vals = struct.unpack_from("<8Q", blob, off)
                hits = [v for v in vals if v in mapset]
                if len(hits) >= 3:
                    print("  0x%x：%s" % (lo + off, " ".join(
                        ("*0x%x" % v) if v in mapset else hex(v) for v in vals)))


if __name__ == "__main__":
    main()
