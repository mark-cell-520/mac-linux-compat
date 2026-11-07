#!/usr/bin/env python3
"""走 MLC 客户机的 link_map 链，检查每个库的 scope 与查表元数据。

用法：mlc-k2-chain.py <转储目录> <错误日志> <libc 基址，十六进制>

已知事实（由 mlc-k2-ptrs.py 定位）：libc 的 link_map 起点满足
偏移 0x00 是 l_addr（等于 libc 基址）、0x08 是 l_name、0x10 是 l_ld。
本脚本据此走完整条链，再反查每个 map 被谁引用（即谁把它放进了 l_scope）。
"""
import os
import re
import struct
import sys

DUMP, ERRLOG = sys.argv[1], sys.argv[2]
LIBC_BASE = int(sys.argv[3], 16)

F_L_ADDR, F_L_NAME, F_L_LD, F_L_NEXT, F_L_PREV = 0x00, 0x08, 0x10, 0x18, 0x20
F_L_REAL, F_L_NS, F_L_LIBNAME = 0x28, 0x30, 0x38


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


REGS = load_regions()


def read(addr, n):
    for _, lo, hi, blob in REGS:
        if lo <= addr and addr + n <= hi:
            return blob[addr - lo:addr - lo + n]
    return None


def q(addr):
    b = read(addr, 8)
    if b is None or len(b) < 8:
        return None
    return struct.unpack("<Q", b)[0]


def cstr(addr, limit=256):
    b = read(addr, limit)
    if b is None:
        return None
    z = b.find(b"\0")
    return b[:z].decode("utf-8", "replace") if z >= 0 else b.decode("utf-8", "replace")


def find_libc_map():
    for _, lo, hi, blob in REGS:
        for off in range(0, len(blob) - 0x40, 8):
            a, ld = struct.unpack_from("<QQ", blob, off)
            if a == LIBC_BASE:
                return lo + off
    return None


def find_refs(target):
    """找所有等于 target 的 qword，返回 [(地址, 所在区域号)]。"""
    out = []
    for i, lo, hi, blob in REGS:
        for off in range(0, len(blob) - 8, 8):
            v, = struct.unpack_from("<Q", blob, off)
            if v == target:
                out.append((lo + off, i))
    return out


def main():
    libc_map = find_libc_map()
    if libc_map is None:
        print("没找到 libc 的 link_map")
        return 1
    print("libc link_map @ 0x%x" % libc_map)

    # 沿 l_prev 走到链头
    head = libc_map
    seen = set()
    while True:
        p = q(head + F_L_PREV)
        if p is None or p in seen or p == 0:
            break
        seen.add(head)
        head = p
        if len(seen) > 64:
            break
    print("链头 @ 0x%x（沿 l_prev 回退 %d 步）" % (head, len(seen)))

    maps = []
    cur = head
    guard = 0
    while cur and guard < 64:
        guard += 1
        addr = q(cur + F_L_ADDR)
        namep = q(cur + F_L_NAME)
        ld = q(cur + F_L_LD)
        nxt = q(cur + F_L_NEXT)
        if addr is None:
            break
        maps.append((cur, addr, cstr(namep) if namep else None, ld, nxt))
        cur = nxt
    print("\n共 %d 个 link_map：" % len(maps))
    for cur, addr, name, ld, nxt in maps:
        print("  map 0x%08x  l_addr=0x%08x  l_ld=0x%08x  l_next=0x%08x  %s"
              % (cur, addr, ld or 0, nxt or 0, name))

    # 每个 map 被谁引用：引用点就是别人的 l_scope 条目或链指针
    print("\n各 map 的引用点（引用者地址 -> 被引用 map）：")
    for cur, addr, name, ld, nxt in maps:
        refs = find_refs(cur)
        owners = []
        for raddr, ridx in refs:
            # 引用点减去 map 起点，得到它在宿主结构里的偏移
            host = None
            for c2, a2, n2, l2, x2 in maps:
                if c2 <= raddr < c2 + 0x800:
                    host = (c2, raddr - c2)
                    break
            if host is None and ridx is not None:
                host = ("region%d" % ridx, raddr)
            owners.append("0x%x(来自 %s+0x%x)" % (raddr, host[0], host[1]))
        print("  map 0x%08x %-40s 被引用 %d 次：%s"
              % (cur, (name or "?")[:40], len(refs), ", ".join(owners[:12])))

    # perl 的 map：l_name 以 /usr/bin/perl 或 perl 结尾
    perl_map = None
    for cur, addr, name, ld, nxt in maps:
        if name and name.endswith("perl"):
            perl_map = cur
            break
    if perl_map is None:
        print("\n没在链里找到 perl 的 map")
        return 0
    print("\nperl link_map @ 0x%x" % perl_map)
    refs = find_refs(perl_map)
    print("perl map 被引用 %d 次" % len(refs))
    for raddr, ridx in refs:
        # scope 数组的特征：连续多个 qword 都是 map 指针
        row = []
        for k in range(-2, 14):
            v = q(raddr + k * 8)
            row.append(v)
        tag = ""
        if any(v in [m[0] for m in maps] for v in row if v):
            tag = "  <-- 附近有 map 指针，疑为 l_scope"
        print("  引用点 0x%x（region%d，距自身结构 0x%x）%s"
              % (raddr, ridx or -1, raddr - perl_map, tag))
        if tag:
            print("    上下文：%s" % " ".join("0x%x" % (v or 0) for v in row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
