#!/usr/bin/env python3
"""对比失败轮与成功轮的 link_map 链、l_scope 与 l_versions。

之所以要看 l_versions：它是 glibc 在 _dl_check_map_versions 里 malloc 出来的
数组，**不属于任何库的 PT_LOAD**，所以此前「按 PT_LOAD 全量比对五个库映像」
那轮排查根本没有覆盖它。符号查找带版本时（perl 需要 calloc@GLIBC_2.17），
第一步就是读调用者 link_map 的 l_versions[ndx] 拿 {hash, name}；
这个数组若没被正确建立或后来被踩，查找会在第一步就落空，
报的正是「undefined symbol: calloc, version GLIBC_2.17」。

用法：mlc-k2-lv.py <dump目录>
"""
import os
import re
import struct
import sys

DUMP = sys.argv[1].rstrip("/")


def load_regions():
    regs = []
    for line in open(os.path.join(DUMP, "err.txt")):
        m = re.search(r"\[mlc\]\[转储\] 区域 (\d+) \[(0x[0-9a-f]+),(0x[0-9a-f]+)\) -> ([^\s，]+)", line)
        if not m:
            continue
        i, lo, hi, p = int(m.group(1)), int(m.group(2), 16), int(m.group(3), 16), m.group(4)
        if os.path.exists(p):
            regs.append((i, lo, hi, open(p, "rb").read()))
    return regs


R = load_regions()


def rd(a, n):
    out = b""
    while n > 0:
        hit = None
        for _, lo, hi, b in R:
            if lo <= a < hi:
                k = min(n, hi - a)
                out += b[a - lo:a - lo + k]
                a += k
                n -= k
                hit = 1
                break
        if not hit:
            return None
    return out


def q(a):
    b = rd(a, 8)
    return struct.unpack("<Q", b)[0] if b else None


def cstr(a):
    b = rd(a, 128)
    if b is None:
        return None
    e = b.find(b"\0")
    return b[:e].decode("utf-8", "replace") if e >= 0 else "<无NUL>"


def main():
    txt = open(os.path.join(DUMP, "err.txt")).read()
    perl_base = int(re.search(r"加载 rootfs/\S+/perl：基址 (0x[0-9a-f]+)", txt).group(1), 16)
    perl_ent = int(re.search(r"入口 (0x[0-9a-f]+)", txt).group(1), 16)
    print("perl 基址 0x%x 入口 0x%x" % (perl_base, perl_ent))

    perl_map = None
    for _, lo, hi, b in R:
        for off in range(0, len(b) - 0x40, 8):
            v, = struct.unpack_from("<Q", b, off)
            if v != perl_base:
                continue
            if q(lo + off + 0x2f8) == perl_ent:
                perl_map = lo + off
                break
        if perl_map:
            break
    if not perl_map:
        print("没定位到 perl 的 link_map")
        return 1
    print("perl link_map @ 0x%x" % perl_map)

    chain = []
    cur = perl_map
    for _ in range(12):
        chain.append(cur)
        n = q(cur + 0x18)
        if not n or n in chain:
            break
        cur = n
    names = {}
    for m in chain:
        np = q(m + 0x08)
        nm = cstr(np) if np else None
        names[m] = nm if nm else "<无名 ptr=0x%x>" % (np or 0)
    print("\nlink_map 链 %d 项：" % len(chain))
    for m in chain:
        print("  0x%x l_addr=0x%x l_name_ptr=0x%x l_name=%s" % (m, q(m), q(m + 0x08), names[m]))

    # 收集 .dynstr 里的 GLIBC_ 字符串，用于识别 l_versions 数组
    glibc_strs = {}
    for _, lo, hi, b in R:
        off = 0
        while True:
            j = b.find(b"GLIBC_", off)
            if j < 0:
                break
            off = j + 6
            e = b.find(b"\0", off)
            if e > off:
                glibc_strs[lo + j] = b[j:e].decode("utf-8", "replace")
    print("\n.dynstr 里 GLIBC_ 字符串 %d 个" % len(glibc_strs))

    mapset = set(chain)
    for m in chain:
        print("\n=== map 0x%x (%s) ===" % (m, names[m]))
        # l_scope：扫该 map 的每个指针字段，看指向的数组是否含链上 map
        for fld in range(0x260, 0x500, 8):
            p = q(m + fld)
            if not p or p < 0x100000000:
                continue
            arr = []
            pp = p
            for _ in range(10):
                v = q(pp)
                if not v:
                    break
                arr.append(v)
                pp += 8
            if len([v for v in arr if v in mapset]) >= 2:
                print("  l_scope：字段 0x%x -> 0x%x，%d 项：%s"
                      % (fld, p, len(arr), " | ".join(names.get(v, "?") for v in arr)))
                break
        # l_versions：扫该 map 的每个指针字段，看指向的数组是否 {hash, GLIBC_*} 成对
        for fld in range(0x260, 0x500, 8):
            p = q(m + fld)
            if not p or p < 0x100000000:
                continue
            rows = []
            for k in range(12):
                h = q(p + k * 16)
                nm = q(p + k * 16 + 8)
                if nm in glibc_strs:
                    rows.append((k, h, glibc_strs[nm]))
            if len(rows) >= 2:
                print("  l_versions：字段 0x%x -> 0x%x，%d 个版本："
                      % (fld, p, len(rows)))
                for k, h, nm in rows:
                    hit = "  <<< perl 要的就是它" if (h == 0x06969197 and nm == "GLIBC_2.17") else ""
                    print("      [%d] hash=0x%08x name=%s%s" % (k, h, nm, hit))
                break
        else:
            print("  l_versions：扫遍 0x260-0x500 没找到")

    # 收尾：直接回答 perl 那一项在不在
    print("\n=== 结论 ===")
    pm = names.get(perl_map, "")
    found = False
    for fld in range(0x260, 0x500, 8):
        p = q(perl_map + fld)
        if not p or p < 0x100000000:
            continue
        for k in range(12):
            h = q(p + k * 16)
            nm = q(p + k * 16 + 8)
            if nm in glibc_strs:
                found = True
    print("perl 主程序的 l_versions 数组：%s" % ("存在" if found else "扫不到"))


if __name__ == "__main__":
    main()
