#!/usr/bin/env python3
"""K2 因果验证：跑 N 次 perl，每次把「link_map+0x448 指向的符号」与「本轮失败符号」配对。

用法：mlc-k2-causal.py [次数]
转储目录固定 /tmp/k2causal，引擎二进制与 rootfs 路径按仓库约定写死。
"""
import os
import re
import struct
import subprocess
import sys

PROJECT = "/Users/mm/Pictures/mac-linux-compat"
CORE = os.path.join(PROJECT, "src/mlc-core")
PERL = "rootfs/sysroot/usr/bin/perl"
PERL_FILE = os.path.join(PROJECT, PERL)
OUT = "/tmp/k2causal"
DYNSYM, DYNSTR = 0x2bd0, 0xc248
FIELD = 0x448

D = open(PERL_FILE, "rb").read()


def sym_name(idx):
    o = DYNSYM + idx * 24
    if o + 24 > len(D):
        return "?"
    st_name, = struct.unpack_from("<I", D, o)
    if DYNSTR + st_name >= len(D):
        return "?st_name=%d" % st_name
    e = D.find(b"\0", DYNSTR + st_name)
    if e < 0:
        return "?st_name=%d" % st_name
    return D[DYNSTR + st_name:e].decode("utf-8", "replace")


def sym_at(idx):
    o = DYNSYM + idx * 24
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", D, o)
    return st_name, st_info, st_shndx, st_value, st_size


def load_regions(errlog):
    regs = []
    with open(errlog) as f:
        for line in f:
            m = re.search(r"区域 (\d+) \[(0x[0-9a-f]+),(0x[0-9a-f]+)\) -> ([^\s，]+)", line)
            if not m:
                continue
            i = int(m.group(1))
            lo, hi = int(m.group(2), 16), int(m.group(3), 16)
            p = os.path.join(OUT, "cur", "reg%02d.bin" % i)
            if os.path.exists(p):
                with open(p, "rb") as fh:
                    regs.append((lo, hi, fh.read()))
    return regs


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    os.system("rm -rf %s" % OUT)
    os.makedirs(os.path.join(OUT, "cur"), exist_ok=True)
    agree = dis = 0
    for i in range(1, n + 1):
        env = dict(os.environ, MLC_DEBUG="1", MLC_DUMP_DIR=os.path.join(OUT, "cur"))
        p = subprocess.run([CORE, PERL, "-e", "print 6*7"], cwd=PROJECT,
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        rc = p.returncode
        err = p.stderr.decode("utf-8", "replace")
        with open(os.path.join(OUT, "cur", "err.txt"), "w") as f:
            f.write(err)
        m = re.search(r"加载 rootfs/sysroot/usr/bin/perl：基址 (0x[0-9a-f]+)", err)
        fm = re.search(r"undefined symbol: ([A-Za-z0-9_.]+)", err)
        failsym = fm.group(1) if fm else None
        if not m:
            print("第 %2d 轮 rc=%d 没取到 perl 基址" % (i, rc))
            continue
        base = int(m.group(1), 16)
        regs = load_regions(os.path.join(OUT, "cur", "err.txt"))

        def rd(addr, k):
            for lo, hi, blob in regs:
                if lo <= addr and addr + k <= hi:
                    return blob[addr - lo:addr - lo + k]
            return None

        # 找 perl 的 link_map：用 l_entry（偏移 0x2f8）唯一确定，比按 l_addr 扫可靠
        entry = base + 0x44fc0
        perlmap = None
        for lo, hi, blob in regs:
            for off in range(0, len(blob) - 0x40, 8):
                if struct.unpack_from("<Q", blob, off)[0] != entry:
                    continue
                cand = lo + off - 0x2f8
                a = struct.unpack_from("<Q", blob, off - 0x2f8)[0]
                if a == base:
                    perlmap = cand
                    break
            if perlmap:
                break
        if perlmap is None:
            print("第 %2d 轮 rc=%d 失败符号 %-18s 没找到 perl 的 link_map"
                  % (i, rc, failsym or "无"))
            continue
        pv = struct.unpack("<Q", rd(perlmap + FIELD, 8))[0]
        off_in_img = pv - base
        idx = (off_in_img - DYNSYM) // 24 if DYNSYM <= off_in_img < DYNSYM + 0x9678 else None
        info = ""
        if idx is not None and (off_in_img - DYNSYM) % 24 == 0:
            st_name, st_info, st_shndx, st_value, st_size = sym_at(idx)
            info = "%s(idx=%d, st_shndx=%d)" % (sym_name(idx), idx, st_shndx)
        else:
            info = "非 dynsym 项（偏移 0x%x）" % off_in_img
        same = ""
        if failsym:
            if failsym in info:
                same = "  <<< 与失败符号相同"
                agree += 1
            else:
                same = "  <<< 与失败符号不同"
                dis += 1
        print("第 %2d 轮 rc=%3d 失败符号 %-18s 缓存字段 -> %s%s"
              % (i, rc, failsym or "无", info, same))
    print("\n缓存字段指向的符号与失败符号：相同 %d 次，不同 %d 次" % (agree, dis))


if __name__ == "__main__":
    main()
