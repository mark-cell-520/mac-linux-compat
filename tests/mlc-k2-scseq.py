#!/usr/bin/env python3
"""对比失败轮与成功轮的系统调用序列，找第一次分叉点。

背景：失败轮与成功轮在退出时刻的所有符号查找结构（link_map 链、scope、
l_versions、libc 的 bloom/buckets/chain、.gnu.version、.dynsym 项）逐项
完全相同（用 mlc-k2-lv.py 与 tests/mlc-k2-imgcmp.py 六轮交叉验证过），
说明差异不在最终状态而在过程里。系统调用序列是过程的可观测投影。

实测结论（2026-11-09，MLC_SC_TRACE=1 抓 6 失败 + 13 成功）：
  失败轮长度 46 或 47，成功轮长度 176 到 178。
  5 个失败轮在第 44 项完全一致地分叉：前 4 个 mprotect 之后，
    成功轮继续 prlimit64、munmap、rt_sigaction×67、write，
    失败轮直接 writev（错误信息）+ exit_group。
  另有 1 个失败轮（sc-17）在第 12 项就分叉：成功轮连续两次 munmap，
    失败轮只有一次 munmap 就接 mprotect。
  计数差异：失败轮 mmap 13、munmap 5、mprotect 7、rt_sigaction 0；
            成功轮 mmap 15、munmap 5、mprotect 8、rt_sigaction 67。
也就是失败发生在 ld.so 处理 perl 自身重定位的阶段，且库加载阶段的
映射/解除映射次数已经开始不同。

用法：mlc-k2-scseq.py <目录>     （目录里是 MLC_SC_TRACE=1 抓的 stderr 文件）
"""
import glob
import os
import re
import sys
from collections import Counter

NR = {
    25: "mprotect?", 29: "ioctl", 48: "faccessat?", 56: "openat", 57: "close",
    62: "lseek", 63: "read", 64: "write", 66: "writev", 78: "readlinkat",
    79: "readlinkat2?", 80: "fstat", 93: "exit", 94: "exit_group",
    96: "set_tid_address", 98: "futex", 99: "sysinfo?", 113: "clock_gettime",
    134: "rt_sigaction", 174: "getuid", 175: "geteuid", 176: "getgid",
    177: "getegid", 214: "brk", 215: "munmap", 222: "mmap", 226: "mprotect",
    261: "prlimit64", 278: "?", 293: "?",
}


def nm(n):
    return "%d(%s)" % (n, NR.get(n, "?"))


def load(d):
    out = {}
    for p in sorted(glob.glob(os.path.join(d, "*"))):
        try:
            txt = open(p, errors="replace").read()
        except OSError:
            continue
        tail = [l.strip() for l in txt.splitlines() if l.strip() in ("0", "127")]
        if not tail:
            continue
        m = re.search(r"系统调用序列（(\d+) 个）：([\d,]*)", txt)
        if not m:
            continue
        out[os.path.basename(p)] = ([int(x) for x in m.group(2).split(",") if x],
                                   tail[-1] == "127")
    return out


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    data = load(d)
    fails = {k: v[0] for k, v in data.items() if v[1]}
    oks = {k: v[0] for k, v in data.items() if not v[1]}
    print("失败轮 %d 个，成功轮 %d 个" % (len(fails), len(oks)))
    if not fails or not oks:
        print("缺一侧，无法对比")
        return 1
    print("失败轮长度：%s" % [len(v) for v in fails.values()])
    print("成功轮长度：%s" % [len(v) for v in oks.values()])
    print()
    oklist = sorted(oks.items())
    bk, base = oklist[0]
    print("基准成功轮 %s（长度 %d）" % (bk, len(base)))
    for k, seq in sorted(fails.items()):
        n = min(len(base), len(seq))
        i = 0
        while i < n and base[i] == seq[i]:
            i += 1
        print("  失败 %-12s 长度 %-4d 第一次分叉下标 %d" % (k, len(seq), i))
        print("      基准：[%s]" % " ".join(nm(x) for x in base[max(0, i - 3):i + 8]))
        print("      失败：[%s]" % " ".join(nm(x) for x in seq[max(0, i - 3):i + 8]))
    print()
    print("=== 调用计数对比 ===")
    cf = Counter()
    for v in fails.values():
        cf.update(v)
    co = Counter()
    for v in oks.values():
        co.update(v)
    keys = sorted(set(cf) | set(co))
    for k in keys:
        a, b = cf.get(k, 0), co.get(k, 0)
        print("  %-14s 失败侧合计 %-5d 成功侧合计 %-5d %s"
              % (nm(k), a, b, "   <<< 差异" if abs(a - b) > 0 else ""))
    print()
    print("=== 各轮末尾 8 个调用 ===")
    for k, v in sorted(fails.items())[:3]:
        print("  失败 %-12s %s" % (k, " ".join(nm(x) for x in v[-8:])))
    for k, v in oklist[:2]:
        print("  成功 %-12s %s" % (k, " ".join(nm(x) for x in v[-8:])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
