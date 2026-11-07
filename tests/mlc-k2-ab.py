#!/usr/bin/env python3
"""交替 A/B 测试：把「修 x10 抹改」前后的引擎交替运行，控制时间漂移。

交替而不是分批，是因为 K2 的失败率在全天范围内会从 0% 漂到 70%，
分批测会把时段波动算成改动效果（2026-11-06 已经因此误判过一次：
单批 40 轮得出「MLC_DEBUG 让失败率归零」，复测 100 轮得 63 次失败）。

用法：mlc-k2-ab.py [轮数]
"""
import os
import subprocess
import sys

PROJECT = "/Users/mm/Pictures/mac-linux-compat"
# 两个二进制必须都放在项目 src/ 下：引擎用自身路径推导 rootfs 前缀，
# 放在 /tmp 会拿到 /tmp/../rootfs/sysroot，直接 ENOENT 退出码 1——
# 退出码不是 127，于是被统计成「没失败」，A/B 结论整个作废。
OLD = os.path.join(PROJECT, "src/mlc-core-ab-old")
NEW = os.path.join(PROJECT, "src/mlc-core")
PERL = "rootfs/sysroot/usr/bin/perl"

n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
old_fail = new_fail = 0
old_crash = new_crash = 0
for i in range(n):
    for tag, exe in (("old", OLD), ("new", NEW)):
        p = subprocess.run([exe, PERL, "-e", "print 6*7"], cwd=PROJECT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if p.returncode == 127:
            if tag == "old":
                old_fail += 1
            else:
                new_fail += 1
        elif p.returncode == 99:
            if tag == "old":
                old_crash += 1
            else:
                new_crash += 1
print("旧版（x10 被抹）：符号失败 %d/%d，崩溃 %d/%d" % (old_fail, n, old_crash, n))
print("新版（x10 已还原）：符号失败 %d/%d，崩溃 %d/%d" % (new_fail, n, new_crash, n))
if new_fail < old_fail:
    print("新版失败更少：降低 %d 次（%.1f 个百分点）" % (old_fail - new_fail, 100.0 * (old_fail - new_fail) / n))
elif new_fail > old_fail:
    print("新版失败更多：升高 %d 次" % (new_fail - old_fail))
else:
    print("两版失败次数相同，本项改动对 K2 无影响")
