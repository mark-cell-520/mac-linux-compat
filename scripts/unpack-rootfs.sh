#!/bin/bash
# ============================================================
# MLC rootfs 解包：仓库只带 29MB 的 tarball，跑之前要先解出 sysroot
#
# 为什么不把 103MB 的 sysroot 直接入库：
#   1. GitHub 对单仓库体积敏感，103MB 的解压树 + 29MB 的包是 132MB 的纯数据，
#      而交付代码与文档合计不足 1MB——clone 时间全花在数据上；
#   2. tarball 可校验（sha256），解压树不可校验，散落入库反而容易版本漂移；
#   3. 换 rootfs 只需换一个包，不必重提整个仓库历史。
#
# 卸载：删掉 rootfs/sysroot 目录即可，tarball 可留可删。
# ============================================================
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOTFS="$PROJECT_ROOT/rootfs"
TARBALL="$ROOTFS/ubuntu-base-arm64.tar.gz"
SYSROOT="$ROOTFS/sysroot"

log() { echo "[MLC-rootfs] $*"; }

[ -f "$TARBALL" ] || { echo "[MLC-rootfs][错误] 找不到 $TARBALL" >&2; exit 1; }

if [ -d "$SYSROOT" ] && [ -n "$(ls -A "$SYSROOT" 2>/dev/null)" ]; then
    log "sysroot 已存在，跳过解压：$SYSROOT"
    exit 0
fi

log "解压 $TARBALL -> $SYSROOT （约 103MB，需要十几秒）"
mkdir -p "$SYSROOT" || exit 1
tar xzf "$TARBALL" -C "$SYSROOT" || { echo "[MLC-rootfs][错误] 解压失败" >&2; exit 1; }

# 验收：解出来的树必须带 bin 与 lib，且 ld.so 在位
for p in bin lib lib/ld-linux-aarch64.so.1 usr/bin; do
    [ -e "$SYSROOT/$p" ] || { echo "[MLC-rootfs][错误] 解压结果缺少 $p" >&2; exit 1; }
done
log "解压完成：$(du -sh "$SYSROOT" | cut -f1)（$(find "$SYSROOT" | wc -l | tr -d ' ') 个条目）"
