#!/bin/bash
# ============================================================
# MLC 安装脚本（v1）：构建翻译器核心并自检
# 唯一依赖：Xcode 命令行工具（clang）。不装任何第三方组件。
# ============================================================
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$PROJECT_ROOT/src"

log() { echo "[MLC-安装] $*"; }
die() { echo "[MLC-安装][错误] $*" >&2; exit 1; }

log "前置检查..."
[ "$(uname -m)" = "arm64" ] || die "只支持 Apple Silicon（arm64）"
command -v clang >/dev/null || die "缺少 clang，请先运行 xcode-select --install"

log "解包 rootfs（仓库只带 29MB tarball）..."
bash "$PROJECT_ROOT/scripts/unpack-rootfs.sh" || die "rootfs 解包失败"

log "构建 mlc-core..."
clang -O2 -Wall -o "$SRC/mlc-core" "$SRC/mlc-core.c" || die "编译失败"
log "构建完成: $SRC/mlc-core"

log "运行验证套件（25 项：11 静态载荷 + 4 动态链接冒烟 + 10 项回归）..."
bash "$PROJECT_ROOT/tests/verify.sh" || die "验证未通过"

log "=== 安装完成 ==="
log "用法:"
log "  mlc ls -la /                # 命令行入口（已装到 ~/.local/bin/mlc）"
log "  bash tests/stability.sh     # 偶发失败率观测（不作为门禁，见 docs/10 的 K1）"
log "  $SRC/mlc-core <elf> [参数...]  # 直接调翻译器"
log "说明: 动态链接镜像已可运行；fork/exec、多线程、真实信号尚未实现，"
log "      动态链接错误路径有约 2% 偶发失败（缺陷 K1），见 docs/10-整改清单.md"
