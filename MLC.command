#!/bin/bash
# ============================================================
# MLC 一键安装（macOS Apple Silicon）
#
# 双击本文件即可完成：检查依赖 → 解包 rootfs → 构建翻译器 → 跑验证套件 →
# 安装 mlc 命令到 ~/.local/bin。不装 Homebrew、不动系统配置、不留服务。
# 卸载：删掉 $MLC_HOME 与 ~/.local/bin/mlc 即可，无残留。
# ============================================================
set -uo pipefail

MLC_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$MLC_HOME/src"
BIN_DIR="${HOME}/.local/bin"

log()  { echo "[MLC-安装] $*"; }
die()  { echo "[MLC-安装][错误] $*" >&2; echo "按回车键关闭窗口..."; read -r; exit 1; }

log "MLC 安装目录：$MLC_HOME"

# 1. 前置检查
[ "$(uname -m)" = "arm64" ] || die "只支持 Apple Silicon（arm64），当前是 $(uname -m)"
[ "$(uname -s)" = "Darwin" ] || die "只支持 macOS"
command -v clang >/dev/null 2>&1 || die "缺少 clang。请先运行：xcode-select --install"

# 2. 解包 rootfs（仓库只带 tarball，103MB 的解压树按需生成）
log "检查 rootfs ..."
bash "$MLC_HOME/scripts/unpack-rootfs.sh" || die "rootfs 解包失败"

# 3. 构建翻译器核心
log "构建翻译器核心（src/mlc-core.c）..."
clang -O2 -Wall -o "$SRC/mlc-core" "$SRC/mlc-core.c" || die "编译失败"
log "构建完成：$SRC/mlc-core"

# 4. 自检
log "运行验证套件（32 项）..."
bash "$MLC_HOME/tests/verify.sh" || die "验证未通过，安装中止"

# 5. 装 mlc 命令
log "安装 mlc 命令到 $BIN_DIR ..."
mkdir -p "$BIN_DIR" || die "无法创建 $BIN_DIR"
cp "$SRC/mlc" "$BIN_DIR/mlc" || die "拷贝失败"
chmod +x "$BIN_DIR/mlc"

# 6. PATH 提示
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    # 按当前 shell 选 rc 文件：两个分支都写 .zshrc 是条恒真的死代码，
    # bash 用户会被告知"已写进 .zshrc"然后什么都不生效（2026-11-06 审计修）
    case "${SHELL:-}" in
        */bash) SHELL_RC="${HOME}/.bashrc" ;;
        *)      SHELL_RC="${HOME}/.zshrc" ;;
    esac
    if [ -f "$SHELL_RC" ] && grep -q '\.local/bin' "$SHELL_RC" 2>/dev/null; then
        log "$SHELL_RC 里已有 ~/.local/bin，重开终端即可生效"
    else
        printf '\n# MLC（mac-linux-compat）\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$SHELL_RC"
        log "已把 ~/.local/bin 写进 $SHELL_RC，重开终端即可生效"
        log "当前终端可先执行：export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi

log "=== 安装完成 ==="
log "用法："
log "  mlc ls -la /                 列 rootfs 根目录"
log "  mlc cat /etc/hostname        读 rootfs 里的文件"
log "  mlc --list                   看 rootfs 里有哪些程序"
log "  mlc sh -c 'echo hi'          跑 sh"
log "rootfs 位置：$MLC_HOME/rootfs/sysroot（Ubuntu Base 24.04.5 ARM64）"
log "已知边界：多线程、真实信号投递、fork/exec 尚未实现；动态链接错误路径有约 2% 偶发失败"
log "          （缺陷 K1，见 docs/10-整改清单.md；复现与观测用 bash tests/stability.sh）"
echo
echo "按回车键关闭窗口..."
read -r
