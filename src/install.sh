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

log "运行验证套件（32 项：11 静态载荷 + 4 动态链接冒烟 + 17 项回归）..."
bash "$PROJECT_ROOT/tests/verify.sh" || die "验证未通过"

# 装 mlc 命令（与 MLC.command 第 5 步同一套动作，两边必须保持一致）。
# 以前这里只打印"已装到 ~/.local/bin/mlc"却什么都没做，是一句空话。
log "安装 mlc 命令到 ${HOME}/.local/bin ..."
BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR" || die "无法创建 $BIN_DIR"
cp "$SRC/mlc" "$BIN_DIR/mlc" || die "拷贝失败"
chmod +x "$BIN_DIR/mlc"
sed -i '' "s|^INSTALL_HOME=\"\"|INSTALL_HOME=\"$PROJECT_ROOT\"|" "$BIN_DIR/mlc" || die "写入项目根失败"
grep -q "^INSTALL_HOME=\"$PROJECT_ROOT\"" "$BIN_DIR/mlc" || die "项目根未写进 ${BIN_DIR}/mlc"
log "mlc 已安装：${BIN_DIR}/mlc（项目根 ${PROJECT_ROOT}）"
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    log "提示：$BIN_DIR 不在 PATH 里，重开终端或先执行 export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

log "=== 安装完成 ==="
log "用法:"
log "  mlc ls -la /                # 列 rootfs 根目录"
log "  mlc cat /etc/hostname       # 读 rootfs 里的文件"
log "  mlc --list                  # rootfs 里可运行的程序清单"
log "  mlc sh -c 'ls /'            # 跑 sh 里的外部命令（fork/exec）"
log "  bash tests/stability.sh     # 偶发失败率观测（不作为门禁，见 docs/09 风险登记表）"
log "  $SRC/mlc-core <elf> [参数...]  # 直接调翻译器"
log "已知边界：多线程、真实信号投递、网络、非 PIE 镜像尚未实现，"
log "      偶发失败率与已知缺陷见 docs/09-风险登记表.md 与 docs/10-整改清单.md"
