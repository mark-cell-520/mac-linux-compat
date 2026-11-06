# MLC — mac-linux-compat

macOS 上的 Linux 兼容层。不做虚拟机，用用户态翻译在 macOS ARM64 上直接运行 Linux ARM64 程序。
思路与 CrossOver/Wine 同构：客户机指令原生执行，Linux 系统调用在本进程内翻译成 macOS 调用。

## 现状（2026-11-06，v1.3）

能跑：Ubuntu Base 24.04.5 ARM64 的真实动态 PIE 可执行文件。
实测通过：`ls`、`ls -la /`、`cat`、`echo`、`sh -c`（内建命令）、
完整的 ld.so → libc → libselinux → libpcre2 动态链接链、locale/gconv 初始化、
`statx/newfstatat/lstat` 权限与符号链接、`getdents64` 目录列举、
客户机退出码原样透传。
已验证约 60 个系统调用；tests/verify.sh 二十一项全过（十一项静态载荷 + 四项动态链接冒烟 + 六项审计回归）。
不能跑：fork/exec（外部命令）、多线程、真实信号投递、网络、非 PIE 镜像
（见 docs/10-整改清单.md 的 M2/M3 段）。
已知缺陷：动态链接错误路径有 2% 到 5% 的偶发失败（缺陷 K1，见 docs/10，
复现与量化用 `bash tests/stability.sh`）。成功路径不复现。

v1.3 做了一轮全量审计（src/mlc-core.c 1742 行通读），修掉 12 项产品缺陷与
3 项测试自身缺陷，编号 F37-F50 见 docs/08。最重的一条是宿主栈缓冲区溢出：
客户机参数条数没有上界，`mlc $(seq 1 500)` 就能踩宿主栈。

## 一键安装

双击 `MLC.command`（Finder 里右键→打开，或直接双击）。
脚本依次做：检查 arm64 + clang → 解包 rootfs → 构建 src/mlc-core → 跑 21 项验证 →
把 `mlc` 命令拷到 `~/.local/bin`。不装 Homebrew、不改系统配置、不留服务。
卸载：删掉项目目录与 `~/.local/bin/mlc`，无残留。

```bash
# 等价的手动安装
bash src/install.sh
```

rootfs 只以 29MB 的 tarball 形式入库（`rootfs/ubuntu-base-arm64.tar.gz`），
103MB 的解压树由 `scripts/unpack-rootfs.sh` 按需生成，安装流程会自动调用。
想瘦身仓库就删掉 `rootfs/sysroot`；想彻底不要数据就删掉 tarball，
代价是 mlc 只能跑静态链接的客户机。

## 快速开始

```bash
mlc ls -la /                 # 列 rootfs 根目录
mlc cat /etc/hostname        # 读 rootfs 里的文件
mlc --list                   # rootfs 里可运行的程序清单
mlc sh -c 'echo hi'          # 跑 sh（内建命令）
bash tests/verify.sh         # 二十一项验证
bash tests/stability.sh 200  # 偶发失败率观测（只报告，不作门禁）
```

`mlc` 与直接调 `src/mlc-core` 的关系：`mlc` 负责在 rootfs 里按客户机 PATH 找程序、
透传参数、原样返回退出码；翻译器本体仍是 `src/mlc-core`。

路径语义：客户机的绝对路径（`/etc/hostname`）重写进 `rootfs/sysroot`；
相对路径与 `.` 用宿主当前目录，因此 `mlc ls` 列的是你所在目录的真实文件。

## 原理

1. ET_DYN 镜像从「客户机地址窗口」顺序取址（蹦桌池 16MB + 窗口 96MB 一次映射、
   物理相邻，任一库到蹦桌的 B 距离必然在 ±128MB 内），按段拷贝、按段 mprotect。
2. 有 PT_INTERP 时按同一机制加载 ld.so（从窗口高端向下），再把控制权交给它，
   由 glibc 的加载器完成全部依赖库映射与重定位。
3. 可执行段里的 svc #0 替换为 B（不写 LR，Linux 的 svc 本来就不碰 LR），
   跳到进程内蹦桌；每个 svc 一份独立副本，副本末条用可运行时修补的 B 立即数
   编码返回地址。蹦桌进出时保存/恢复客户机 TPIDR_EL0。
4. 客户机栈按 AArch64 PCS 搭建（argc/argv/envp/auxv，SP 16 字节对齐），
   argv 条数、环境变量条数、初始栈词数都有硬上限，栈顶留白 64KB——
   这三个数原先没有上界，客户机参数可以直接踩宿主栈（F37）。
   auxv 的 AT_PAGESZ 报宿主真实页大小 16384——报 4096 会让 glibc 的段对齐
   与宿主页粒度错位，把同页内相邻映射的数据抹掉（F35）。

## 目录

- MLC.command 一键安装（双击运行）
- src/mlc-core.c 翻译器核心（单文件，零第三方依赖）
- src/stub.s 系统调用存根汇编
- src/mlc 命令行入口（PATH 查找 + 退出码透传）
- src/install.sh 手动安装（等价于 MLC.command）
- scripts/unpack-rootfs.sh 按需解出 103MB 的 sysroot
- tests/ 测试载荷生成器（mkelf.py 迷你链接器 + test.s）、验证脚本（21 项）、稳定性观测
- rootfs/ubuntu-base-arm64.tar.gz Ubuntu Base 24.04.5 ARM64（29MB，解压后约 103MB）
- docs/ 十份生命周期文档：调研、准备、计划、执行、验证、审计、安全、修复、落地、整改

## 重要声明

MLC 不是沙箱：客户机以本进程权限直接操作宿主文件系统与进程（详见 docs/07）。
v1.3 起客户机的 MAP_FIXED / munmap / mprotect 一律不得覆盖引擎保护区
（镜像蹦桌区与蹦桌池），brk 预留区只登记已提交部分，区域表在 MAP_FIXED
失败时同步摘除——这三条都是为了「簿记不说谎」，让野指针校验始终有效。
但客户机仍可读写自己映射内的任意地址。只运行可信镜像。

## 为什么没有用 QEMU

qemu 官方 configure 硬禁 macOS 宿主构建 linux-user，homebrew 的 qemu 在 macOS 上也只有系统仿真。
该生态位因此空缺——现成引擎在 macOS 上不存在，必须自研。详见 docs/01 第 2.5 节。
