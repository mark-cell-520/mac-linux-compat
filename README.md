# MLC — mac-linux-compat

macOS 上的 Linux 兼容层。不做虚拟机，用用户态翻译在 macOS ARM64 上直接运行 Linux ARM64 程序。
思路与 CrossOver/Wine 同构：客户机指令原生执行，Linux 系统调用在本进程内翻译成 macOS 调用。

## 现状（2026-11-06，v1.4）

能跑：Ubuntu Base 24.04.5 ARM64 的真实动态 PIE 可执行文件。
实测通过：`ls`、`ls -la /`、`cat`、`echo`、`sh -c`（内建命令）、
完整的 ld.so → libc → libselinux → libpcre2 动态链接链、locale/gconv 初始化、
`statx/newfstatat/lstat` 权限与符号链接、`getdents64` 目录列举、
客户机退出码原样透传。
已验证约 60 个系统调用；tests/verify.sh 二十三项全过（十一项静态载荷 + 四项动态链接冒烟 + 七项审计回归 + 一项寄存器保存回归）。
不能跑：fork/exec（外部命令）、多线程、真实信号投递、网络、非 PIE 镜像
（见 docs/10-整改清单.md 的 M2/M3 段）。
已知缺陷：动态链接路径有 2% 到 7% 的偶发崩溃（缺陷 K1，见 docs/10，
复现与量化用 `bash tests/stability.sh`）。成功路径不复现。

v1.4 接着 v1.3 的全量审计往下挖，修掉三处并新增两项观测口径：
1. 蹦桌漏存客户机寄存器。Linux aarch64 系统调用 ABI 规定除 x0 外所有寄存器
   原样保留，而蹦桌只存 x0-x9、x16-x23、x28、x30，漏掉 x10-x15、x24-x27、x29。
   blr 进 C 处理器会按 AAPCS 踩掉 x10-x15 且不还原，客户机放在这些寄存器里的
   活值就被抹了。tests/regs.elf 专盯这条，把 ML_STUB 里 ldp x10,x11 的还原
   换成 nop，退出码立刻从 0 变 10（断言有牙）。
2. 验证脚本的变量名吞全角字符。`bad "…（退出码 $DRC）"` 里 $DRC 后面紧跟
   全角括号，bash 3.2 在多字节 locale 下把它并进变量名，一旦断言失败要打
   失败原因就整个脚本 unbound variable 退出。已改为 ${DRC}、${CRC}。
3. 稳定性脚本的失败判据。原脚本把「退出码非 0」一律算失败，于是
   `ls /nonexistent` 每次都记失败 200/200——那个程序的正常退出码就是 2。
   改为只认崩溃签名退出码 99。
另加客户机 TPIDR_EL0 写入校验（见下）与系统调用入口的线程指针核对。

## 一键安装

双击 `MLC.command`（Finder 里右键→打开，或直接双击）。
脚本依次做：检查 arm64 + clang → 解包 rootfs → 构建 src/mlc-core → 跑 23 项验证 →
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
bash tests/verify.sh         # 二十三项验证
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
   编码返回地址。蹦桌保存并还原客户机全部 31 个通用寄存器（x0-x30）与
   TPIDR_EL0——x0-x30 一个都不能少，Linux 系统调用 ABI 规定除 x0 外全部保留，
   而 blr 进 C 处理器会按 AAPCS 踩掉 x10-x15（v1.4 修，见上文第 1 条）。
4. 同一遍扫描还拦 msr TPIDR_EL0, xN（编码 0xD51BD040|N）。客户机二进制里会写
   线程指针的只有 ld.so 两处（全 rootfs 扫过，libc 与所有程序、库一处都没有），
   走 mlc_tp_write_probe 校验：写入值是 mmap 出来的高地址就当有效 TCB 记下，
   太低（低于 0x10000000）说明是 macOS libSystem 的遗留小值，手里有有效 TCB
   就顶替。系统调用入口再核对一次保存块里的值。两条路都是为了「客户机线程指针
   不许变成野值」——TPIDR 一野，glibc 所有 TP 相对访问都落到近零地址上。
5. 客户机栈按 AArch64 PCS 搭建（argc/argv/envp/auxv，SP 16 字节对齐），
   argv 条数、环境变量条数、初始栈词数都有硬上限，栈顶留白 64KB——
   这三个数原先没有上界，客户机参数可以直接踩宿主栈（F37）。
   auxv 的 AT_PAGESZ 报宿主真实页大小 16384——报 4096 会让 glibc 的段对齐
   与宿主页粒度错位，把同页内相邻映射的数据抹掉（F35）。

## 目录

- MLC.command 一键安装（双击运行）
- src/mlc-core.c 翻译器核心（单文件，零第三方依赖）
- src/stub.s 系统调用存根汇编（保存客户机全部寄存器）
- src/tp-stub.s 客户机 TPIDR_EL0 写入校验存根
- src/mlc 命令行入口（PATH 查找 + 退出码透传）
- src/install.sh 手动安装（等价于 MLC.command）
- scripts/unpack-rootfs.sh 按需解出 103MB 的 sysroot
- tests/ 测试载荷生成器（mkelf.py 迷你链接器 + test.s + regs.s）、验证脚本（23 项）、稳定性观测
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
