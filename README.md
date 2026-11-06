# MLC — mac-linux-compat

macOS 上的 Linux 兼容层。不做虚拟机，用用户态翻译在 macOS ARM64 上直接运行 Linux ARM64 程序。
思路与 CrossOver/Wine 同构：客户机指令原生执行，Linux 系统调用在本进程内翻译成 macOS 调用。

## 现状（2026-11-06，v1.6）

能跑：Ubuntu Base 24.04.5 ARM64 的真实动态 PIE 可执行文件。
实测通过：`ls`、`ls -la /`、`cat`、`echo`、`sh -c`（内建命令与外部命令）、
完整的 ld.so → libc → libselinux → libpcre2 动态链接链、locale/gconv 初始化、
`statx/newfstatat/lstat` 权限与符号链接、`getdents64` 目录列举、
客户机退出码原样透传、fork/exec/wait4（外部命令经 sh 执行）。
已验证约 60 个系统调用；tests/verify.sh 二十八项全过（十一项静态载荷 + 四项动态链接冒烟 + 十项审计回归 + 一项寄存器保存回归 + 一项线程指针回归 + 三项 fork/exec）。
不能跑：多线程、真实信号投递、网络、非 PIE 镜像
（见 docs/10-整改清单.md 的 M2/M3 段）。
已知缺陷：
· K1（动态链接偶发崩溃）已在 v1.5 消除——实测 8000 轮 0 次崩溃，同口径 v1.4
  基线是 43/2000。根因仍未定位，属「知其然不知其所以然」。
· K2（v1.6 量化发现，未解决）：部分客户机偶发符号查找失败与永久挂起。
  id 约 1.3%、hostname 约 0.7% 的概率以退出码 127 结束
  （`symbol lookup error: ... undefined symbol: calloc, version GLIBC_2.17`），
  另有约 0.5% 的概率永久挂起。uname/date/env/pwd/arch/nproc/true/echo/ls/cat/sh
  各 150 次全干净。与 v1.6 的 fork/exec 无关——v1.5 同口径比例一致，且直接调
  mlc-core 就复现。量化用 `bash tests/stability.sh`。

v1.6 在 v1.5 的基础上打通 fork/exec（B7），外部命令从此能经 sh 跑起来。

v1.5 那轮做的是把缺陷 K1 打到归零，做法与证据见 docs/08 的 F55/F56 与
docs/10 的 K1 节，这里不重复。v1.6 的五点：

1. clone（nr=220）落到宿主 fork()。客户机只有两种用法：glibc posix_spawn 的
   CLONE_VM|CLONE_VFORK|SIGCHLD（实测 a0=0x4111）与裸 fork 的 SIGCHLD。
   其余带 CLONE_THREAD/CLONE_SETTLS 等位的一律返回 ENOSYS——多线程归 M3，
   不给语义不符的成功。CLONE_VM 的「共享地址空间」在 posix_spawn 的用法里
   无所谓：子进程紧接着就 execve 把整个镜像换掉，父进程用 fork 的写时复制
   本来就更安全。CLONE_VFORK 的「挂起父进程」同理可以不做。
2. execve（nr=221）在本进程内换镜像，靠 longjmp 回 main 的加载循环：重新加载
   新镜像、重建客户机栈、再跳一次入口。之所以必须 longjmp，是因为 execve 是从
   蹦桌 → C 处理器 → impl 的深处被调用的，那里没有路能「不返回客户机旧代码」
   地切到新入口。
3. wait4（nr=260）落到 waitpid，并把状态编码从 BSD 形态翻成 Linux 形态
   （退出码在 bits 8-15、信号在 bits 0-6）。不翻的话父进程读到的等待结果全错。
4. execve 的 argv/envp 必须抄进宿主自己的缓冲区，不能只存客户机指针——
   longjmp 之后 load_image2 会 MAP_FIXED 落到客户机窗口低端，把存着 argv
   字符串的旧客户机栈整块盖掉。实测踩过：只存指针时 exec 出来的 echo
   收不到任何参数（write 只写出一个换行）。
5. fd 表在 execve 之后保持不动（Linux 的 execve 默认保留已打开的 fd，fork
   出来的子进程本就继承了副本），区域表、guard 表、镜像表、brk 区、蹦桌池
   全部重建；环境变量也换成客户机自己给的那份，不再透传宿主 environ。

回归：tests/verify.sh 新增第 [8] 段三项——外部命令真的执行了、argv 真的传对了、
退出码经 wait4 真的透传了。tests/stability.sh 的观测面扩到 8 个程序，并改用
引擎自带的 MLC_WATCHDOG 把「永久挂起」单列：macOS 没有 timeout 命令，
一次挂起就能把观测脚本卡死，v1.6 量化 K2 时正是这么卡住的。

## 一键安装

双击 `MLC.command`（Finder 里右键→打开，或直接双击）。
脚本依次做：检查 arm64 + clang → 解包 rootfs → 构建 src/mlc-core → 跑 28 项验证 →
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
mlc sh -c 'ls /'            # 跑 sh 里的外部命令（fork/exec）
bash tests/verify.sh         # 二十八项验证
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
4. 同一遍扫描还拦两类线程指针指令。写侧是 msr TPIDR_EL0, xN（编码
   0xD51BD040|N）：客户机二进制里会写线程指针的只有 ld.so 两处（全 rootfs
   816 个 ELF 扫过，libc 与所有程序、库一处都没有），走 mlc_tp_write_probe
   校验，写入值是 mmap 出来的高地址就当有效 TCB 记下。读侧是 mrs xN,
   TPIDR_EL0（编码 0xD53BD040|N，注意 0xD51BD040 是写、0xD53BD040 是读，
   这两者最早认错过，害了一圈弯路）：一律走 19 词存根核对，读出来跟已知有效
   TCB 不一致就换成有效 TCB。为什么非拦读不可——v1.5 实测确认蹦桌在每次系统
   调用出口都把有效 TCB 写回了 TPIDR_EL0，崩溃运行里也没有任何信号到达，
   翻野只发生在「最后一次系统调用之后」那段纯客户机代码里，而那段代码里没有
   任何 msr 会执行；写野值的是 macOS libSystem，但触发点不可观测。既然拦不住
   写，就让客户机读不到野值。系统调用入口再核对一次保存块里的值。
   两条路都是为了「客户机线程指针不许变成野值」——TPIDR 一野，glibc 所有
   TP 相对访问都落到近零地址上。
5. 客户机栈按 AArch64 PCS 搭建（argc/argv/envp/auxv，SP 16 字节对齐），
   argv 条数、环境变量条数、初始栈词数都有硬上限，栈顶留白 64KB——
   这三个数原先没有上界，客户机参数可以直接踩宿主栈（F37）。
   auxv 的 AT_PAGESZ 报宿主真实页大小 16384——报 4096 会让 glibc 的段对齐
   与宿主页粒度错位，把同页内相邻映射的数据抹掉（F35）。
6. fork/exec 三条路（v1.6）。clone 只认 posix_spawn 的 CLONE_VM|CLONE_VFORK|
   SIGCHLD 与裸 fork 的 SIGCHLD，落到宿主 fork()，其余带 CLONE_THREAD 等位的
   一律 ENOSYS。execve 记下路径与 argv/envp（字符串抄进宿主缓冲区，旧客户机栈
   会被新镜像盖掉）后 longjmp 回 main 的加载循环，重新加载镜像、重建客户机栈、
   再跳一次入口。wait4 走 waitpid 并把状态编码翻成 Linux 形态。
   execve 保留 fd 表，区域表/guard 表/镜像表/brk 区/蹦桌池全部重建。

## 目录

- MLC.command 一键安装（双击运行）
- src/mlc-core.c 翻译器核心（单文件，零第三方依赖）
- src/stub.s 系统调用存根汇编（保存客户机全部寄存器）
- src/tp-stub.s 客户机 TPIDR_EL0 写入校验存根
- src/mlc 命令行入口（PATH 查找 + 退出码透传）
- src/install.sh 手动安装（等价于 MLC.command）
- scripts/unpack-rootfs.sh 按需解出 103MB 的 sysroot
- tests/ 测试载荷生成器（mkelf.py 迷你链接器 + test.s + regs.s + tp.s）、验证脚本（28 项）、稳定性观测
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
