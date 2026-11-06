# MLC — mac-linux-compat

macOS 上的 Linux 兼容层。不做虚拟机，用用户态翻译在 macOS ARM64 上直接运行 Linux ARM64 程序。
思路与 CrossOver/Wine 同构：客户机指令原生执行，Linux 系统调用在本进程内翻译成 macOS 调用。

## 现状（2026-11-06，v1.5）

能跑：Ubuntu Base 24.04.5 ARM64 的真实动态 PIE 可执行文件。
实测通过：`ls`、`ls -la /`、`cat`、`echo`、`sh -c`（内建命令）、
完整的 ld.so → libc → libselinux → libpcre2 动态链接链、locale/gconv 初始化、
`statx/newfstatat/lstat` 权限与符号链接、`getdents64` 目录列举、
客户机退出码原样透传。
已验证约 60 个系统调用；tests/verify.sh 二十五项全过（十一项静态载荷 + 四项动态链接冒烟 + 七项审计回归 + 一项寄存器保存回归 + 一项线程指针回归）。
不能跑：fork/exec（外部命令）、多线程、真实信号投递、网络、非 PIE 镜像
（见 docs/10-整改清单.md 的 M2/M3 段）。
已知缺陷：动态链接路径的偶发崩溃（缺陷 K1）已在 v1.5 消除——实测 2000 轮
`sh -c true`、1500 轮 `ls /nonexistent`、1500 轮 `cat /etc/hostname` 全部 0 次崩溃，
同口径下 v1.4 基线是 43/2000。量化用 `bash tests/stability.sh`。

v1.5 接着 v1.4 的全量审计往下挖，把缺陷 K1 从「2% 到 7% 偶发崩溃」打到归零：

1. 先定位到翻野的区间。崩溃现场打印「蹦桌末次还原」与「系统调用 nr」后确认：
   蹦桌在最后一次系统调用出口写回的一直是有效 TCB（0x10xxxxf80 一档），
   而崩溃时 TPIDR_EL0 是 0x1006 一类的小值。也就是说翻野发生在「最后一次
   系统调用之后、崩溃之前」那段只有客户机代码在跑的区间里。
2. 排除了客户机自己写野值的可能。全 rootfs 816 个 ELF 静态扫过 msr TPIDR_EL0
   （编码 0xD51BD040|N），只有 ld.so 两处、ldconfig.real 一处，libc 与所有
   程序、库一处都没有，且 ld.so 那两处都已修补、运行期只进入其中一处。
   又给所有可捕获信号装了监听，崩溃运行里一个信号都没到达。
3. 剩下的可能只有 macOS libSystem。实测它在宿主调用里确实会把 0x0、0x1006、
   0x1007 一类小值写进 TPIDR_EL0（约二十分之一的调用会这样），但它凭什么在
   没有宿主调用的间隙里能跑，没有可观测的触发点。
4. 既然拦不住写，就拦住读。客户机唯一拿到线程指针的入口是 mrs xN, TPIDR_EL0
   （编码 0xD53BD040|N）。v1.5 新增 19 词的 mrs 拦截存根，读出来跟已知有效
   TCB 不一致就换成有效 TCB。于是无论 TPIDR_EL0 被谁写野，客户机都看不到，
   glibc 的 TP 相对访问再也不会落到近零地址。
5. 顺带解决蹦桌池的一对矛盾：池子既要被引擎反复写，又要被客户机当指令跳，
   而 macOS 禁止匿名映射同时可写可执行（实测 mprotect 到 RWX 直接 EACCES）。
   v1.4 及以前按 page_up 把已用范围整段设为只读，F55 之后拦截数上去就爆了。
   现在改成「写前恢复可写、写后设为只读可执行」的切换，且收尾无条件执行——
   少了这个无条件，mprotect 补扫那条路会把池子留在可写不可执行状态，
   ls -la / 崩 199/200（故障页 prot=3，故障指令正是 mrs 存根首条）。

回归：tests/tp.elf 端到端钉住这条链（msr 记下有效 TCB、野值被顶替、mrs 读回
有效 TCB、七种目标寄存器一致、邻存寄存器不被踩、跨系统调用后仍成立）。
去牙实测：关掉 msr 拦截退出码变 4，把 cbz 分支改回旧下标退出码变 11，
把 movk 编码少写一位退出码变 99。

性能：mrs 拦截单次开销约 0.87 纳秒（约 3 个周期，实测两亿条 mrs 多花 0.17 秒）；
端到端在噪声范围内（`sh -c true` 400 次 0.738 秒对 0.798 秒，`ls /` 400 次
0.579 秒对 0.536 秒）。

## 一键安装

双击 `MLC.command`（Finder 里右键→打开，或直接双击）。
脚本依次做：检查 arm64 + clang → 解包 rootfs → 构建 src/mlc-core → 跑 25 项验证 →
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
bash tests/verify.sh         # 二十五项验证
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

## 目录

- MLC.command 一键安装（双击运行）
- src/mlc-core.c 翻译器核心（单文件，零第三方依赖）
- src/stub.s 系统调用存根汇编（保存客户机全部寄存器）
- src/tp-stub.s 客户机 TPIDR_EL0 写入校验存根
- src/mlc 命令行入口（PATH 查找 + 退出码透传）
- src/install.sh 手动安装（等价于 MLC.command）
- scripts/unpack-rootfs.sh 按需解出 103MB 的 sysroot
- tests/ 测试载荷生成器（mkelf.py 迷你链接器 + test.s + regs.s + tp.s）、验证脚本（25 项）、稳定性观测
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
