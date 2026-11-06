# MLC — mac-linux-compat

macOS 上的 Linux 兼容层。不做虚拟机，用用户态翻译在 macOS ARM64 上直接运行 Linux ARM64 程序。
思路与 CrossOver/Wine 同构：客户机指令原生执行，Linux 系统调用在本进程内翻译成 macOS 调用。

## 现状（2026-11-06，v1.6.1）

能跑：Ubuntu Base 24.04.5 ARM64 的真实动态 PIE 可执行文件。
实测通过：`ls`、`ls -la /`、`cat`、`echo`、`sh -c`（内建命令与外部命令）、
命令替换 `$(...)` 与反引号、管道、shell 重定向（含重定向之后 fd 正确还原）、
完整的 ld.so → libc → libselinux → libpcre2 动态链接链、locale/gconv 初始化、
`statx/newfstatat/lstat` 权限与符号链接、`getdents64` 目录列举、
客户机退出码原样透传、fork/exec/wait4（外部命令经 sh 执行）。
已验证约 60 个系统调用；tests/verify.sh 三十八项全过（十一项静态载荷 + 四项动态链接冒烟 + 十项审计回归 + 一项寄存器保存回归 + 一项线程指针回归 + 三项 fork/exec + 四项 newfstatat + 两项安装路径 + 四项 glibc fork 与 fcntl）。
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

v1.6.1 修掉四个"门禁全绿但产品不可用"的缺陷（F60-F63）。它们不是审计也不是
压测找到的，是用户按本文档装好之后真的去用，几分钟内撞出来的。共同点：38 项
验证全绿，因为每一项都只在项目目录里直接调 src/mlc——装到别处之后的路、以及
"真的写个脚本"会用到的路，一条都没被测过。教训一句话：在项目目录里跑绿的门禁，
证明不了装到别处之后还能用。四点：

1. 拷到 `~/.local/bin/mlc` 之后找不到项目根（F60）。`src/mlc` 原先用「脚本
   上一级」当项目根，拷走之后上一级变成 `~/.local`，CORE 算成
   `~/.local/src/mlc-core`，一运行就退 127。改成三级定位：环境变量
   `MLC_HOME` > 安装时写死的 `INSTALL_HOME` > 脚本相对位置；两个安装脚本
   拷过去之后用 sed 把真实项目根写进 `INSTALL_HOME` 并 grep 校验写成功了。
   顺带修掉报错句里的全角逗号——`$CORE，` 会被 bash 3.2 解析成变量 `CORE，`，
   `set -u` 直接让脚本死掉，用户看到的是一句乱码而不是"没找到核心"。
   这个坑在本项目已第三次出现。
2. clone 漏了 glibc 真正的 fork()（F61）。客户机创建进程有两条不同的 clone
   调用：posix_spawn 用 `CLONE_VM|CLONE_VFORK|SIGCHLD`（实测 a0=0x4111），
   而真正的 fork() 用 `SIGCHLD|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID`
   （0x1200011）。实现只认前一条，于是 dash 的命令替换 `$(...)`、反引号、
   管道、以及任何带重定向的外部命令全都报 `Cannot fork`、退出码 2。
   v1.6 的 fork/exec 三项回归没抓到，是因为它测的
   `sh -c '/usr/bin/echo ...'` 走 posix_spawn；而 dash 的最后一个命令优化
   又让 `sh -c 'ls /'` 不 fork 也能跑，于是连"外部命令能跑"都没露馅。
3. fcntl(F_DUPFD) 把宿主 fd 号递回客户机（F62）。宿主返回值是宿主 fd 号，
   客户机认的是自己的 fd 表，直接递回去就等于给了一个从未登记过的 fd。dash
   保存 stdout 正是 `fcntl(1, F_DUPFD, 10)`、还原是 `dup3(10, 1, 0)`，第二次
   调用时 EBADF，stdout 就永久停在重定向目标上——
   `sh -c 'echo a; echo b > /dev/null; echo c'` 只打印 a。
   改成结果走 guest_fd_alloc 登记成客户机 fd。
4. fcntl 命令号两侧不是同一套（F63）。Linux `F_GETLK=5/F_SETLK=6/F_SETLKW=7/
   F_DUPFD_CLOEXEC=1030`，宿主是 `7/8/9/67`。原来不翻译，而且校验指针时用的
   常量写的是 F_GETFD/F_SETFD——野指针校验一次都没生效过。加了一张翻译表。

回归：verify.sh 32 → 38 项，新增第 [9] 段两项（拷贝后能跑、MLC_HOME 优先）与
第 [10] 段四项（命令替换、管道、重定向后 stdout 被还原、重定向本身仍生效）。
两组都做了去牙实测。稳定性：stability.sh 60 轮 0 崩溃 0 挂起；fork 加重定向
混合 120 轮 0 失败。

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

回归：tests/verify.sh 新增第 [8] 段三项（外部命令真的执行了、argv 真的传对了、
退出码经 wait4 真的透传了）与第 [8b] 段四项（test -f 认得常规文件、test -d
认得目录、不存在的路径仍为假、PATH 搜索能定位并执行外部命令）。
tests/stability.sh 的观测面扩到 8 个程序，并改用引擎自带的 MLC_WATCHDOG 把
「永久挂起」单列：macOS 没有 timeout 命令，一次挂起就能把观测脚本卡死，
v1.6 量化 K2 时正是这么卡住的。

顺带修掉一个一直潜伏的严重缺陷 F59：newfstatat 的 a2/a3 写反了。
Linux 的 ABI 是 `newfstatat(dfd, filename, statbuf, flag)`，即 a2 是 statbuf、
a3 是 flag；实现里却把 a2 当 flag、a3 当 statbuf。后果是 statbuf 从来没被
填过，而返回值一直是 0（成功）——客户机看到的是「stat 成功但整个结构体全零」。
连锁后果比想象的严重：dash 的 PATH 搜索靠 S_ISREG 决定要不要用这个文件，
st_mode 为 0 时所有找到的可执行文件都被判成「非常规文件」而跳过，
于是 sh -c 里任何靠 PATH 找的外部命令都跑不了（报 Permission denied、退出码 127）。
它一直没被发现是因为 glibc 2.39 上的 coreutils 优先走 statx（nr=291），
而 statx 那条路是对的；只有直接走 newfstatat 的消费者才会踩到。

## 一键安装

双击 `MLC.command`（Finder 里右键→打开，或直接双击）。
脚本依次做：检查 arm64 + clang → 解包 rootfs → 构建 src/mlc-core → 跑 38 项验证 →
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
mlc sh -c 'ls /'             # 跑 sh 里的外部命令（fork/exec）
mlc sh -c 'echo $(uname -s)' # 命令替换（glibc fork）
mlc sh -c 'ls / | wc -l'     # 管道
mlc sh -c 'ls / > /dev/null; echo after'   # 重定向之后 fd 会还原
bash tests/verify.sh         # 三十八项验证
bash tests/stability.sh 200  # 偶发失败率观测（只报告，不作门禁）
```

诊断信息全部走 stderr，所以 `mlc ls > out.txt` 拿到的是干净输出；
想看加载与系统调用过程就加 `MLC_DEBUG=1`。

`mlc` 与直接调 `src/mlc-core` 的关系：`mlc` 负责在 rootfs 里按客户机 PATH 找程序、
透传参数、原样返回退出码；翻译器本体仍是 `src/mlc-core`。

如果 `mlc` 被拷到了别处（安装脚本正是这么做的），它靠写在脚本里的
`INSTALL_HOME` 找回项目根；也可以用环境变量覆盖：
`MLC_HOME=/路径/mac-linux-compat mlc ls`。

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
6. fork/exec 三条路（v1.6）。clone 认三种进程级用法：posix_spawn 的
   CLONE_VM|CLONE_VFORK|SIGCHLD（0x4111）、裸 fork 的 SIGCHLD（0x0011）、
   以及 glibc 真正的 fork() 的 SIGCHLD|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID
   （0x1200011）——最后这条 v1.6 漏了，命令替换与管道因此全废，v1.6.1 补上。
   三种都落到宿主 fork()，并分别实现 CLONE_CHILD_SETTID（父进程把子 TID 写进
   parent_tidptr）、CLONE_PARENT_SETTID（子进程写 child_tidptr）、
   CLONE_CHILD_CLEARTID（退出时清零）。其余带 CLONE_THREAD/CLONE_SETTLS 等位的
   一律 ENOSYS——多线程归 M3，不给语义不符的成功。
   execve 记下路径与 argv/envp（字符串抄进宿主缓冲区，旧客户机栈会被新镜像
   盖掉）后 longjmp 回 main 的加载循环，重新加载镜像、重建客户机栈、再跳一次
   入口。wait4 走 waitpid 并把状态编码翻成 Linux 形态。
   execve 保留 fd 表，区域表/guard 表/镜像表/brk 区/蹦桌池全部重建。

## 目录

- MLC.command 一键安装（双击运行）
- src/mlc-core.c 翻译器核心（单文件，零第三方依赖）
- src/stub.s 系统调用存根汇编（保存客户机全部寄存器）
- src/tp-stub.s 客户机 TPIDR_EL0 写入校验存根
- src/mlc 命令行入口（PATH 查找 + 退出码透传）
- src/install.sh 手动安装（等价于 MLC.command）
- scripts/unpack-rootfs.sh 按需解出 103MB 的 sysroot
- tests/ 测试载荷生成器（mkelf.py 迷你链接器 + test.s + regs.s + tp.s）、验证脚本（38 项）、稳定性观测
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
