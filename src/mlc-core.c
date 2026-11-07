// ============================================================
// mlc-core.c — MLC 兼容层核心（v1.1）
// macOS ARM64 上直接运行 Linux ARM64 静态 ELF，无虚拟机、无内核模块。
//
// 原理（CrossOver/Wine 同构的用户态翻译思路）：
//   1. 加载静态 ELF 的 PT_LOAD 段到固有虚拟地址
//   2. 把可执行段里的 Linux 系统调用指令 svc #0 (0xD4000001)
//      替换为 BL 跳转到本程序的系统调用存根
//   3. 存根保存寄存器，调用 C 处理器，把 Linux 系统调用翻译成
//      macOS 宿主调用，返回值写回 x0，恢复寄存器，返回客户机
//   4. 搭建客户机栈（argc/argv/envp/auxv），跳转到 ELF 入口
//
// v1.1 新增：客户机内存区域表。所有客户机指针先过校验（guest_ptr_ok /
// guest_str_ok），野指针返回 -EFAULT 不再崩宿主；mprotect / mmap-FIXED /
// munmap 只准作用于客户机已注册区间，客户机无法改写蹦床与引擎映射。
// munmap 按客户机区间精确卸载（宿主页内残余 PROT_NONE）；brk 失败回滚；
// svc 与蹦床距离超 BL ±128MB 在加载期报错。
//
// 已知边界：仅静态链接 ELF；信号为桩；网络/ioctl 多数返回 ENOSYS；
// futex 恒返回 0（多线程前必须实现）；客户机看到 4K 页而宿主是 16K 页。
// ============================================================
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <signal.h>

// ---------- Linux arm64 系统调用号（asm-generic/unistd.h） ----------
#define SYS_io_setup        0
#define SYS_setxattr        5
#define SYS_ioctl          29
#define SYS_openat         56
#define SYS_close          57
#define SYS_lseek          62
#define SYS_read           63
#define SYS_write          64
#define SYS_readv          65
#define SYS_writev         66
#define SYS_pread64        67
#define SYS_pwrite64       68
#define SYS_readlinkat     78
#define SYS_fstat          80
#define SYS_exit           93
#define SYS_exit           93
#define SYS_exit_group     94
#define SYS_set_tid_address 96
#define SYS_clone         220   // 进程创建：glibc 的 posix_spawn 与 fork 都走这条
#define SYS_execve        221   // 替换当前镜像
#define SYS_wait4         260   // 等待子进程

// ---------- Linux clone 标志（linux/sched.h） ----------
#define CLONE_VM             0x00000100UL
#define CLONE_FS             0x00000200UL
#define CLONE_FILES          0x00000400UL
#define CLONE_SIGHAND        0x00000800UL
#define CLONE_VFORK          0x00004000UL
#define CLONE_PARENT_SETTID  0x00100000UL
#define CLONE_CHILD_CLEARTID 0x00200000UL
#define CLONE_CHILD_SETTID   0x01000000UL
#define CLONE_THREAD         0x00010000UL
#define CLONE_SETTLS         0x00080000UL
#define SYS_futex          98
#define SYS_set_robust_list 99
#define SYS_nanosleep     101
#define SYS_clock_gettime 113
#define SYS_clock_nanosleep 115
#define SYS_kill          129
#define SYS_tgkill        131
#define SYS_getpid        172
#define SYS_getppid       173
#define SYS_getuid        174
#define SYS_geteuid       175
#define SYS_getgid        176
#define SYS_getegid       177
#define SYS_gettid        178
#define SYS_sysinfo       179
#define SYS_uname         160
#define SYS_getcwd         17
#define SYS_chdir          49
#define SYS_fchdir         50
#define SYS_faccessat      48
#define SYS_newfstatat     79
#define SYS_getdents64     61
#define SYS_brk           214
#define SYS_munmap        215
#define SYS_mremap        216
#define SYS_mmap          222
#define SYS_mprotect      226
#define SYS_madvise       233
#define SYS_pipe2          59
#define SYS_dup            23
#define SYS_dup3           24
#define SYS_fcntl          25
#define SYS_prlimit64     261
#define SYS_getrandom     278
#define SYS_rseq          293
#define SYS_statx         291
#define SYS_sched_getaffinity 123
#define SYS_sched_yield   124
#define SYS_membarrier    283
#define SYS_capget         90
// 注意：aarch64 没有 getpagesz 这个调用（78 号是 readlinkat）。
// 曾经这里写过一条 #define SYS_getpagesz 78 的占位常量，从未被 switch 使用，
// 却与 SYS_readlinkat 同号——任何人顺手把它加进 switch 就会把 readlinkat
// 分支整个吃掉，而 ld.so 读 /proc/self/exe 会静默变成 ENOENT。审计 F41 删除。
#define SYS_rt_sigaction  134
#define SYS_rt_sigprocmask 135
#define SYS_getpgid       155
#define SYS_gettimeofday  169
#define SYS_sigaltstack   43   // glibc 早期初始化会调它；曾返回 ENOSYS，见 F46

// macOS SDK 无 sys/sysmacros.h：statx 需要的主次设备号宏
#define major(x) ((int)(((unsigned)(x) >> 24) & 0xff))
#define minor(x) ((int)((x) & 0xffffff))

// ---------- Linux errno（asm-generic/errno.h） ----------
#define L_EPERM   1
#define L_ENOENT  2
#define L_ESRCH   3
#define L_EIO     5
#define L_EBADF   9
#define L_EAGAIN 11
#define L_ENOMEM 12
#define L_EACCES 13
#define L_EFAULT 14
#define L_EINVAL 22
#define L_ENOTTY 25
#define L_ESPIPE 29
#define L_ERANGE 34
#define L_ENOSYS 38
#define L_ENOTSOCK 88
#define L_EOPNOTSUPP 95
#define L_ENOTSUP  95
#define L_EMFILE_  24
#define L_ENOTDIR 20
#define L_ENAMETOOLONG_ 36

// ---------- Linux 打开标志（asm-generic/fcntl.h） ----------
#define L_O_WRONLY   01
#define L_O_RDWR     02
#define L_O_CREAT     0100
#define L_O_EXCL      0200
#define L_O_TRUNC    01000
#define L_O_APPEND   02000
#define L_O_NONBLOCK 04000
#define L_O_DIRECTORY 0200000
#define L_O_CLOEXEC  02000000

#define GUEST_FD_MAX 256
static int g_fd_map[GUEST_FD_MAX];   // 客户机 fd -> 宿主 fd，-1 为空
// F65：/dev/urandom 与 /dev/zero 没有宿主 fd，用这两个标记记住哪个客户机 fd
// 是哪个设备，read 时按标记造数据，close 时只摘标记不动宿主 fd。
static uint8_t g_dev_random[GUEST_FD_MAX];
static uint8_t g_dev_zero[GUEST_FD_MAX];
static uint64_t g_brk_start, g_brk_cur;
// 诊断计数器：看门狗用它们区分"客户机真的没再调用"与"在疯狂调用但 trace 不可信"
static volatile uint64_t g_sc_total;
static volatile uint64_t g_sc_by_nr[512];
// brk 预留区（v1.2）：必须独立于任何镜像映射。
// 曾经的算法是"主镜像末段之后"，但镜像映射实际跨度是 span+0x14000（含间隔与蹦床），
// 客户机 brk 增长用 MAP_FIXED 会把蹦床覆盖掉，之后所有系统调用都跳进被污染的蹦床。
#define BRK_RESERVE (32ULL * 1024 * 1024)
static uint64_t g_brk_region_end;

static int guest_fd_alloc(int host_fd) {
    for (int i = 0; i < GUEST_FD_MAX; i++)
        if (g_fd_map[i] == -1) { g_fd_map[i] = host_fd; return i; }
    return -1;
}
static int guest_fd_host(int gfd) {
    if (gfd < 0 || gfd >= GUEST_FD_MAX) return -1;
    return g_fd_map[gfd];
}

// F65：判断客户机 fd 是否是 /dev/urandom 一类的虚拟设备
static int guest_fd_is_dev(int gfd) {
    return gfd >= 0 && gfd < GUEST_FD_MAX && (g_dev_random[gfd] || g_dev_zero[gfd]);
}

// F65：打开虚拟设备。用宿主 /dev/null 做后备 fd，这样 dup/fcntl/fstat/lseek
// 全都自然可用（dd 打开 /dev/urandom 后会 dup3 再 fstat，没有真 fd 就走不下去）；
// 真正的数据由 SYS_read 按标记现造。两个标记都置上时以 random 优先。
static int64_t dev_open(int is_random) {
    int hfd = open("/dev/null", O_RDONLY);
    if (hfd < 0) return -errno;
    int gfd = guest_fd_alloc(hfd);
    if (gfd < 0) { close(hfd); return -L_EMFILE_; }
    if (is_random) g_dev_random[gfd] = 1; else g_dev_zero[gfd] = 1;
    return gfd;
}

// F65：dup 系列要把设备标记一起带过去，否则复制出来的 fd 只剩 /dev/null 的语义
static void dev_fd_copy(int from, int to) {
    if (from < 0 || from >= GUEST_FD_MAX || to < 0 || to >= GUEST_FD_MAX) return;
    g_dev_random[to] = g_dev_random[from];
    g_dev_zero[to]   = g_dev_zero[from];
}
static void guest_fd_free(int gfd) {
    if (gfd >= 0 && gfd < GUEST_FD_MAX) g_fd_map[gfd] = -1;
}

// ---------- 客户机内存区域表（v1.1 M1/M3）----------
// 客户机指针与宿主指针同值（无地址重定位），但只有本进程为客 户机注册过的
// 区间才允许触碰：野指针一律返回 -EFAULT，绝不让宿主进程崩溃（M1）；
// mmap/munmap/mprotect 也以此为边界，客户机无法改到引擎自身代码（安全加固）。
#define G_REGION_MAX 512
typedef struct { uint64_t start, end; } g_region_t;   // 半开区间 [start, end)
static g_region_t g_region[G_REGION_MAX];
static int g_region_n = 0;
static int g_overlap_seen = 0;         // 已报告过区域重叠（只报一次，K2 排查）
static pthread_mutex_t g_region_lock = PTHREAD_MUTEX_INITIALIZER;   // 为 M3 多线程预留

static void region_check(const char *who) {
    for (int i = 0; i < g_region_n; i++) {
        if ((g_region[i].start & 0x3FFFULL) || (g_region[i].end & 0x3FFFULL)) {
            fprintf(stderr, "[mlc][区域告警] %s 之后区域表出现未对齐条目 [0x%llx,0x%llx)\n",
                    who, (unsigned long long)g_region[i].start,
                    (unsigned long long)g_region[i].end);
            return;
        }
    }
    // 重叠检测：两个已登记区间重叠，说明后一次 MAP_FIXED 把前一次映射的内容
    // 静默卸掉了（macOS 的 MAP_FIXED 不报错，直接替换）。这类损坏没有症状提示，
    // 只会让客户机读到别人的数据——K2 的「失败符号每次都不一样」正符合这个特征。
    for (int i = 0; i < g_region_n && !g_overlap_seen; i++) {
        for (int j = i + 1; j < g_region_n; j++) {
            if (g_region[i].start < g_region[j].end && g_region[j].start < g_region[i].end) {
                fprintf(stderr, "[mlc][重叠告警] %s 之后区域 %d [0x%llx,0x%llx) 与区域 %d [0x%llx,0x%llx) 重叠\n",
                        who, i, (unsigned long long)g_region[i].start,
                        (unsigned long long)g_region[i].end,
                        j, (unsigned long long)g_region[j].start,
                        (unsigned long long)g_region[j].end);
                g_overlap_seen = 1;
                break;
            }
        }
    }
}

static void region_add(uint64_t s, uint64_t e) {
    if (s >= e) return;
    // K2 排查：区域表区间必须是宿主页对齐的。未对齐的区间会让 guest_region_overlap
    // 与 guest_ptr_ok 给出错误答案（登记范围比实际映射偏了一页内的偏移），
    // 后续 mmap 的落位与野指针校验都会跟着错。这里抓现场。
    if ((s & 0x3FFFULL) || (e & 0x3FFFULL)) {
        fprintf(stderr, "[mlc][区域告警] region_add 传入未对齐区间 [0x%llx,0x%llx)\n",
                (unsigned long long)s, (unsigned long long)e);
    }
    pthread_mutex_lock(&g_region_lock);
    for (int i = 0; i < g_region_n; i++) {          // 相邻即合并，减少碎片
        if (s <= g_region[i].end && g_region[i].start <= e) {
            if (s < g_region[i].start) g_region[i].start = s;
            if (e > g_region[i].end)   g_region[i].end = e;
            pthread_mutex_unlock(&g_region_lock);
            return;
        }
    }
    if (g_region_n < G_REGION_MAX) {
        g_region[g_region_n].start = s;
        g_region[g_region_n].end = e;
        g_region_n++;
    } else {
        fprintf(stderr, "[mlc] 警告: 客户机区域表已满（%d），后续映射不纳入校验\n", G_REGION_MAX);
    }
    region_check("region_add");
    pthread_mutex_unlock(&g_region_lock);
}

static void region_del(uint64_t s, uint64_t e) {
    if (s >= e) return;
    pthread_mutex_lock(&g_region_lock);
    for (int i = 0; i < g_region_n; ) {
        uint64_t rs = g_region[i].start, re = g_region[i].end;
        if (e <= rs || re <= s) { i++; continue; }                 // 无交集
        if (s <= rs && re <= e) {                                  // 整体删除
            g_region[i] = g_region[--g_region_n];
            continue;
        }
        if (rs < s && e < re) {                                    // 删中间：分裂
            if (g_region_n < G_REGION_MAX) {
                g_region[i].end = s;
                g_region[g_region_n].start = e;
                g_region[g_region_n].end = re;
                g_region_n++;
            } else {
                g_region[i].end = s;      // 表满，保守截断（宁可拒绝也不放行）
            }
            i++;
            continue;
        }
        if (s <= rs) g_region[i].start = e;                        // 删头部
        else         g_region[i].end = s;                          // 删尾部
        i++;
    }
    region_check("region_del");
    pthread_mutex_unlock(&g_region_lock);
}

// [s,e) 是否被已注册区域完全覆盖（按区间的并集判定，不要求落在同一条目里）。
// 原实现要求整个 [s,e) 落在单一条目内，而 region_add 只与第一个相交条目合并、
// 相邻映射经常是两条独立条目，于是跨边界的合法指针被判成非法，引擎返回 -EFAULT。
// K2（2026-11-06 定位）：ld.so 的符号查找路径上有大量跨映射边界的缓冲，
// 被误判后系统调用逐个失败，症状就是「undefined symbol」而失败符号每次都不一样。
static int region_covers(uint64_t s, uint64_t e) {
    if (s >= e) return 0;
    int r = 0;
    pthread_mutex_lock(&g_region_lock);
    uint64_t cur = s;
    for (;;) {
        uint64_t best = cur;
        for (int i = 0; i < g_region_n; i++) {
            // 能接上当前点，且比已知最远端更远——取最远的那个，跳过中间条目
            if (g_region[i].start <= cur && g_region[i].end > best) best = g_region[i].end;
        }
        if (best == cur) break;          // 没有区域能继续延伸，中间有洞
        cur = best;
        if (cur >= e) break;
    }
    r = (cur >= e);
    pthread_mutex_unlock(&g_region_lock);
    return r;
}

// [s,e) 是否与任何已注册客户机区域相交（只要有交集就算）
// 审计 F39：无 MAP_FIXED 的 mmap 在 Linux 里只是"建议地址"，内核不得破坏
// 既有映射；而引擎为了满足 glibc 首段 hint 语义，是拿 MAP_FIXED 去落位的。
// 若不先查重叠，一次与活映射部分重合的 hint 就会把那段活数据静默卸掉——
// 与 F32（窗口水位算错导致 data 段被抹）同一类损坏，只是触发点不同。
static int guest_region_overlap(uint64_t s, uint64_t e) {
    if (s >= e) return 0;
    int r = 0;
    pthread_mutex_lock(&g_region_lock);
    for (int i = 0; i < g_region_n; i++)
        if (s < g_region[i].end && g_region[i].start < e) { r = 1; break; }
    pthread_mutex_unlock(&g_region_lock);
    return r;
}

// 客户机缓冲区校验：p 为 NULL 且 len 为 0 时放行（合法的空调用）
static int guest_ptr_ok(uint64_t p, uint64_t len) {
    if (len == 0) return p == 0 ? 1 : region_covers(p, p + 1);
    if (p == 0 || p + len < p) return 0;          // 空指针或区间回绕
    return region_covers(p, p + len);
}

// 客户机字符串校验：必须在已注册区域内以 NUL 结尾（maxlen 内）。
// F66（2026-11-06）：原实现只在「p 所在的那一个区域」里找 NUL，字符串一旦跨到
// 相邻区域就被判成非法指针，系统调用返回 -EFAULT。这与 region_covers 原来的
// 单条目限制是同一类缺陷——region_add 只与第一个相交条目合并，相邻映射经常是
// 两条独立条目。改成按区间并集逐段找：当前段没找到 NUL 就跳到下一个能接上的区域。
static int guest_str_ok(uint64_t p, uint64_t maxlen) {
    if (!p) return 0;
    pthread_mutex_lock(&g_region_lock);
    int ok = 0;
    uint64_t cur = p;
    uint64_t limit = p + maxlen;
    for (;;) {
        // 找能覆盖 cur 且伸得最远的区域
        uint64_t best = cur;
        for (int i = 0; i < g_region_n; i++)
            if (g_region[i].start <= cur && g_region[i].end > best) best = g_region[i].end;
        if (best == cur) break;                       // 没有区域能接上，中间是洞
        uint64_t seg_end = (best < limit) ? best : limit;
        const char *s = (const char *)(uintptr_t)cur;
        for (uint64_t k = 0; k < seg_end - cur; k++)
            if (s[k] == 0) { ok = 1; break; }
        if (ok) break;
        if (seg_end >= limit) break;                  // 已经找满 maxlen 还没 NUL
        cur = seg_end;
    }
    pthread_mutex_unlock(&g_region_lock);
    return ok;
}

// 单次 I/O 的长度上限：防止客户机给个天文数字让宿主操作异常
#define GUEST_IO_MAX (1ULL << 30)

// ---------- getdents64 的目录句柄表（v1.1 M2：close 联动 + 加锁）----------
// 宿主目录流由 fdopendir 维护偏移，必须挂在 guest fd 上，
// close 时联动 closedir，否则 DIR* 与内部 dup 出的 fd 一起泄漏。
static DIR *g_dir[GUEST_FD_MAX];
static pthread_mutex_t g_dir_lock = PTHREAD_MUTEX_INITIALIZER;

// ---------- 系统调用存根字节（clang 汇编产出，见 stub.s） ----------
// 立即数位于偏移 0x54 起的四条 movz/movk（x9），运行时修补为处理器地址
// v4：进 C 处理器前后多了一组 mrs/str/msr + ldr/msr，负责保管客户机 TPIDR_EL0
// （macOS libSystem 会把它写成 0x1006 一类的小值，见 stub.s 注释，v1.2 F34）
// v5：保存块从 x0-x9/x16-x23/x28/x30 扩到 x0-x30 全部。
// Linux aarch64 系统调用 ABI 规定除 x0 外所有寄存器原样保留，而 blr 进 C 处理器
// 会按 AAPCS 踩掉 x10-x15；v4 不还原它们，客户机放在 x10-x15 的活值被抹掉，
// glibc 的 malloc 在 mmap/brk 两侧正是用这些寄存器存临时量，被抹后堆状态出错，
// 有 2% 到 5% 的概率返回野指针，一路传到 ld.so 的 msr TPIDR_EL0, x20，
// 客户机线程指针变成 0x1006，随后 __libc_init_first 的 mrs x0, TPIDR_EL0
// 拿到它，ldur q0, [x4, #-0x48] 以 TPIDR-0x648 为地址 SIGSEGV（缺陷 K1 根因）。
static const uint32_t ML_STUB[] = {
    0xd10443ffu, 0xa90007e0u, 0xa9010fe2u, 0xa90217e4u,
    0xa9031fe6u, 0xa90427e8u, 0xa9052feau, 0xa90637ecu,
    0xa9073feeu, 0xa90847f0u, 0xa9094ff2u, 0xa90a57f4u,
    0xa90b5ff6u, 0xa90c67f8u, 0xa90d6ffau, 0xa90e77fcu,
    0xf9007bfeu, 0xd53bd049u, 0xf9007fe9u, 0xd51bd05fu,
    0x910003e0u, 0xd2800009u, 0xf2a00009u, 0xf2c00009u,
    0xf2e00009u, 0xd63f0120u, 0xf9407fe9u, 0xd51bd049u,
    0xf90083e0u, 0xa94007e0u, 0xa9410fe2u, 0xa94217e4u,
    0xa9431fe6u, 0xa94427e8u, 0xa9452feau, 0xa94637ecu,
    0xa9473feeu, 0xa94847f0u, 0xa9494ff2u, 0xa94a57f4u,
    0xa94b5ff6u, 0xa94c67f8u, 0xa94d6ffau, 0xa94e77fcu,
    0xf9407bfeu, 0xf94083e0u, 0x910443ffu, 0x14000000u,
};
#define ML_STUB_WORDS (sizeof(ML_STUB) / sizeof(ML_STUB[0]))   // 48 词 = 192 字节
#define ML_STUB_SLOT  256u          // 每个 svc 修补点一份独立蹦桌副本（须 >= ML_STUB_WORDS*4）

// 客户机 mrs xN, TPIDR_EL0 的读拦截存根（v1.5 F55，缺陷 K1 的收口）。
// 编码由 clang 汇编后逐条比对确认（0xd51bd040|N 是 msr 写、0xd53bd040|N 才是 mrs 读，
// 这两者最早认错过，害了一圈弯路）。
//
// 为什么拦读而不只是拦写：v1.4 已证实蹦桌在每次系统调用出口都把有效 TCB 写回了
// TPIDR_EL0（崩溃现场「蹦桌末次还原」打印的一直是 0x10xxxxf80 一档的有效值），
// 全 rootfs 816 个 ELF 里 msr TPIDR_EL0 只有 ld.so 两处且都已修补，崩溃运行里
// 也没有任何信号到达——也就是说翻野发生在「最后一次系统调用之后、崩溃之前」那段
// 只有客户机代码在跑的区间里，而客户机代码里没有任何 msr 会执行。写野值的只能是
// macOS libSystem（实测它在宿主调用里确实会把 0x0/0x1006/0x1007 一类小值写进
// TPIDR_EL0），但它凭什么在系统调用之间的间隙里能跑，目前没有可观测触发点。
//
// 既然拦不住写，就拦住读：客户机唯一拿到线程指针的入口就是 mrs xN, TPIDR_EL0。
// 这里在出口统一核对——读出来跟已知有效 TCB 不一致，就换成有效 TCB。于是无论
// TPIDR_EL0 被谁写野，客户机都看不到，glibc 的 TP 相对访问再也不会落到近零地址。
//
// 约束：单线程模型下 TPIDR_EL0 必须恒等于 g_guest_tp_good（蹦桌进宿主调用前清零、
// 出口还原，客户机代码不会在清零期间运行）。多线程（M3）落地后这条要重做。
//
// 2026-11-07 修正（缺陷 K2 的根因）：原存根把选中的值放在 x10 里，出口
//     orr xN, xzr, x10
// 只还原了 x0、x1、x9，**没有还原 x10**。而客户机的 mrs xN, TPIDR_EL0 只写 xN，
// x10 在调用者手里可能是活的。实测全 rootfs 五个二进制里 mrs 共 2323 处，
// 目标寄存器是 x10 的只有 4 处（libc 1530 处里 3 处、perl 524 处里 1 处，
// libm 240 处里 0 处、ld.so 29 处里 0 处），也就是 2319 处都会把调用者手里的
// x10 抹成 TCB 地址。TCB 是已映射的合法地址，抹了不会 SIGSEGV，只会让拿着
// x10 当指针用的客户机代码读到 TCB 内容当符号表用——症状正是 K2：
// 「symbol lookup error: undefined symbol: <任意符号>」，失败符号每轮都不一样，
// 而内存镜像逐字节比对又查不出损坏（表确实是好的，坏的是指向表的那个寄存器）。
// 现在改成用 x9 作载体，出口先还原 x10 再 orr，最后才还原 x9（目标寄存器恰为
// x9 时那条 ldr 由补丁代码改成 nop，否则会把刚写进 x9 的结果又盖回去）。
// 词数仍是 19，蹦桌槽大小不变。
// 编码由 clang 汇编后逐条比对确认（0xd51bd040|N 是 msr 写、0xd53bd040|N 才是 mrs 读，
// 这两者最早认错过，害了一圈弯路）。
static const uint32_t ML_MRS_STUB[] = {
    0xd100c3ffu,       // 0  sub  sp, sp, #0x30
    0xa90007e0u,       // 1  stp  x0, x1, [sp]
    0xa9012be9u,       // 2  stp  x9, x10, [sp, #0x10]
    0xd53bd049u,       // 3  mrs  x9, tpidr_el0        ← 现场值
    0xd280000au,       // 4  movz x10, #0              ┐ 立即数运行时修补
    0xf2a0000au,       // 5  movk x10, #0, lsl #16     │ 指向 g_guest_tp_good
    0xf2c0000au,       // 6  movk x10, #0, lsl #32     │
    0xf2e0000au,       // 7  movk x10, #0, lsl #48     ┘
    0xf940014au,       // 8  ldr  x10, [x10]           ← x10 = 有效 TCB（0 表示还没建立）
    0xb400008au,       // 9  cbz  x10, restore         ← 未建立：跳到「取现场值」，不能抹掉它
    0xeb0a013fu,       // 10 cmp  x9, x10
    0x54000040u,       // 11 b.eq restore              ← 与有效 TCB 相同，直接用
    0xaa0a03e9u,       // 12 mov  x9, x10              ← 野值顶替；三条路都在 x9 里留下选中值
                        //    restore:（下标 13，由 cbz 与 b.eq 落入）
    0xa94007e0u,       // 13 ldp  x0, x1, [sp]         ← 先还原可能被覆盖的 x0/x1
    0xf9400feau,       // 14 ldr  x10, [sp, #0x18]     ← 还原客户机原 x10（K2 修正的关键）
    0xaa0903e0u,       // 15 orr  xN, xzr, x9          ← 下标 15 运行时修补成目标寄存器
    0xf9400be9u,       // 16 ldr  x9, [sp, #0x10]      ← 还原原 x9；目标寄存器是 x9 时改 nop
    0x9100c3ffu,       // 17 add  sp, sp, #0x30
    0x14000000u,       // 18 b    返回客户机            ← 末条 B 立即数运行时修补
};
#define ML_MRS_STUB_WORDS (sizeof(ML_MRS_STUB) / sizeof(ML_MRS_STUB[0]))   // 19 词 = 76 字节
#define ML_MRS_STUB_IDX_ADDR 4    // movz/movk 四条：g_guest_tp_good 的地址
#define ML_MRS_STUB_IDX_DST  15   // orr xN, xzr, x9：N 由被拦指令给出
#define ML_MRS_STUB_IDX_X9REST 16 // ldr x9, [sp,#0x10]：目标寄存器是 x9 时须改成 nop
#define AARCH64_NOP 0xd503201fu


// 保存块布局（与 stub.s v5 对应）：下标 i 就是 x_i，即
//   0..30 = x0..x30（x8 是 Linux 系统调用号），31 = 客户机 TPIDR_EL0，
//   32 = 返回值槽。x0 最后才被返回值覆盖，避免冲掉刚还原的其它寄存器。
// v4 及以前的布局是压缩的（x16 在下标 10、x28 在下标 18），已随 v5 废弃。
#define REG_X0   0
#define REG_X8   8
#define REG_TPIDR 31
#define REG_RET  32

// ---------- 客户机 TPIDR_EL0 写入校验存根（clang 汇编产出，见 tp-stub.s） ----------
// 立即数位于偏移 0x4c 的 mov w1（被写寄存器下标）与 0x50 起的四条 movz/movk（x9，
// 指向 mlc_tp_write_probe），运行时修补。背景与判据见 tp-stub.s 顶部注释。
static const uint32_t ML_TP_STUB[] = {
    0xd10443ffu, 0xa90007e0u, 0xa9010fe2u, 0xa90217e4u,
    0xa9031fe6u, 0xa90427e8u, 0xa9052feau, 0xa90637ecu,
    0xa9073feeu, 0xa90847f0u, 0xa9094ff2u, 0xa90a57f4u,
    0xa90b5ff6u, 0xa90c67f8u, 0xa90d6ffau, 0xa90e77fcu,
    0xf9007bfeu, 0xd51bd05fu, 0x910003e0u, 0x52800001u,
    0xd2800009u, 0xf2a00009u, 0xf2c00009u, 0xf2e00009u,
    0xd63f0120u, 0xd51bd040u, 0xa94007e0u, 0xa9410fe2u,
    0xa94217e4u, 0xa9431fe6u, 0xa94427e8u, 0xa9452feau,
    0xa94637ecu, 0xa9473feeu, 0xa94847f0u, 0xa9494ff2u,
    0xa94a57f4u, 0xa94b5ff6u, 0xa94c67f8u, 0xa94d6ffau,
    0xa94e77fcu, 0xf9407bfeu, 0x910443ffu, 0x14000000u,
};
#define ML_TP_STUB_WORDS (sizeof(ML_TP_STUB) / sizeof(ML_TP_STUB[0]))   // 44 词 = 176 字节
#define ML_TP_STUB_IDX_N   19    // mov w1, #N 的位置
#define ML_TP_STUB_IDX_FN  20    // movz/movk x9 四条的位置

// 客户机 TCB 一定落在 mmap 出来的高地址（本进程客户机窗口在 0x100000000 以上），
// 而 macOS libSystem 在 TPIDR_EL0 里留的值都远小于此（实测 0x0/0x1/0x3 与
// 0x1006 一类）。低于这个阈值的写入值一律视为野值。
#define TP_PLAUSIBLE_MIN 0x10000000ULL

static uint64_t g_guest_tp_good = 0;   // 最近一次见到的有效客户机 TCB
static int g_tp_fixups = 0;            // 野值被顶替的次数（诊断用）
static uint64_t g_tp_last_write = 0;    // TP 存根最后一次真正写进 TPIDR_EL0 的值
static int g_tp_writes = 0;             // TP 存根被进入的次数
static uint64_t g_tp_last_restored = 0; // 蹦桌最后一次 msr 回客户机的值（K1 排查）
static uint64_t g_sc_last_nr = 0;       // 最后一次系统调用号（K1 排查）
static int g_patch_skipped = 0;        // 补丁因 B 射程超限被跳过的站点数（K2 排查）

static int64_t mlc_syscall_handler(uint64_t *regs);
static int64_t mlc_tp_write_probe(uint64_t *regs, int n);

// ---------- 小工具 ----------
static uint64_t page_down(uint64_t a) { return a & ~0x3FFFULL; }   // 宿主 16K 页
static uint64_t page_up(uint64_t a)   { return (a + 0x3FFFULL) & ~0x3FFFULL; }

static void die(const char *msg) { fprintf(stderr, "[mlc][致命] %s (errno=%d %s)\n", msg, errno, strerror(errno)); exit(1); }

// ---------- ELF 结构（arm64） ----------
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;

#define PT_LOAD 1
#define PF_X 1
#define PF_W 2
#define PF_R 4

// ---------- Linux struct stat（arm64 布局） ----------
typedef struct {
    uint64_t st_dev;      // 0
    uint64_t st_ino;      // 8
    uint32_t st_mode;     // 16
    uint32_t st_nlink;    // 20
    uint32_t st_uid;      // 24
    uint32_t st_gid;      // 28
    uint64_t st_rdev;     // 32
    uint64_t __pad1;      // 40
    uint64_t st_size;     // 48
    uint32_t st_blksize;  // 56
    uint32_t __pad2;      // 60
    uint64_t st_blocks;   // 64
    uint64_t l_atime;      // 72
    uint64_t st_atime_nsec; // 80
    uint64_t l_mtime;      // 88
    uint64_t st_mtime_nsec; // 96
    uint64_t l_ctime;      // 104
    uint64_t st_ctime_nsec; // 112
    uint32_t __unused4;   // 120
    uint32_t __unused5;   // 124
} l_stat_t;               // 共 128 字节

static void fill_lstat(l_stat_t *ls, const struct stat *hs) {
    memset(ls, 0, sizeof(*ls));
    ls->st_dev     = hs->st_dev;
    ls->st_ino     = hs->st_ino;
    ls->st_mode    = hs->st_mode;
    ls->st_nlink   = hs->st_nlink;
    ls->st_uid     = hs->st_uid;
    ls->st_gid     = hs->st_gid;
    ls->st_rdev    = hs->st_rdev;
    ls->st_size    = hs->st_size;
    ls->st_blksize = hs->st_blksize ? hs->st_blksize : 4096;
    ls->st_blocks  = hs->st_blocks;
    ls->l_atime    = hs->st_atime;   ls->st_atime_nsec = hs->st_atimespec.tv_nsec;
    ls->l_mtime    = hs->st_mtime;   ls->st_mtime_nsec = hs->st_mtimespec.tv_nsec;
    ls->l_ctime    = hs->st_ctime;   ls->st_ctime_nsec = hs->st_ctimespec.tv_nsec;
}

// ---------- Linux new_utsname ----------
typedef struct {
    char sysname[65], nodename[65], release[65], version[65], machine[65], domainname[65];
} l_utsname_t;

// ---------- rootfs 路径重写（v1.2 M2：让 glibc ld.so 自己干活）----------
// 动态链接走「加载 interp + 路径重写 + 交给 ld.so」路线：由 ld.so 完成依赖库
// 加载、符号解析与重定位，兼容性远好于自研 linker。前提是客户机看到的绝对
// 路径必须落到 rootfs 内，否则 ld.so 打不开 libc.so.6。
static char g_rootfs[512];
static char g_execfn[512];      // 客户机看到的自身路径（readlinkat /proc/self/exe 用）
// set_tid_address 的落点：客户机给的「线程退出时写线程号」的地址，原样记住备查
static int *g_tid_addr;

// 客户机登记的备用信号栈（sigaltstack，43 号）。本引擎不投递信号，登记只为让
// glibc 的早期初始化拿到成功返回；布局按 Linux aarch64 自己解，见 case SYS_sigaltstack。
// 标志位取值与 macOS 不同（Linux SS_DISABLE=2，macOS 是 4），不能直接调宿主。
typedef struct { uint64_t ss_sp; int32_t ss_flags; uint32_t _pad; uint64_t ss_size; } g_stack_t;
static g_stack_t g_altstack;
static int g_altstack_set = 0;

static void rootfs_init(const char *argv0) {
    const char *env = getenv("MLC_ROOT");
    if (env && *env) { snprintf(g_rootfs, sizeof(g_rootfs), "%s", env); return; }
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", argv0 ? argv0 : ".");
    char *slash = strrchr(buf, '/');
    if (slash) *slash = 0;                                  // 去掉可执行名，剩 src/
    snprintf(g_rootfs, sizeof(g_rootfs), "%s/../rootfs/sysroot", buf);
}

// 客户机绝对路径 -> 宿主路径。已在 rootfs 内的不重复加前缀；相对路径原样返回。
static int guest_to_host_path(const char *gp, char *out, size_t outsz) {
    if (!gp) { if (outsz) out[0] = 0; return 0; }
    if (gp[0] != '/') { snprintf(out, outsz, "%s", gp); return 0; }
    size_t rl = strlen(g_rootfs);
    if (rl && strncmp(gp, g_rootfs, rl) == 0) { snprintf(out, outsz, "%s", gp); return 0; }
    if (rl + strlen(gp) + 1 > outsz) return -1;
    snprintf(out, outsz, "%s%s", g_rootfs, gp);
    return 0;
}

// ---------- 镜像加载（v1.2：主程序与 interp 通用，每个镜像自带蹦床）----------
#define MAX_IMAGES 24
#define PT_INTERP 3
#define PT_DYNAMIC 2
#define PT_PHDR 6
typedef struct {
    uint8_t *img;        // 文件镜像缓冲（ELF 头与 phdr 所在）
    uint8_t *mem;        // 运行时映射
    uint64_t span;       // 段区跨度
    uint64_t base;       // 运行基址（ET_DYN：mem - page_down(lo)）
    uint64_t entry;      // 运行入口
    uint64_t phdr_addr;  // 内存中 phdr 地址
    uint64_t tramp;      // 本镜像的系统调用蹦桌区
    uint64_t total;      // 本镜像占用的宿主映射总长（含蹦桌区）
    int phnum;
    char name[256];
} image_t;
static image_t g_img[MAX_IMAGES];
static int g_nimg = 0;

// ---------- 系统调用实现 ----------
static int64_t sys_ioctl(int gfd, uint64_t cmd, uint64_t arg) {
    // 常见探测：TCGETS(0x5401)/TIOCGWINSZ(0x5413) —— 一律报告非终端
    if (cmd == 0x5401 || cmd == 0x5413) return -L_ENOTTY;
    return -L_ENOTTY;
}

static int64_t sys_openat(int gdirfd, const char *path, uint64_t lflags, uint64_t mode) {
    // v1：仅支持 AT_FDCWD(-100) 与绝对/相对路径
    if (!guest_str_ok((uint64_t)path, 4096)) return -L_EFAULT;
    if (gdirfd != -100 && path[0] != '/') return -L_EBADF;   // AT_FDCWD=-100
    // F65（2026-11-06 实测）：rootfs 里没有 /dev/urandom、/dev/random、/dev/zero，
    // 客户机打开一律 ENOENT。glibc 的 malloc 播种、getrandom 回退、以及任何要
    // 熵源的脚本都会走到这里。宿主的 arc4random 是真随机，直接用它，不落盘。
    // /dev/null 走下面的普通路径（rootfs 里已有一个空文件，读写都成功）。
    if (strcmp(path, "/dev/urandom") == 0 || strcmp(path, "/dev/random") == 0) {
        if (lflags & (L_O_WRONLY | L_O_RDWR)) return -L_EACCES;   // 随机源只读
        return dev_open(1);
    }
    if (strcmp(path, "/dev/zero") == 0) {
        return dev_open(0);
    }
    char hpath[1024];
    if (guest_to_host_path(path, hpath, sizeof(hpath)) < 0) return -L_ENAMETOOLONG_;
    int flags = 0;
    if (lflags & 3) flags |= (lflags & 3);                    // O_RDONLY/O_WRONLY/O_RDWR 取值一致
    if (lflags & L_O_CREAT)     flags |= O_CREAT;
    if (lflags & L_O_EXCL)      flags |= O_EXCL;
    if (lflags & L_O_TRUNC)     flags |= O_TRUNC;
    if (lflags & L_O_APPEND)    flags |= O_APPEND;
    if (lflags & L_O_NONBLOCK)  flags |= O_NONBLOCK;
    if (lflags & L_O_DIRECTORY) flags |= O_DIRECTORY;
    if (lflags & L_O_CLOEXEC)   flags |= O_CLOEXEC;
    int hfd = open(hpath, flags, (mode_t)mode);
    if (hfd < 0) {
        if (getenv("MLC_DEBUG"))
            fprintf(stderr, "[mlc][openat] 失败 客户机路径=%s 宿主路径=%s flags=0x%llx errno=%d(%s)\n",
                    path, hpath, (unsigned long long)lflags, errno, strerror(errno));
        return -errno;
    }
    int gfd = guest_fd_alloc(hfd);
    if (gfd < 0) { close(hfd); return -L_EMFILE_; }
    return gfd;
}

static int64_t sys_getdents64(int gfd, void *dirp, uint64_t count) {
    int hfd = guest_fd_host(gfd);
    if (hfd < 0) return -L_EBADF;
    if (!guest_ptr_ok((uint64_t)(uintptr_t)dirp, count)) return -L_EFAULT;
    if (count < 20) return -L_EINVAL;
    // 用 DIR* 读宿主目录；句柄表加锁保护建立/销毁，readdir/telldir 由 libc 内部锁保护
    DIR *d;
    pthread_mutex_lock(&g_dir_lock);
    d = g_dir[gfd];
    if (!d) {
        int dupfd = dup(hfd);
        if (dupfd < 0) { pthread_mutex_unlock(&g_dir_lock); return -errno; }
        d = fdopendir(dupfd);
        if (!d) { close(dupfd); pthread_mutex_unlock(&g_dir_lock); return -L_ENOTDIR; }
        g_dir[gfd] = d;
    }
    pthread_mutex_unlock(&g_dir_lock);
    struct dirent *de;
    uint64_t off = 0;
    while (off + 19 + 1 < count && (de = readdir(d)) != NULL) {
        size_t namelen = strlen(de->d_name) + 1;
        uint64_t reclen = (19 + namelen + 7) & ~7ULL;   // d_ino,d_off,d_reclen,d_type + name
        if (off + reclen > count) break;
        uint8_t *rec = (uint8_t *)dirp + off;
        memset(rec, 0, reclen);
        *(uint64_t *)(rec + 0)  = de->d_ino;            // d_ino
        *(uint64_t *)(rec + 8)  = telldir(d);           // d_off
        *(uint16_t *)(rec + 16) = (uint16_t)reclen;     // d_reclen
        rec[18] = de->d_type;                           // d_type
        memcpy(rec + 19, de->d_name, namelen);            // d_name
        off += reclen;
    }
    if (getenv("MLC_DEBUG")) {
        uint8_t *r0 = (uint8_t *)dirp;
        fprintf(stderr, "[mlc][dbg] getdents64 返回 %llu 字节，首项: ino=%llu reclen=%u type=%u name=%s\n",
                (unsigned long long)off, *(uint64_t *)r0, *(uint16_t *)(r0 + 16), r0[18], (char *)(r0 + 19));
    }
    return (int64_t)off;
}

// 引擎保护区：镜像映射、镜像蹦桌、以及给动态库现场建的蹦桌。
// 客户机（含 ld.so）的 MAP_FIXED 一律不得覆盖这些，否则蹦桌被数据替换后
// 所有系统调用都会跳飞（v1.2 修：曾因漏登记动态蹦桌导致 SIGSEGV）。
#define G_GUARD_MAX 256
static struct { uint64_t s, e; } g_guard[G_GUARD_MAX];
static int g_guard_n = 0;
static void guard_add(uint64_t s, uint64_t e) {
    if (s >= e || g_guard_n >= G_GUARD_MAX) return;
    g_guard[g_guard_n].s = s; g_guard[g_guard_n].e = e; g_guard_n++;
}

// 引擎保护区：各镜像的宿主映射（含蹦桌区）。MAP_FIXED 只禁止覆盖这里，
// 其余地址允许客户机映射——ld.so 会把新库 MAP_FIXED 到它自己选的新地址，
// 那些地址尚未注册，用 region_covers 一律拒绝会让动态链接直接失败（v1.2 修）。
static int engine_region_hit(uint64_t s, uint64_t e) {
    for (int i = 0; i < g_nimg; i++) {
        uint64_t ms = (uint64_t)g_img[i].mem + g_img[i].span;   // 只护间隔与蹦桌，客户机段不护
        uint64_t me = ms + (g_img[i].total - g_img[i].span);
        if (s < me && ms < e) {
            fprintf(stderr, "[mlc][诊断] 客户机目标 [0x%llx,0x%llx) 与镜像 %s 的引擎保护区 [0x%llx,0x%llx) 重叠\n",
                    (unsigned long long)s, (unsigned long long)e, g_img[i].name,
                    (unsigned long long)ms, (unsigned long long)me);
            return 1;
        }
    }
    for (int i = 0; i < g_guard_n; i++)
        if (s < g_guard[i].e && g_guard[i].s < e) {
            fprintf(stderr, "[mlc][诊断] 客户机目标 [0x%llx,0x%llx) 与蹦桌保护区 [0x%llx,0x%llx) 重叠\n",
                    (unsigned long long)s, (unsigned long long)e,
                    (unsigned long long)g_guard[i].s, (unsigned long long)g_guard[i].e);
            return 1;
        }
    return 0;
}


// ---------- 客户机地址窗口与蹦桌池（v1.2 B1）----------
// 问题：蹦桌若紧邻客户机映射，ld.so 会复用它认为空闲的地址，把新库 MAP_FIXED
// 到蹦桌上（或 munmap 卸掉蹦桌），之后系统调用跳进被替换/已卸载的页。
// 解法：客户机 body 全部从一段预留窗口顺序分配（栈式，从高往低，匹配 ld.so 的
// 「预留→卸尾部→重映射」LIFO 模式），蹦桌放在窗口外侧的独立池里。
// 窗口 + 池一次映射、物理相邻，任一库到池的距离 < 窗口跨度 + 池大小 < 128MB，
// 既保证 B 跳转可及，又让客户机根本碰不到蹦桌。
#define COMPAT_WIN_SIZE (96ULL << 20)
#define COMPAT_TP_SIZE  (16ULL << 20)
// 主程序之后留给 ld.so 向下分配的间隙。ld.so 从自己的映射末端往下给新库找地址，
// 间隔不够就会穿过主程序映射（v1.2 修）。按 Ubuntu base 的库总量取 48MB。
#define COMPAT_LD_GAP   (48ULL << 20)
static uint8_t *g_win_base, *g_win_low, *g_win_high, *g_win_end;   // 客户机 body 窗口
static uint8_t *g_tp_base, *g_tp_next, *g_tp_end;      // 蹦桌池

static void compat_window_init(void) {
    uint8_t *p = mmap(NULL, COMPAT_TP_SIZE + COMPAT_WIN_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) die("无法分配客户机地址窗口");
    g_tp_base = p; g_tp_next = p; g_tp_end = p + COMPAT_TP_SIZE;
    g_win_base = p + COMPAT_TP_SIZE;
    g_win_end = p + COMPAT_TP_SIZE + COMPAT_WIN_SIZE;
    g_win_low = g_win_base;                 // 低端 bump-up：主程序
    g_win_high = g_win_end;                 // 高端 bump-down：interp 与库
    guard_add((uint64_t)p, (uint64_t)p + COMPAT_TP_SIZE);   // 蹦桌池整体是保护区
    fprintf(stderr, "[mlc] 客户机窗口 0x%llx-0x%llx（%lluMB，主程序从低端、interp 与库从高端），蹦桌池 0x%llx-0x%llx（%lluMB）\n",
            (unsigned long long)g_win_base, (unsigned long long)g_win_end,
            (unsigned long long)(COMPAT_WIN_SIZE >> 20),
            (unsigned long long)g_tp_base, (unsigned long long)g_tp_end,
            (unsigned long long)(COMPAT_TP_SIZE >> 20));
}

// 窗口顺序分配（len 已按宿主页对齐）；失败返回 0。
// 低端 bump-up 给主程序；高端 bump-down 给 interp。
// 关键：ld.so 从自己的映射末端往下分配新库，若主程序也在高端就会被穿过；
// 主程序放低端、interp 放高端，ld.so 往下分配时落在窗口空白区（v1.2 修）。
static uint64_t win_alloc(uint64_t len) {
    if (len == 0 || (uint64_t)(g_win_low + len) > (uint64_t)g_win_high) return 0;
    // K2 排查：游标必须是宿主页对齐的。未对齐的游标会让 mmap 的 MAP_FIXED 落点
    // 比引擎簿记的地址低最多一页，而返回给客户机的却是 page_down 之后的地址，
    // 客户机据此算出的 l_addr 与后续 MAP_FIXED 全部偏掉，两个库可能叠在一起。
    if ((uint64_t)g_win_low & 0x3FFFULL)
        fprintf(stderr, "[mlc][窗口告警] win_alloc 游标未对齐 0x%llx（len=0x%llx）\n",
                (unsigned long long)(uintptr_t)g_win_low, (unsigned long long)len);
    uint64_t r = (uint64_t)g_win_low;
    g_win_low += len;
    return r;
}
static uint64_t win_alloc_high(uint64_t len) {
    if (len == 0 || (uint64_t)(g_win_high - len) < (uint64_t)g_win_low) return 0;
    g_win_high -= len;
    return (uint64_t)g_win_high;
}
// 卸的正是窗口当前顶部时把指针还回去（栈式复用，避免 ld.so 反复预留卸空把窗口耗尽）。
// 但只能退到"确实已经空了"的边界。宿主页 16K 而客户机页 4K，一次 munmap 的宿主取整
// 范围常比请求范围大，若直接退到 page_down(s)，仍被相邻映射占着的页会被算成空闲，
// 下一次 win_alloc 把新库 MAP_FIXED 上去，就把那块活数据静默替换掉了（v1.2 F32 修：
// ld.so 因此读到被抹掉的链接结构，算出野指针写进 libc 只读文本页，SIGBUS 收尾崩）。
static void win_free_top(uint64_t s, uint64_t e) {
    if (!(e > s) || g_win_low < g_win_base) return;
    uint64_t low = (uint64_t)g_win_low;
    if (!(s <= low && low <= e)) return;
    uint64_t cand = page_down(s);
    for (int changed = 1; changed; ) {          // 跳过所有仍然活着的区间
        changed = 0;
        for (int i = 0; i < g_region_n; i++) {
            uint64_t rs = g_region[i].start, re = g_region[i].end;
            if (cand < re && rs < low) { cand = re; changed = 1; }
        }
    }
    if (cand < low) {
        if (cand & 0x3FFFULL)
            fprintf(stderr, "[mlc][窗口告警] win_free_top 要把游标退到未对齐地址 0x%llx\n",
                    (unsigned long long)cand);
        g_win_low = (uint8_t *)cand;
    }
}
// 蹦桌池分配（len 已对齐）；失败返回 0
static uint64_t tp_alloc(uint64_t len) {
    // 不按页取整：蹦桌副本按 128 字节紧邻排布。曾按页取整，副本之间留下
    // 大量未初始化空洞，B 一旦落进空洞就是执行 0x00000000（SIGILL）。
    if ((uint64_t)(g_tp_next + len) > (uint64_t)g_tp_end) return 0;
    uint64_t r = (uint64_t)g_tp_next;
    g_tp_next += len;
    return r;
}

// 蹦桌池的「可写 / 可执行」切换。
//
// 为什么必须切：macOS 禁止匿名映射同时可写可执行（实测 mprotect 到 RWX 直接
// EACCES），而蹦桌既要被引擎反复写（patch_svc_in_range 每次处理一个新映射的库
// 都要往里写几百上千份副本），又要被客户机当指令跳。
//
// 曾经的两种错法：
//   按 page_up(g_tp_next) 设只读——本次调用是安全了，可下一次调用分配的地址
//   仍落在已设为只读的页里，写入即 SIGSEGV（libc 有 517 处 svc、上千处 mrs，
//   一次动态链接就要跨几百页，迟早踩到）。
//   按 page_down(g_tp_next) 设只读——当前未写满的那一页保持可写，于是落在
//   这一页里的蹦桌不可执行，客户机一跳过去就是 SIGBUS（v1.5 实测：
//   ls -la / 崩 199/200，故障指令正是 mrs 存根首条 sub sp, sp, #0x20）。
//
// 现在的口径：写之前把已设为只读的整段恢复可写，写完之后再把已用整段设为只读
// 可执行。安全性在于 patch_svc_in_range 只从系统调用处理器内部被调用，切换发生
// 时客户机代码根本没有在跑（客户机只在两次系统调用之间运行），不存在「客户机
// 正踩着某条蹦桌时被改保护」的窗口。
static uint64_t g_tp_rx_end = 0;    // 已设为只读可执行的末尾（页对齐），0 表示可写

static void tp_prepare_write(void) {
    if (g_tp_rx_end > (uint64_t)g_tp_base)
        mprotect((void *)g_tp_base, (size_t)(g_tp_rx_end - (uint64_t)g_tp_base),
                 PROT_READ | PROT_WRITE);
    g_tp_rx_end = 0;
}

static void tp_finish_write(void) {
    uint64_t used = page_up((uint64_t)g_tp_next);
    if (used > (uint64_t)g_tp_base) {
        mprotect((void *)g_tp_base, (size_t)(used - (uint64_t)g_tp_base),
                 PROT_READ | PROT_EXEC);
        g_tp_rx_end = used;
    }
}

// ---------- fork/exec（B7，v1.6）----------
// 客户机的进程模型只有两条路能落到宿主上：
//   1. clone（nr=220）——glibc 的 posix_spawn 用 CLONE_VM|CLONE_VFORK|SIGCHLD
//      （实测 a0=0x4111），裸 fork 用 SIGCHLD。macOS 没有 clone，用 fork() 落地。
//      CLONE_VM 的「共享地址空间」在 posix_spawn 的用法里无所谓：子进程紧接着就
//      execve 把整个镜像换掉，父进程那边用 fork 的写时复制本来就更安全
//      （不存在「父子互相踩同一块」的窗口）。CLONE_VFORK 的「挂起父进程」同理
//      可以不做：fork 之后父子地址空间已经独立，父进程继续跑不会破坏子进程。
//   2. execve（nr=221）——在本进程内换镜像。做法是 longjmp 回 main 的加载循环，
//      重新加载新镜像、重建客户机栈再跳一次。之所以必须 longjmp：execve 是从
//      系统调用处理器深处（蹦桌 → C 处理器 → impl）被调用的，那里没有路能
//      「不返回客户机旧代码」地切换到新入口。
//
// fd 表在 execve 之后保持不动的依据：Linux 的 execve 默认保留已打开的 fd
// （除非带 O_CLOEXEC），而 fork 出来的子进程本就继承了父进程的 fd 表副本。
// 蹦桌池、区域表、guard 表、镜像表、brk 区则全部重建——它们是旧镜像的私有簿记。
#define GUEST_EXEC_ARGC_MAX 128
#define GUEST_EXEC_ENVC_MAX 128
#define GUEST_EXEC_STR_MAX 4096

// execve 的 argv/envp 必须抄到宿主自己的缓冲区里，不能只存客户机指针。
// 原因：longjmp 回 main 之后要重新加载新镜像，而 load_image2 是 MAP_FIXED 落到
// 客户机窗口低端的——旧镜像的客户机栈（argv 字符串就在那儿）会被整块盖掉。
// 实测踩过：只存指针时，建新栈读出来的 argv 全是空串，exec 出来的 echo
// 收不到任何参数（write 只写出一个换行）。
static char g_exec_argv_buf[GUEST_EXEC_ARGC_MAX][GUEST_EXEC_STR_MAX];
static char g_exec_envp_buf[GUEST_EXEC_ENVC_MAX][GUEST_EXEC_STR_MAX];
static jmp_buf g_exec_jmp;                 // longjmp 回 main 的加载循环
static int g_exec_pending = 0;             // 有 execve 请求待处理
static char g_exec_path[1024];             // 新镜像的客户机路径
static char *g_exec_argv[GUEST_EXEC_ARGC_MAX];
static int g_exec_argc;
static char *g_exec_envp[GUEST_EXEC_ENVC_MAX];
static int g_exec_envc;

// CLONE_CHILD_CLEARTID 的簿记：子进程退出时必须把 child_tidptr 清成 0，
// 否则 glibc 挂在那个地址上的 futex 永远等不到唤醒。execve 之后地址失效，
// 因此 guest_state_reset 要一起清掉。
static uint64_t g_exit_cleartid = 0;
static int32_t  g_exit_cleartid_val = 0;

// execve 之前的旧镜像簿记清理。只清必须清的，其余留给新加载覆盖。
static void guest_state_reset(void) {
    // 目录句柄不跨 exec：先 closedir 再清表，否则 DIR* 与其内部 dup 的 fd 一起泄漏
    for (int i = 0; i < GUEST_FD_MAX; i++) {
        if (g_dir[i]) { closedir(g_dir[i]); g_dir[i] = NULL; }
    }
    // 旧 brk 预留区整块卸掉（32MB，不卸的话每次 exec 漏一块）
    if (g_brk_start) {
        munmap((void *)g_brk_start, (size_t)(g_brk_region_end - g_brk_start));
        region_del(g_brk_start, g_brk_region_end);
    }
    g_brk_start = g_brk_cur = g_brk_region_end = 0;
    // 蹦桌池回到起点：新镜像的蹦桌从头写。先把上次设为只读的池段恢复可写。
    g_tp_rx_end = 0;
    mprotect((void *)g_tp_base, (size_t)((uint64_t)g_tp_end - (uint64_t)g_tp_base),
             PROT_READ | PROT_WRITE);
    g_tp_next = g_tp_base;
    // 簿记全部重建（fd 表不动）
    g_region_n = 0;
    g_guard_n = 0;
    g_nimg = 0;
    g_guest_tp_good = 0;
    g_tp_fixups = 0;
    g_tp_writes = 0;
    g_tp_last_write = 0;
    g_tp_last_restored = 0;
    g_sc_last_nr = 0;
    g_patch_skipped = 0;
    g_sc_total = 0;
    for (int i = 0; i < 512; i++) g_sc_by_nr[i] = 0;   // volatile 数组不能用 memset
    // 窗口游标回到两端，新镜像从低端重新 bump-up
    g_win_low = g_win_base;
    g_win_high = g_win_end;
    // CLEARTID 地址属于旧镜像，exec 之后不能再碰
    g_exit_cleartid = 0;
    g_exit_cleartid_val = 0;
}


// 客户机 msr TPIDR_EL0 的校验探针（由 tp-stub.s 调用）。
// 返回真正要写进 TPIDR_EL0 的值。写入值够高就当它是有效 TCB 并记下来；
// 太低说明是 macOS libSystem 遗留的小值（或客户机算错了），此时若手里已有
// 一个有效 TCB 就顶替掉——客户机继续用旧 TCB 能跑，线程指针变野值则必崩。
static int64_t mlc_tp_write_probe(uint64_t *regs, int n) {
    g_tp_writes++;
    uint64_t v = regs[n];
    if (getenv("MLC_DEBUG"))
        fprintf(stderr, "[mlc][tp-write] 客户机要写 TPIDR_EL0 = 0x%llx（当前有效 TCB 0x%llx）\n",
                (unsigned long long)v, (unsigned long long)g_guest_tp_good);
    if (v >= TP_PLAUSIBLE_MIN) {
        g_guest_tp_good = v;
        g_tp_last_write = v;
        return (int64_t)v;
    }
    if (g_guest_tp_good) {
        if (g_tp_fixups < 8)
            fprintf(stderr,
                    "[mlc][警告] 客户机 msr TPIDR_EL0 要写野值 0x%llx，改用有效 TCB 0x%llx（第 %d 次）\n",
                    (unsigned long long)v, (unsigned long long)g_guest_tp_good, g_tp_fixups + 1);
        else if (g_tp_fixups == 8)
            fprintf(stderr, "[mlc][警告] 后续同类顶替不再逐次打印，累计次数见退出诊断\n");
        g_tp_fixups++;
        g_tp_last_write = g_guest_tp_good;
        return (int64_t)g_guest_tp_good;
    }
    // 还没有任何有效 TCB 可用（ld.so 最早那次写入），原样放行
    g_tp_last_write = v;
    return (int64_t)v;
}

// 在一段已就位的客户机可执行内存里扫 svc 并修补到蹦桌池。
// 供 sys_mmap（新映射）与 sys_mprotect（ld.so 后改权限的段）共用：
// 只认 0xD4000001，已修成 B 的位置不会被重复修。
// 同一遍扫描里还拦 msr TPIDR_EL0, xN（0xD51BD040|N），理由见 tp-stub.s：
// 那是客户机唯一会写线程指针的地方，而 macOS libSystem 会把 TPIDR_EL0
// 当成自己的槽位，写野值会让 glibc 的 TP 相对访问落到近零地址上（缺陷 K1）。
static int patch_svc_in_range(uint8_t *content, size_t nbytes) {
    if (!content || nbytes < 4) return 0;
    tp_prepare_write();          // 先把上次设为只读的池段恢复可写
    uint32_t *w = (uint32_t *)content;
    size_t nwords = nbytes / 4;
    int patched = 0;
    uint64_t handler = (uint64_t)(void *)&mlc_syscall_handler;
    uint32_t halves[4] = { (uint32_t)(handler & 0xFFFF), (uint32_t)((handler >> 16) & 0xFFFF),
                           (uint32_t)((handler >> 32) & 0xFFFF), (uint32_t)((handler >> 48) & 0xFFFF) };
    uint64_t tpfn = (uint64_t)(void *)&mlc_tp_write_probe;
    uint32_t tphalves[4] = { (uint32_t)(tpfn & 0xFFFF), (uint32_t)((tpfn >> 16) & 0xFFFF),
                             (uint32_t)((tpfn >> 32) & 0xFFFF), (uint32_t)((tpfn >> 48) & 0xFFFF) };
    uint64_t tpgood = (uint64_t)(void *)&g_guest_tp_good;
    uint32_t tghalves[4] = { (uint32_t)(tpgood & 0xFFFF), (uint32_t)((tpgood >> 16) & 0xFFFF),
                             (uint32_t)((tpgood >> 32) & 0xFFFF), (uint32_t)((tpgood >> 48) & 0xFFFF) };
    for (size_t j = 0; j < nwords; j++) {
        int is_svc = (w[j] == 0xD4000001u);
        // msr TPIDR_EL0, xN：N 取 0..30，31 是 xzr（写 0，同样要拦）
        int is_msr_tp = (w[j] >= 0xD51BD040u && w[j] <= 0xD51BD05Fu);
        // mrs xN, TPIDR_EL0：读线程指针。N=31（xzr）读了也没用，不拦
        int is_mrs_tp = (w[j] >= 0xD53BD040u && w[j] <= 0xD53BD05Eu);
        if (!is_svc && !is_msr_tp && !is_mrs_tp) continue;
        uint64_t stub = tp_alloc(ML_STUB_SLOT);
        if (!stub) {
            fprintf(stderr, "[mlc] 警告: 蹦桌池不足，此处 %s 不拦截（PC=0x%llx）\n",
                    is_svc ? "svc" : (is_msr_tp ? "msr TPIDR_EL0" : "mrs TPIDR_EL0"),
                    (unsigned long long)(uintptr_t)&w[j]);
            break;
        }
        uint32_t *t = (uint32_t *)stub;
        int nwords_stub;
        if (is_svc) {
            memcpy(t, ML_STUB, sizeof(ML_STUB));
            nwords_stub = ML_STUB_WORDS;
            for (int h = 0; h < 4; h++)
                t[21 + h] = (t[21 + h] & ~(0xFFFFU << 5)) | ((halves[h] & 0xFFFF) << 5);
        } else if (is_msr_tp) {
            memcpy(t, ML_TP_STUB, sizeof(ML_TP_STUB));
            nwords_stub = ML_TP_STUB_WORDS;
            // 参数 2 = 被写寄存器下标（movz w1, #N）
            t[ML_TP_STUB_IDX_N] = 0x52800001u | (((uint32_t)(w[j] & 31)) << 5);
            for (int h = 0; h < 4; h++)
                t[ML_TP_STUB_IDX_FN + h] =
                    (t[ML_TP_STUB_IDX_FN + h] & ~(0xFFFFU << 5)) | ((tphalves[h] & 0xFFFF) << 5);
        } else {
            memcpy(t, ML_MRS_STUB, sizeof(ML_MRS_STUB));
            nwords_stub = ML_MRS_STUB_WORDS;
            for (int h = 0; h < 4; h++)
                t[ML_MRS_STUB_IDX_ADDR + h] =
                    (t[ML_MRS_STUB_IDX_ADDR + h] & ~(0xFFFFU << 5)) | ((tghalves[h] & 0xFFFF) << 5);
            // 目标寄存器：orr xN, xzr, x9（N=0..30）
            t[ML_MRS_STUB_IDX_DST] = 0xAA0903E0u | (w[j] & 31u);
            // 目标寄存器恰为 x9 时，出口那条「还原原 x9」必须让位，否则刚写进 x9 的
            // 选中值会被盖回客户机的旧 x9。改成 nop，其余寄存器不受影响。
            if ((w[j] & 31u) == 9u) t[ML_MRS_STUB_IDX_X9REST] = AARCH64_NOP;
        }
        int64_t to_stub = (int64_t)stub - (int64_t)&w[j];
        int64_t to_ret  = (int64_t)(&w[j] + 1) - (int64_t)(stub + (nwords_stub - 1) * 4);
        if (to_stub > 0x08000000LL || to_stub < -0x08000000LL ||
            to_ret  > 0x08000000LL || to_ret  < -0x08000000LL) {
            // K2 排查：射程不够就放弃这个站点。被放弃的 svc 会触发 SIGSYS，
            // 被放弃的 mrs TPIDR_EL0 会让客户机读到 macOS 遗留的野线程指针。
            // 窗口 96MB 加蹦桌池 16MB 的极限距离约 112MB，离 128MB 只剩 16MB 余量，
            // 而窗口基址每轮都变，所以这是少数几个真会随运行变化的因素。
            g_patch_skipped++;
            continue;
        }
        w[j] = 0x14000000u | ((uint32_t)(to_stub / 4) & 0x03FFFFFFu);
        uint32_t *bret = (uint32_t *)(stub + (nwords_stub - 1) * 4);
        bret[0] = 0x14000000u | ((uint32_t)(to_ret / 4) & 0x03FFFFFFu);
        patched++;
    }
    // 无条件收尾，不能只在 patched 非零时收：mprotect 补扫那条路（SYS_mprotect）
    // 常常一个站点都不命中，而 tp_prepare_write 已经把池子恢复成可写了——
    // 此时若不设回只读可执行就返回客户机，客户机一跳蹦桌就是 SIGBUS。
    // v1.5 实测：ls -la / 崩 199/200，故障页 prot=3（可写不可执行），
    // 崩溃前最后一次系统调用正是 nr=226。
    tp_finish_write();
    return patched;
}

// 诊断包装：把 mmap 的每次决策与窗口游标都打出来。B6（收尾 SIGBUS）排查用——
// 只看 nr=222 的 x0/x1 分不清"走了哪条分支""窗口游标被谁推动"。
// 实现体改名 sys_mmap_impl，本函数是唯一入口（case SYS_mmap 调它）。
static int64_t sys_mmap_dbg(uint64_t addr, uint64_t len, uint64_t prot, uint64_t lflags, int gfd, uint64_t off);

static int64_t sys_mmap_impl(uint64_t addr, uint64_t len, uint64_t prot, uint64_t lflags, int gfd, uint64_t off) {
    if (len == 0) return -L_EINVAL;
    int flags = 0;
    int hfd = -1;
    if (lflags & 0x01) flags |= MAP_SHARED;      // MAP_SHARED=0x01 两侧一致
    if (lflags & 0x02) flags |= MAP_PRIVATE;     // MAP_PRIVATE=0x02 两侧一致
    if (lflags & 0x10) flags |= MAP_FIXED;
    if (lflags & 0x20) {                          // MAP_ANONYMOUS=0x20 -> MAP_ANON
        flags |= MAP_ANON;
    } else {
        hfd = guest_fd_host(gfd);
        if (hfd < 0) return -L_EBADF;
    }
    int hprot = 0;
    if (prot & 1) hprot |= PROT_READ;
    if (prot & 2) hprot |= PROT_WRITE;
    if (prot & 4) hprot |= PROT_EXEC;
    // 宿主页 16K：按宿主页取整。注意必须是 [page_down(addr), page_up(addr+len))，
    // 直接用 page_up(len) 会在 addr 未对齐时少覆盖尾部页（v1.2 修）
    uint64_t map_addr = addr ? page_down(addr) : 0;
    uint64_t map_end  = addr ? page_up(addr + len) : page_up(len);
    uint64_t map_len  = map_end - map_addr;
    // 文件映射一律走"匿名映射 + pread 读入内容"，绕开 macOS 两道限制：
    //   1. 代码签名强制：任意文件（ELF）映射为 PROT_EXEC 返回 EPERM；
    //   2. offset+len 超出文件尾时 macOS 直接 ENOMEM（Linux 允许，仅越界页 SIGBUS）。
    // 代价：MAP_SHARED 文件映射不再写回文件（ld.so 用 MAP_PRIVATE，可接受）。
    if ((hprot & PROT_EXEC) || hfd >= 0) {
        int fixed = (addr && (lflags & 0x10)) != 0;
        uint64_t body_at = 0;
        if (fixed) {
            if (engine_region_hit(map_addr, map_addr + map_len)) return -L_ENOMEM;
            // 覆盖活区间本身是 Linux MAP_FIXED 的合法语义，但必须留痕：
            // 排查动态链接偶发崩溃时，"谁覆盖了谁"是唯一能定位问题的线索
            if (guest_region_overlap(map_addr, map_addr + map_len) && getenv("MLC_DEBUG"))
                fprintf(stderr, "[mlc][mmap] MAP_FIXED 覆盖已注册区间 [0x%llx,0x%llx) prot=%llx\n",
                        (unsigned long long)map_addr, (unsigned long long)(map_addr + map_len),
                        (unsigned long long)prot);
            // 审计 F49：必须先 munmap 再 mmap（macOS 对部分重叠的 MAP_FIXED 直接
            // ENOMEM），但 munmap 之后区域表必须同步改。旧代码在 mmap 失败时直接
            // 返回错误，区域表仍声称该区间可访问——客户机随后访问已卸载内存，
            // 而野指针校验会放行（实测崩溃签名：故障地址"在客户机区域表内=是"）。
            region_del(map_addr, map_addr + map_len);
            munmap((void *)map_addr, map_len);   // macOS 对部分重叠的 MAP_FIXED 会 ENOMEM，先腾空
            body_at = map_addr;
        } else if (addr && !engine_region_hit(page_down(addr), page_up(addr + len))
                   && !guest_region_overlap(map_addr, map_addr + map_len)) {
            // 无 MAP_FIXED 的 hint 要尽量满足：glibc 的 _dl_map_segment 正是用
            // 无 MAP_FIXED 的 mmap 传 hint，再由返回值推 l_addr。我们若把 hint
            // 改分配到别处，ld.so 记录的基址与实际映射脱节，后续段的 MAP_FIXED
            // 就会落到错误地址（v1.2 修）。
            body_at = page_down(addr);
        } else {
            body_at = win_alloc(map_len);        // 否则从窗口顺序分配
        }
        // body_at 由我们指定（窗口分配或客户机 MAP_FIXED 地址），必须 MAP_FIXED 落位；
        // 少了它 macOS 会自选地址，而我们还把客户机请求的地址当成功返回（v1.2 修）
        int anon_flags = MAP_PRIVATE | MAP_ANON | MAP_FIXED;
        // MAP_FIXED 必须保留：曾把它一并剥掉，macOS 就把映射放到别处，而引擎仍把
        // 客户机请求的地址当成功返回，客户机随后访问未映射内存（F17）。
        void *r = mmap((void *)body_at, map_len, PROT_READ | PROT_WRITE, anon_flags, -1, 0);
        if (r == MAP_FAILED) {
            int e = errno;
            fprintf(stderr, "[mlc][诊断] 匿名映射失败 addr=0x%llx len=0x%llx flags=0x%x errno=%d(%s)\n",
                    (unsigned long long)body_at, (unsigned long long)map_len, anon_flags, e, strerror(e));
            if (fixed) win_free_top(map_addr, map_addr + map_len);   // 区间已空，窗口水位可以退
            return -e;                                              // 区域表已在上面摘掉（F49）
        }
        uint64_t rbase = (uint64_t)r;
        size_t off_in_page = (rbase == page_down(addr) && addr) ? (size_t)(addr & 0x3FFF) : 0;
        if (hfd >= 0 && len > 0) {
            ssize_t got = pread(hfd, (void *)(rbase + off_in_page), (size_t)len, (off_t)off);
            if (got < 0) { munmap((void *)rbase, map_len); return -errno; }
            // K2 排查：短读不会报错，但映射尾部会停在零页。glibc 的动态链接元数据
            // 就在文件前部，一旦没读全，符号表整段是零，查表必然失败，而症状是
            // 「undefined symbol」且失败符号每次都不一样——与 K2 完全吻合。
            // 原实现只判 got < 0，短读被静默放过。
            // 短读在这里是正常的：客户机会按 memsz 请求比 filesz 更大的映射，
            // 多出来的部分本就该是零页（匿名映射已是零），所以只在 MLC_DEBUG 下提示。
            if (got != (ssize_t)len && getenv("MLC_DEBUG")) {
                fprintf(stderr, "[mlc][短读] fd=%d 文件偏移 0x%llx 请求 %zu 字节，实读 %zd 字节"
                        "（多出的部分按零页处理）\n", hfd, (unsigned long long)off,
                        (size_t)len, got);
            }
        }
        // 扫 svc 并修补（内容已在内存里）
        if (hprot & PROT_EXEC) {
            int n = patch_svc_in_range((uint8_t *)(rbase + off_in_page), (size_t)len);
            if (n && getenv("MLC_DEBUG"))
                fprintf(stderr, "[mlc] 动态库可执行映射 0x%llx，拦截 %d 处 svc\n",
                        (unsigned long long)rbase, n);
        }
        if (mprotect((void *)page_down(rbase), page_up(map_len), hprot) < 0) {
            int e = errno;
            fprintf(stderr, "[mlc][诊断] 匿名映射 mprotect 失败 addr=0x%llx len=0x%llx errno=%d\n",
                    (unsigned long long)rbase, (unsigned long long)map_len, e);
            munmap((void *)rbase, map_len); return -e;
        }
        region_add(rbase, rbase + map_len);   // 只登记客户机范围，蹦桌池客户机不可见
        // 返回客户机视角地址：FIXED 用请求地址；hint 满足时用 hint；窗口分配返回窗口地址
        if (fixed) return (int64_t)addr;
        if (rbase == page_down(addr) && addr) return (int64_t)addr;
        return (int64_t)rbase;
    }
    if (addr && (lflags & 0x10)) {
        // MAP_FIXED 只禁止覆盖引擎保护区（镜像与蹦桌），其余地址允许：
        // ld.so 的 zero-fill 洞与新库段都要映射到尚未注册的新地址，
        // 用 region_covers 一律拒绝会让动态链接直接失败（v1.2 修）。
        if (engine_region_hit(map_addr, map_addr + map_len)) return -L_ENOMEM;
        if (guest_region_overlap(map_addr, map_addr + map_len) && getenv("MLC_DEBUG"))
            fprintf(stderr, "[mlc][mmap] MAP_FIXED 覆盖已注册区间 [0x%llx,0x%llx) prot=%llx\n",
                    (unsigned long long)map_addr, (unsigned long long)(map_addr + map_len),
                    (unsigned long long)prot);
        // 审计 F49：同匿名/exec 路径——先摘区域表再 munmap，mmap 失败时簿记才不说谎
        region_del(map_addr, map_addr + map_len);
        munmap((void *)map_addr, map_len);   // macOS 对部分重叠的 MAP_FIXED 会 ENOMEM，先腾空
        void *r = mmap((void *)map_addr, map_len, hprot, flags, hfd, 0);
        if (r == MAP_FAILED) {
            int e = errno;
            fprintf(stderr, "[mlc][诊断] MAP_FIXED 映射失败 addr=0x%llx len=0x%llx errno=%d(%s)\n",
                    (unsigned long long)map_addr, (unsigned long long)map_len, e, strerror(e));
            win_free_top(map_addr, map_addr + map_len);
            return -e;
        }
        region_add(map_addr, map_addr + map_len);
        return (int64_t)addr;
    }
    // 非 MAP_FIXED 的映射也一律从客户机窗口取地址（或满足 hint）：
    // 曾让内核自选，结果 libc 被放到距主程序 143MB 之外，B 跳转直接越界，
    // libc 的 svc 全部拦不住（v1.2 修）。
    uint64_t body_at;
    if (addr && !engine_region_hit(page_down(addr), page_up(addr + len))
             && !guest_region_overlap(map_addr, map_addr + map_len))
        body_at = page_down(addr);
    else
        body_at = win_alloc(map_len);
    uint64_t req_len = map_len;
    void *r = body_at ? mmap((void *)body_at, req_len, hprot, flags | MAP_FIXED, hfd, (off_t)(page_down(off)))
                      : mmap(NULL, req_len, hprot, flags, hfd, (off_t)(page_down(off)));
    if (r == MAP_FAILED) {
        int e = errno;
        fprintf(stderr, "[mlc][诊断] 映射失败 addr=0x%llx len=0x%llx prot=0x%x flags=0x%x fd=%d errno=%d(%s)\n",
                (unsigned long long)map_addr, (unsigned long long)req_len, hprot, flags, hfd, e, strerror(e));
        return -e;
    }
    region_add((uint64_t)r, (uint64_t)r + req_len);   // M3：登记映射区间
    return (int64_t)r;
}

static int64_t sys_mmap_dbg(uint64_t addr, uint64_t len, uint64_t prot, uint64_t lflags, int gfd, uint64_t off) {
    uint64_t wl = (uint64_t)g_win_low, wh = (uint64_t)g_win_high;
    int64_t r = sys_mmap_impl(addr, len, prot, lflags, gfd, off);
    if (getenv("MLC_DEBUG"))
        fprintf(stderr, "[mlc][mmap] addr=%llx len=%llx prot=%llx flags=%llx fd=%d off=%llx"
                        " -> ret=%llx 游标 low %llx->%llx high %llx->%llx\n",
                (unsigned long long)addr, (unsigned long long)len, (unsigned long long)prot,
                (unsigned long long)lflags, gfd, (unsigned long long)off,
                (unsigned long long)(uint64_t)r,
                (unsigned long long)wl, (unsigned long long)(uint64_t)g_win_low,
                (unsigned long long)wh, (unsigned long long)(uint64_t)g_win_high);
    return r;
}

static void fill_utsname(l_utsname_t *u) {
    memset(u, 0, sizeof(*u));
    strcpy(u->sysname, "Linux");
    gethostname(u->nodename, sizeof(u->nodename) - 1);
    strcpy(u->release, "5.15.0-mlc");
    strcpy(u->version, "#1 SMP mlc-compat");
    strcpy(u->machine, "aarch64");
    strcpy(u->domainname, "(none)");
}

// ---------- 系统调用分发 ----------
static int64_t mlc_syscall_handler_impl(uint64_t *regs) {
    uint64_t nr = regs[REG_X8];
    uint64_t a0 = regs[0], a1 = regs[1], a2 = regs[2], a3 = regs[3], a4 = regs[4], a5 = regs[5];

    switch (nr) {
    case SYS_write:
    case SYS_writev: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        if (nr == SYS_write) {
            if (!guest_ptr_ok(a1, a2 > GUEST_IO_MAX ? 0 : a2)) return -L_EFAULT;
            ssize_t r = write(hfd, (const void *)a1, (size_t)a2);
            return r < 0 ? -errno : r;
        } else {
            // iovec: {base, len} × cnt
            uint64_t cnt = a2;
            if (!guest_ptr_ok(a1, cnt * 16)) return -L_EFAULT;
            ssize_t total = 0;
            for (uint64_t i = 0; i < cnt; i++) {
                uint64_t base = *(uint64_t *)(a1 + i * 16);
                uint64_t len  = *(uint64_t *)(a1 + i * 16 + 8);
                if (!guest_ptr_ok(base, len > GUEST_IO_MAX ? 0 : len)) return -L_EFAULT;
                ssize_t r = write(hfd, (const void *)base, (size_t)len);
                if (r < 0) return total ? total : -errno;
                total += r;
                if ((uint64_t)r < len) break;
            }
            return total;
        }
    }
    case SYS_read: {
        // F65：设备 fd 必须先判，它们没有宿主 fd（表里是 -1 占位），
        // 走到下面 guest_fd_host 的 EBADF 分支就再也读不到了
        if ((int)a0 >= 0 && (int)a0 < GUEST_FD_MAX && g_dev_random[(int)a0]) {
            if (!guest_ptr_ok(a1, a2 > GUEST_IO_MAX ? 0 : a2)) return -L_EFAULT;
            arc4random_buf((void *)a1, (size_t)a2);
            return (int64_t)a2;
        }
        if ((int)a0 >= 0 && (int)a0 < GUEST_FD_MAX && g_dev_zero[(int)a0]) {
            if (!guest_ptr_ok(a1, a2 > GUEST_IO_MAX ? 0 : a2)) return -L_EFAULT;
            memset((void *)a1, 0, (size_t)a2);
            return (int64_t)a2;
        }
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        if (!guest_ptr_ok(a1, a2 > GUEST_IO_MAX ? 0 : a2)) return -L_EFAULT;
        ssize_t r = read(hfd, (void *)a1, (size_t)a2);
        return r < 0 ? -errno : r;
    }
    case SYS_readv: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        uint64_t cnt = a2;
        if (!guest_ptr_ok(a1, cnt * 16)) return -L_EFAULT;
        ssize_t total = 0;
        for (uint64_t i = 0; i < cnt; i++) {
            uint64_t base = *(uint64_t *)(a1 + i * 16);
            uint64_t len  = *(uint64_t *)(a1 + i * 16 + 8);
            if (!guest_ptr_ok(base, len > GUEST_IO_MAX ? 0 : len)) return -L_EFAULT;
            ssize_t r = read(hfd, (void *)base, (size_t)len);
            if (r < 0) return total ? total : -errno;
            total += r;
            if ((uint64_t)r < len) break;
        }
        return total;
    }
    case SYS_pread64: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        if (!guest_ptr_ok(a1, a2 > GUEST_IO_MAX ? 0 : a2)) return -L_EFAULT;
        ssize_t r = pread(hfd, (void *)a1, (size_t)a2, (off_t)a3);
        return r < 0 ? -errno : r;
    }
    case SYS_pwrite64: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        if (!guest_ptr_ok(a1, a2 > GUEST_IO_MAX ? 0 : a2)) return -L_EFAULT;
        ssize_t r = pwrite(hfd, (const void *)a1, (size_t)a2, (off_t)a3);
        return r < 0 ? -errno : r;
    }
    case SYS_openat:
        return sys_openat((int)a0, (const char *)a1, a2, a3);
    case SYS_close: {
        int gfd = (int)a0;
        // F65：设备 fd 没有宿主 fd，先摘标记再返回，不能走 close(hfd)
        if (gfd >= 0 && gfd < GUEST_FD_MAX && (g_dev_random[gfd] || g_dev_zero[gfd])) {
            g_dev_random[gfd] = 0;
            g_dev_zero[gfd] = 0;
            guest_fd_free(gfd);
            return 0;
        }
        int hfd = guest_fd_host(gfd);
        if (hfd < 0) return -L_EBADF;
        // M2：目录句柄联动销毁，避免 DIR* 与内部 dup fd 泄漏
        pthread_mutex_lock(&g_dir_lock);
        DIR *d = g_dir[gfd];
        g_dir[gfd] = NULL;
        pthread_mutex_unlock(&g_dir_lock);
        if (d) closedir(d);
        close(hfd);
        guest_fd_free(gfd);
        return 0;
    }
    case SYS_lseek: {
        // F65：设备 fd 不可 seek，报 0 让调用方以为停在开头
        if (guest_fd_is_dev((int)a0)) return 0;
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        off_t r = lseek(hfd, (off_t)a1, (int)a2);
        return r < 0 ? -errno : r;
    }
    case SYS_fstat: {
        if (!guest_ptr_ok(a1, sizeof(l_stat_t))) return -L_EFAULT;
        // F65：设备 fd 没有宿主 fd，报成字符设备（S_IFCHR=0o020000，size 0）
        if (guest_fd_is_dev((int)a0)) {
            memset((void *)a1, 0, sizeof(l_stat_t));
            l_stat_t *ls = (l_stat_t *)a1;
            ls->st_mode = 0020000 | 020666;
            ls->st_blksize = 4096;
            return 0;
        }
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        struct stat hs;
        if (fstat(hfd, &hs) < 0) return -errno;
        fill_lstat((l_stat_t *)a1, &hs);
        return 0;
    }
    case SYS_newfstatat: {
        // ABI：newfstatat(int dfd, const char *filename, struct stat *statbuf, int flag)
        //      a0=dfd  a1=filename  a2=statbuf  a3=flag
        // 曾把 a2/a3 写反：a2 当 flag、a3 当 statbuf。后果是 statbuf 从来没被填过，
        // 而客户机看到的返回值一直是 0（成功）——于是 stat 全都「成功但全零」。
        // 实测症状：dash 的 test -f / -d 恒为假（st_mode 为 0，S_ISREG/S_ISDIR 都不成立），
        // 进而 dash 的 PATH 搜索把找到的可执行文件全部判成「非常规文件」而跳过，
        // sh -c 'ls /' 报 Permission denied、退出码 127。
        // ls/cat/stat 一类不受影响是因为 glibc 2.39 优先走 statx（nr=291），那条路是对的。
        if (!guest_str_ok(a1, 4096)) return -L_EFAULT;
        if (a2 && !guest_ptr_ok(a2, sizeof(l_stat_t))) return -L_EFAULT;
        const char *path = (const char *)a1;
        char hpath[1024];
        if (guest_to_host_path(path, hpath, sizeof(hpath)) < 0) return -L_ENAMETOOLONG_;
        struct stat hs;
        int r;
        // a3 是 flags：AT_SYMLINK_NOFOLLOW(0x100) 时用 lstat
        int nofollow = (a3 & 0x100) != 0;
        if (a0 == (uint64_t)-100 /*AT_FDCWD*/)
            r = nofollow ? lstat(hpath, &hs) : stat(hpath, &hs);
        else
            r = fstatat(guest_fd_host((int)a0), hpath, &hs, nofollow ? AT_SYMLINK_NOFOLLOW : 0);
        if (r < 0) return -errno;
        if (a2 /* statbuf */) fill_lstat((l_stat_t *)a2, &hs);
        return 0;
    }
    case SYS_statx: {
        // glibc 2.39（Ubuntu 24.04）用它探测文件。struct statx 布局按 Linux arm64 手工填关键字段。
        if (!guest_str_ok(a1, 4096)) return -L_EFAULT;
        if (!guest_ptr_ok(a4, 256)) return -L_EFAULT;
        char hpath[1024];
        if (guest_to_host_path((const char *)a1, hpath, sizeof(hpath)) < 0) return -L_ENAMETOOLONG_;
        struct stat hs;
        int nofollow = (a2 & 0x100) != 0;    // AT_SYMLINK_NOFOLLOW
        int r = (a0 == -100) ? (nofollow ? lstat(hpath, &hs) : stat(hpath, &hs))
                             : fstatat(guest_fd_host((int)a0), hpath, &hs,
                                       nofollow ? AT_SYMLINK_NOFOLLOW : 0);
        if (r < 0) return -errno;
        uint8_t *b = (uint8_t *)a4;
        memset(b, 0, 256);
        const uint32_t STX_TYPE = 1, STX_MODE = 2, STX_NLINK = 4, STX_UID = 8, STX_GID = 0x10,
                       STX_ATIME = 0x20, STX_MTIME = 0x40, STX_CTIME = 0x80, STX_INO = 0x100,
                       STX_SIZE = 0x200, STX_BLOCKS = 0x400;
        uint32_t mask = STX_TYPE | STX_MODE | STX_NLINK | STX_UID | STX_GID |
                        STX_ATIME | STX_MTIME | STX_CTIME | STX_INO | STX_SIZE | STX_BLOCKS;
        *(uint32_t *)(b + 0)  = mask;                     // stx_mask
        *(uint32_t *)(b + 4)  = (uint32_t)hs.st_blksize;  // stx_blksize
        *(uint32_t *)(b + 16) = (uint32_t)hs.st_nlink;    // stx_nlink
        *(uint32_t *)(b + 20) = hs.st_uid;                // stx_uid
        *(uint32_t *)(b + 24) = hs.st_gid;                // stx_gid
        *(uint16_t *)(b + 28) = (uint16_t)hs.st_mode;     // stx_mode
        *(uint64_t *)(b + 32) = (uint64_t)hs.st_ino;      // stx_ino
        *(uint64_t *)(b + 40) = (uint64_t)hs.st_size;     // stx_size
        *(uint64_t *)(b + 48) = (uint64_t)hs.st_blocks;   // stx_blocks
        int64_t at = hs.st_atime, mt = hs.st_mtime, ct = hs.st_ctime;
        memcpy(b + 64, &at, 8); memcpy(b + 72, &(long){hs.st_atimespec.tv_nsec}, 4);   // atime
        memcpy(b + 112, &mt, 8); memcpy(b + 120, &(long){hs.st_mtimespec.tv_nsec}, 4); // mtime
        memcpy(b + 96, &ct, 8); memcpy(b + 104, &(long){hs.st_ctimespec.tv_nsec}, 4);  // ctime
        *(uint32_t *)(b + 136) = major(hs.st_rdev);       // stx_dev_major
        *(uint32_t *)(b + 140) = minor(hs.st_rdev);       // stx_dev_minor
        *(uint32_t *)(b + 128) = major(hs.st_dev);        // stx_rdev_major
        *(uint32_t *)(b + 132) = minor(hs.st_dev);        // stx_rdev_minor
        return 0;
    }
    case SYS_getdents64:
        return sys_getdents64((int)a0, (void *)a1, a2);
    case SYS_ioctl:
        return sys_ioctl((int)a0, a1, a2);
    case SYS_fcntl: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        // 命令号两侧不是同一套：Linux F_GETLK=5/F_SETLK=6/F_SETLKW=7、
        // F_DUPFD_CLOEXEC=1030，宿主分别是 7/8/9 与 67。不翻译的话客户机要
        // F_GETLK 会拿到宿主的 F_GETOWN，要 F_SETLK 会去改 socket owner，
        // 而且全都"成功返回"——静默做错事比报错更难发现（2026-11-06 修）。
        int cmd = (int)a1;
        switch (cmd) {
            case 5:    cmd = 7;  break;   // F_GETLK
            case 6:    cmd = 8;  break;   // F_SETLK
            case 7:    cmd = 9;  break;   // F_SETLKW
            case 1030: cmd = 67; break;   // F_DUPFD_CLOEXEC
            default: break;
        }
        // 带指针的那几个要校验，否则客户机给个野指针就写穿宿主内存
        if ((cmd == 7 /*宿主 F_GETLK*/ || cmd == 8 /*F_SETLK*/ || cmd == 9 /*F_SETLKW*/)
            && !guest_ptr_ok(a2, sizeof(struct flock))) return -L_EFAULT;
        // F_DUPFD / F_DUPFD_CLOEXEC：宿主返回的是宿主 fd 号，客户机认的是自己
        // 的 fd 表。原来直接把宿主号递回去，客户机会拿到一个从未登记过的 fd，
        // 之后对它的任何操作都是 EBADF。dash 保存 stdout 再还原正是这条路：
        //   fcntl(1, F_DUPFD, 10) -> 10，fcntl(10, F_GETFD) -> EBADF，
        //   dup3(10, 1, 0) -> EBADF，于是 stdout 永远停在重定向目标上。
        // 实测症状：sh -c 'echo a; echo b > /dev/null; echo c' 只打印 a。
        int is_dup = (cmd == 0 || cmd == 67);
        int r = fcntl(hfd, cmd, (void *)a2);
        if (r < 0) return -errno;
        if (is_dup) {
            int g = guest_fd_alloc(r);
            if (g < 0) { close(r); return -L_EMFILE_; }
            dev_fd_copy((int)a0, g);
            return g;
        }
        return r;
    }
    case SYS_brk: {
        if (!a0) return (int64_t)g_brk_cur;
        if (a0 < g_brk_start) return (int64_t)g_brk_cur;
        uint64_t want = page_up(a0);
        uint64_t cur  = page_up(g_brk_cur);
        if (want > cur) {
            if (want > g_brk_region_end) return (int64_t)g_brk_cur;   // 超出预留区
            void *r = mmap((void *)cur, want - cur, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
            if (r == MAP_FAILED) return (int64_t)g_brk_cur;   // L1：失败即回滚
            region_add(cur, want);
        } else if (want < cur) {
            if (munmap((void *)want, cur - want) < 0) return (int64_t)g_brk_cur;   // L1：回滚
            region_del(want, cur);
        }
        g_brk_cur = a0;
        return (int64_t)a0;
    }
    case SYS_mmap:
        return sys_mmap_dbg(a0, a1, a2, a3, (int)a4, a5);
    case SYS_munmap: {
        // M3：只卸完整的宿主页（[page_up(s), page_down(e))），宿主页内与相邻映射
        // 共享的部分一律不碰。曾把页内残余 mprotect 成 PROT_NONE，但 macOS 的
        // mprotect 长度按页向上取整，一个 0x1000 的"残余"会把整个 16K 宿主页
        // 连同相邻映射的数据一起打成不可访问（v1.2 F31 修）。
        uint64_t s = a0, e = a0 + a1;
        if (a1 == 0 || e < s) return -L_EINVAL;
        // 引擎保护区（镜像、蹦桌）不可卸：曾因 ld.so 卸预留区尾部把 libc 的蹦桌
        // 一起卸掉，之后系统调用跳进已卸载页，SIGBUS（v1.2 修）。
        // 这里只查一次：审计 F40 发现同一句连续查了两遍，第二遍是补注释时
        // 复制留下的，除了多打一行诊断没有任何作用。
        if (engine_region_hit(page_down(s), page_up(e))) return -L_EINVAL;
        uint64_t wl_before = (uint64_t)g_win_low;
        // 区域表与宿主实际卸除的范围必须一致：宿主只卸 [page_up(s), page_down(e))
        // （页内残余不能动，见上方 F31 注释），所以区域表也只摘这一段。
        // 曾直接把未对齐的 [s, e) 交给 region_del，它的「删中间」与「删头部」
        // 分支会写出未对齐条目（实测形如 [0x10a5c4018,0x10a5c8000)），
        // 之后 region_add 的合并、win_free_top 的游标回退都建立在对齐假设上。
        uint64_t d_s = page_up(s), d_e = page_down(e);
        // 先从区域表摘掉，win_free_top 才能看出哪一段真的空了（顺序反了会永远退不动）
        if (d_s < d_e) region_del(d_s, d_e);
        win_free_top(page_down(s), page_up(e));   // 窗口栈式复用
        uint64_t mid_s = page_up(s), mid_e = page_down(e);
        if (mid_s < mid_e && munmap((void *)mid_s, mid_e - mid_s) < 0) return -errno;
        if (getenv("MLC_DEBUG"))
            fprintf(stderr, "[mlc][munmap] [%llx,%llx) 宿主卸 [%llx,%llx) 游标 low %llx->%llx\n",
                    (unsigned long long)s, (unsigned long long)e,
                    (unsigned long long)mid_s, (unsigned long long)mid_e,
                    (unsigned long long)wl_before, (unsigned long long)(uint64_t)g_win_low);
        return 0;
    }
    case SYS_mprotect: {
        // 黑名单式：只禁止改引擎保护区（镜像、蹦桌池）。原为白名单（region_covers），
        // 但 ld.so 会给对齐 padding 发 mprotect，范围比原映射大，白名单一律拒绝导致
        // "cannot change memory protections"（v1.2 修）。取舍记录为 D12。
        if (a1 == 0) return -L_EINVAL;
        if (engine_region_hit(page_down(a0), page_up(a0 + a1))) return -L_ENOMEM;
        int hprot = 0;
        if (a2 & 1) hprot |= PROT_READ;
        if (a2 & 2) hprot |= PROT_WRITE;
        if (a2 & 4) hprot |= PROT_EXEC;
        // 长度必须是区间长度，不是末端绝对地址（曾把 page_up(a0+a1) 当长度传，
        // 长度成天文数字，所有 mprotect 都 ENOMEM，ld.so 报 cannot change memory protections）
        uint64_t mp_s = page_down(a0), mp_e = page_up(a0 + a1);
        int r = mprotect((void *)mp_s, mp_e - mp_s, hprot);
        if (r == 0 && (a2 & 4)) {
            // ld.so 会把先映射为 RW 的段改成可执行，那里的 svc 也要拦截（v1.2 补）
            int n = patch_svc_in_range((uint8_t *)page_down(a0), (size_t)(page_up(a0 + a1) - page_down(a0)));
            if (n && getenv("MLC_DEBUG"))
                fprintf(stderr, "[mlc] mprotect 补扫 0x%llx，拦截 %d 处 svc\n",
                        (unsigned long long)page_down(a0), n);
        }
        return r < 0 ? -errno : 0;
    }
    case SYS_madvise:
        return 0;
    case SYS_mremap: {
        // macOS 无 mremap：新映射 + 拷贝 + 解除旧映射
        if (!guest_ptr_ok(a0, a1)) return -L_EFAULT;
        // 卸与登记必须用同一套页对齐区间。审计 F38：旧代码 munmap 用
        // [page_down(a0), page_up(a1)) 而 region_del 用未对齐的 [a0, a0+a1)，
        // 于是区域表里留下"已释放"的残余条目，guest_ptr_ok 会对已卸载地址
        // 返回 true——野指针校验被自己松掉，客户机随后读写宿主已卸载页。
        uint64_t os = page_down(a0), oe = page_up(a0 + a1);
        void *r = mmap(NULL, page_up(a2), PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
        if (r == MAP_FAILED) return -errno;
        memcpy(r, (void *)a0, a1 < a2 ? a1 : a2);
        if (munmap((void *)os, oe - os) == 0) region_del(os, oe);
        region_add((uint64_t)r, (uint64_t)r + page_up(a2));
        return (int64_t)r;
    }
    case SYS_pipe2: {
        if (!guest_ptr_ok(a0, 8)) return -L_EFAULT;
        int fds[2];
        if (pipe(fds) < 0) return -errno;
        int g0 = guest_fd_alloc(fds[0]), g1 = guest_fd_alloc(fds[1]);
        if (g0 < 0 || g1 < 0) { close(fds[0]); close(fds[1]); return -L_EMFILE_; }
        ((int *)a0)[0] = g0; ((int *)a0)[1] = g1;
        return 0;
    }
    case SYS_dup: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        int nd = dup(hfd);
        if (nd < 0) return -errno;
        int g = guest_fd_alloc(nd);
        if (g < 0) { close(nd); return -L_EMFILE_; }
        dev_fd_copy((int)a0, g);
        return g;
    }
    case SYS_dup3: {
        int hfd = guest_fd_host((int)a0);
        if (hfd < 0) return -L_EBADF;
        if (a1 < 0 || a1 >= GUEST_FD_MAX) return -L_EBADF;
        if (a0 == a1) return (int64_t)a1;              // 同号是合法的 no-op
        // v1.1 F09：旧实现把同一宿主 fd 塞给两个 guest fd，关一个就连环双 close。
        // 正确做法是 dup 出独立宿主 fd。
        int nd = dup(hfd);
        if (nd < 0) return -errno;
        int old = guest_fd_host((int)a1);
        if (old >= 0) close(old);
        pthread_mutex_lock(&g_dir_lock);
        DIR *d = g_dir[a1];
        g_dir[a1] = NULL;
        pthread_mutex_unlock(&g_dir_lock);
        if (d) closedir(d);
        g_fd_map[a1] = nd;
        dev_fd_copy((int)a0, (int)a1);
        return (int64_t)a1;
    }
    case SYS_exit:
    case SYS_exit_group: {
        // 这里必须自己打 trace：wrapper 的返回打印排在 _exit 之后，永远不会执行
        if (getenv("MLC_DEBUG")) {
            // K2 排查：失败发生在客户机代码里，看不到调用链就定位不到是哪一段。
            // x30 是链接寄存器，_dl_signal_error 系列的调用者会留在栈上，
            // 这里把退出瞬间的全部寄存器打出来，事后按镜像基址反查符号。
            fprintf(stderr, "[mlc][退出现场] x29=0x%llx x30=0x%llx pc 附近 sp=0x%llx\n",
                    (unsigned long long)regs[29], (unsigned long long)regs[30],
                    (unsigned long long)(uintptr_t)&regs[0]);
            // 反查这些地址各落在哪个客户机区域，直接指出失败发生在哪一段代码里
            uint64_t probes[8];
            int np = 0;
            probes[np++] = regs[30];
            uint64_t *sp0 = (uint64_t *)regs[31];
            if (sp0 && guest_ptr_ok((uint64_t)(uintptr_t)sp0, 128)) {
                for (int k = 0; k < 6 && np < 8; k++) probes[np++] = sp0[k];
            }
            for (int k = 0; k < np; k++) {
                uint64_t a = probes[k];
                if (!a) continue;
                int hit = -1;
                for (int i = 0; i < g_region_n; i++)
                    if (g_region[i].start <= a && a < g_region[i].end) { hit = i; break; }
                fprintf(stderr, "[mlc][退出现场] 地址 0x%llx 落在%s\n",
                        (unsigned long long)a,
                        hit < 0 ? "任何已注册区域之外" : "");
                if (hit >= 0)
                    fprintf(stderr, "[mlc][退发现场]   区域 %d [0x%llx,0x%llx)\n", hit,
                            (unsigned long long)g_region[hit].start,
                            (unsigned long long)g_region[hit].end);
            }
            fprintf(stderr, "[mlc] 系统调用 nr=%llu -> 进程退出码 %d\n",
                    (unsigned long long)nr, (int)a0);
            // 退出前直接读各库加载点：libc 的 _IO_2_1_stdout_ 在基址 + 0x1b1520，
            // _fileno 在 +0x70。客户机把输出写到 fd 0 而不是 fd 1 时，这一行就能定性。
            fprintf(stderr, "[mlc][诊断] fd 表 0..7 = %d,%d,%d,%d,%d,%d,%d,%d\n",
                    g_fd_map[0], g_fd_map[1], g_fd_map[2], g_fd_map[3],
                    g_fd_map[4], g_fd_map[5], g_fd_map[6], g_fd_map[7]);
            // 区域表用量：表满之后新映射不再纳入野指针校验（审计 F42 的上限
            // 从 128 提到 512），这一行让"离写满还有多远"变成可观测量。
            fprintf(stderr, "[mlc][诊断] 区域表 %d/%d，镜像 %d，蹦桌已用 0x%llx\n",
                    g_region_n, G_REGION_MAX, g_nimg,
                    (unsigned long long)((uint64_t)g_tp_next - (uint64_t)g_tp_base));
            // 线程指针顶替次数：0 表示本次运行没有出现"客户机要写野 TPIDR_EL0"
            // 的情况（缺陷 K1 的观测口）。非 0 说明 macOS 遗留值确实被客户机
            // 读回去又写了出来，引擎已代为顶替。
            fprintf(stderr, "[mlc][诊断] TP 存根进入 %d 次，最后写入 0x%llx，有效 TCB 0x%llx，野值顶替 %d 次\n",
                    g_tp_writes, (unsigned long long)g_tp_last_write,
                    (unsigned long long)g_guest_tp_good, g_tp_fixups);
            fprintf(stderr, "[mlc][诊断] 补丁射程超限跳过 %d 处\n", g_patch_skipped);
            // K2 排查：客户机 TCB 若落在未登记区域，所有 TLS 访问（errno、栈保护值、
            // 指针保护值、DTV）都会被 guest_ptr_ok 判成非法指针，系统调用返回 -EFAULT，
            // glibc 内部状态随之错乱。TCB 落在哪里取决于客户机把 TLS 块映射到哪，
            // 而那是逐轮变化的。
            if (g_guest_tp_good) {
                int tpok = region_covers(g_guest_tp_good, g_guest_tp_good + 0x800);
                fprintf(stderr, "[mlc][诊断] 有效 TCB 0x%llx 及其后 2KB %s\n",
                        (unsigned long long)g_guest_tp_good,
                        tpok ? "在已登记区域内" : "不在已登记区域内（TLS 访问会被误判）");
            }
            // K2 探针：把每个镜像的动态链接元数据区（.gnu.hash 到 .rela.plt 末尾）
            // 从客户机内存原样 dump 出来，与 ELF 文件原文逐字节比对。
            // 之所以需要它：K2 的失败符号每次都不一样（calloc / crypt_r / _res /
            // _dl_argv / __libc_single_threaded），说明坏的是查表机制而不是某个符号，
            // 而查表机制的数据全在这段里。比对结果直接回答"内存里的表有没有被改"。
        }
                    const char *dd = getenv("MLC_DUMP_DIR");
            if (dd) {
                // 先把引擎自己登记的镜像 dump 一遍
                for (int i = 0; i < g_nimg; i++) {
                    image_t *m = &g_img[i];
                    Elf64_Ehdr *eh = (Elf64_Ehdr *)m->img;
                    if (!eh || memcmp(eh->e_ident, "\177ELF", 4) != 0) continue;
                    Elf64_Phdr *ph = (Elf64_Phdr *)(m->img + eh->e_phoff);
                    for (int k = 0; k < eh->e_phnum; k++) {
                        if (ph[k].p_type != PT_LOAD) continue;
                        if (!(ph[k].p_flags & 1)) continue;          // 只要可执行段
                        uint64_t lo = ph[k].p_vaddr, hi = lo + ph[k].p_filesz;
                        // 元数据节的文件区间：从 0x200 扫到可执行段末，覆盖
                        // .gnu.hash/.dynsym/.dynstr/.gnu.version*/.rela.*
                        uint64_t s = lo + 0x200, e = hi;
                        if (s >= e) continue;
                        char op[512];
                        const char *bn = strrchr(m->name, '/');
                        bn = bn ? bn + 1 : m->name;
                        snprintf(op, sizeof(op), "%s/%s.bin", dd, bn);
                        FILE *fo = fopen(op, "wb");
                        if (!fo) continue;
                        fwrite((void *)(uintptr_t)(m->mem + s), 1, (size_t)(e - s), fo);
                        fclose(fo);
                        fprintf(stderr, "[mlc][转储] %s 元数据 0x%llx-0x%llx -> %s\n",
                                bn, (unsigned long long)s, (unsigned long long)e, op);
                    }
                }
                // 再扫区域表：libc 一类库是 ld.so 自己 mmap 进来的，引擎没有登记成
                // 镜像，只在区域表里。全量 dump，事后再按 ELF 头定位各个库的表。
                // 之所以不能只 dump 以 ELF 开头的区间：客户机 munmap 掉预留区头部
                // 之后，region_add 的相邻合并会把区间起点并回到预留区基址，
                // 于是"区间起点"并不等于 ELF 头，按 \7fELF 过滤会漏掉真正的库。
                for (int i = 0; i < g_region_n; i++) {
                    uint64_t rs = g_region[i].start, re = g_region[i].end;
                    if (re <= rs) continue;
                    char op[512];
                    snprintf(op, sizeof(op), "%s/reg%02d.bin", dd, i);
                    FILE *fo = fopen(op, "wb");
                    if (!fo) continue;
                    fwrite((void *)(uintptr_t)rs, 1, (size_t)(re - rs), fo);
                    fclose(fo);
                    fprintf(stderr, "[mlc][转储] 区域 %d [0x%llx,0x%llx) -> %s\n",
                            i, (unsigned long long)rs, (unsigned long long)re, op);
                }
            }
        fflush(NULL);
        // CLONE_CHILD_CLEARTID：退出前把 child_tidptr 清成 0（Linux 内核语义）。
        // 只在与当初记下的值一致时才写，避免清掉别人后来写进去的东西。
        if (g_exit_cleartid && guest_ptr_ok(g_exit_cleartid, 4)) {
            if (*(int32_t *)g_exit_cleartid == g_exit_cleartid_val)
                *(int32_t *)g_exit_cleartid = 0;
            g_exit_cleartid = 0;
        }
        _exit((int)a0);
    }
    case SYS_getpid:        return getpid();
    case SYS_getppid:       return getppid();
    case SYS_getuid:        return getuid();
    case SYS_geteuid:       return geteuid();
    case SYS_getgid:        return getgid();
    case SYS_getegid:       return getegid();
    case SYS_gettid: {
        // 客户机 tid 要在本进程内唯一且稳定。曾直接返回 mach 线程端口号
        // （pthread_mach_thread_np）——那是内核对象名不是 tid，量级还与 getpid
        // 撞值，客户机若拿它做线程表索引会串号。改为进程内递增分配、每线程
        // 一份（审计 F45）。
        static __thread int tl_tid = 0;
        static unsigned tid_seq = 0;
        if (!tl_tid) tl_tid = (int)(__atomic_fetch_add(&tid_seq, 1u, __ATOMIC_RELAXED) + 1);
        return tl_tid;
    }
    case SYS_set_tid_address: {
        // 曾返回常量 4242。glibc 把这个返回值当线程号存下来，还会在它给的地址上
        // 写线程号；常量 4242 = 0x1092 正是排查偶发崩溃时反复见到的那个小地址段。
        // 现在按宿主持性返回真实 pid（单进程单线程，二者同值），地址原样记住（审计 F47）。
        g_tid_addr = (int *)a0;
        return getpid();
    }
    case SYS_set_robust_list: return 0;
    case SYS_clone: {
        // B7：客户机创建进程。只支持进程级用法，其余一律 ENOSYS（宁可诚实失败，
        // 也不要给出一个语义不符的成功）：
        //   a0 = 0x4111   = CLONE_VM|CLONE_VFORK|SIGCHLD     —— glibc posix_spawn
        //   a0 = 0x0011   = SIGCHLD                          —— 裸 fork
        //   a0 = 0x1200011= SIGCHLD|CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID
        //                 —— glibc 2.39 真正的 fork()。**这一条以前漏了**，
        //                 于是 dash 的命令替换 $(...)、反引号、管道、以及任何
        //                 带重定向的外部命令全都报 Cannot fork（退出码 2）。
        //                 它们与 posix_spawn 走的是两条不同的 clone 调用。
        // 其它带 CLONE_THREAD/CLONE_SETTLS/CLONE_NEWNS 等位的用法属多线程与命名
        // 空间，归 M3，当前没有实现也不假报成功。
        unsigned long flags = (unsigned long)a0;
        // 信号位：Linux 把退出信号放在 flags 的 bit 0-6，这里只接受 SIGCHLD(17)
        unsigned long sigbits = flags & 0xffUL;
        unsigned long rest   = flags & ~(0xffUL);
        int is_spawn = (flags == (CLONE_VM | CLONE_VFORK | 17UL));
        int is_fork  = (rest == 0UL && sigbits == 17UL)
                    || (rest == (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) && sigbits == 17UL);
        if (!is_spawn && !is_fork) {
            fprintf(stderr, "[mlc] clone：不支持的标志 0x%lx，返回 ENOSYS（多线程归 M3）\n", flags);
            return -L_ENOSYS;
        }
        // 父进程的蹦桌池此时可能停在「可写」状态（某次 patch_svc_in_range 异常
        // 返回），fork 之前先收尾成只读可执行，子进程才不会踩到半写状态。
        tp_finish_write();
        // CLONE_PARENT_SETTID 要求子进程把自己的 TID 写进 child_tidptr（a3）
        int do_child_settid = (flags & CLONE_PARENT_SETTID) && a3
                              && guest_ptr_ok(a3, 4);
        // CLONE_CHILD_CLEARTID 要求子进程退出时把 child_tidptr 清成 0
        int do_cleartid = (flags & CLONE_CHILD_CLEARTID) && a3
                          && guest_ptr_ok(a3, 4);
        pid_t pid = fork();
        if (pid < 0) return -errno;
        if (pid == 0) {
            // 子进程：诊断计数从零开始，蹦桌簿记按写时复制的现状继续用
            g_sc_total = 0;
            for (int i = 0; i < 512; i++) g_sc_by_nr[i] = 0;
            if (do_child_settid) *(int32_t *)a3 = (int32_t)getpid();
            if (do_cleartid) {
                g_exit_cleartid = (uint64_t)a3;
                g_exit_cleartid_val = *(int32_t *)a3;
            }
            return 0;
        }
        // CLONE_CHILD_SETTID 要求父进程把子进程 TID 写进 parent_tidptr（a2）
        if ((flags & CLONE_CHILD_SETTID) && a2 && guest_ptr_ok(a2, 4))
            *(int32_t *)a2 = (int32_t)pid;
        return (int64_t)pid;
    }
    case SYS_wait4: {
        // Linux: wait4(pid, &status, options, &rusage)。status 的编码与宿主不同：
        // Linux 把退出码放在 bits 8-15、终止信号放在 bits 0-6，BSD/macOS 用
        // WEXITSTATUS/WTERMSIG 宏各自的位。不翻译的话父进程读到的等待结果全错。
        int status = 0;
        int opts = 0;
        if (a2 & 0x00000001UL) opts |= WNOHANG;      // WNOHANG 两侧都是 1
        if (a2 & 0x00000008UL) opts |= WUNTRACED;    // WUNTRACED：Linux 2，宿主 2
        if (a1) {
            if (!guest_ptr_ok(a1, 4)) return -L_EFAULT;
        }
        pid_t r = waitpid((pid_t)a0, a1 ? &status : NULL, opts);
        if (r < 0) return -errno;
        if (a1) {
            int ls = 0;
            if (WIFEXITED(status))       ls = (WEXITSTATUS(status) & 0xff) << 8;
            else if (WIFSIGNALED(status)) ls = WTERMSIG(status) & 0x7f;
            else if (WIFSTOPPED(status))  ls = (WSTOPSIG(status) & 0xff) << 8 | 0x7f;
            *(int *)a1 = ls;
        }
        return (int64_t)r;
    }
    case SYS_execve: {
        // B7：替换当前镜像。只记录请求后 longjmp 回 main 的加载循环——
        // 从这里逐层返回客户机旧代码是错的（旧镜像马上就被换掉了）。
        if (!a0 || !guest_str_ok(a0, 4096)) return -L_EFAULT;
        snprintf(g_exec_path, sizeof(g_exec_path), "%s", (const char *)a0);
        g_exec_argc = 0;
        for (int i = 0; i < GUEST_EXEC_ARGC_MAX; i++) {
            if (!guest_ptr_ok(a1 + (uint64_t)i * 8, 8)) return -L_EFAULT;
            uint64_t s;
            memcpy(&s, (const void *)(a1 + (uint64_t)i * 8), 8);
            if (!s) break;
            if (!guest_str_ok(s, GUEST_EXEC_STR_MAX)) return -L_EFAULT;
            snprintf(g_exec_argv_buf[i], GUEST_EXEC_STR_MAX, "%s", (const char *)s);
            g_exec_argv[i] = g_exec_argv_buf[i];
            g_exec_argc++;
        }
        g_exec_envc = 0;
        for (int i = 0; i < GUEST_EXEC_ENVC_MAX; i++) {
            if (!guest_ptr_ok(a2 + (uint64_t)i * 8, 8)) return -L_EFAULT;
            uint64_t s;
            memcpy(&s, (const void *)(a2 + (uint64_t)i * 8), 8);
            if (!s) break;
            if (!guest_str_ok(s, GUEST_EXEC_STR_MAX)) return -L_EFAULT;
            snprintf(g_exec_envp_buf[i], GUEST_EXEC_STR_MAX, "%s", (const char *)s);
            g_exec_envp[i] = g_exec_envp_buf[i];
            g_exec_envc++;
        }
        g_exec_pending = 1;
        longjmp(g_exec_jmp, 1);
    }
    case SYS_rseq:          return -L_ENOSYS;
    case SYS_membarrier:    return 0;
    case SYS_futex:         return 0;              // v1：视为无竞争（L4，M3 多线程前必须实现）
    case SYS_sched_yield:   return 0;
    case SYS_sched_getaffinity: {
        // 返回一个全 CPU 掩码（最小长度 8 字节）
        if (a2 < 8) return -L_EINVAL;
        if (!guest_ptr_ok(a1, a2)) return -L_EFAULT;
        memset((void *)a1, 0xff, 8);
        return 8;
    }
    case SYS_getrandom: {
        if (!guest_ptr_ok(a0, a1)) return -L_EFAULT;
        arc4random_buf((void *)a0, (size_t)a1);
        return (int64_t)a1;
    }
    case SYS_uname:
        if (!guest_ptr_ok(a0, sizeof(l_utsname_t))) return -L_EFAULT;
        fill_utsname((l_utsname_t *)a0);
        return 0;
    case SYS_getcwd: {
        if (!guest_ptr_ok(a0, a1)) return -L_EFAULT;
        char *r = getcwd((char *)a0, (size_t)a1);
        if (!r) return -errno;
        return (int64_t)(strlen((char *)a0) + 1);
    }
    case SYS_chdir: {
        if (!guest_str_ok(a0, 4096)) return -L_EFAULT;
        char hpath[1024];
        if (guest_to_host_path((const char *)a0, hpath, sizeof(hpath)) < 0) return -L_ENAMETOOLONG_;
        return chdir(hpath) < 0 ? -errno : 0;
    }
    case SYS_fchdir: return fchdir(guest_fd_host((int)a0)) < 0 ? -errno : 0;
    case SYS_faccessat: {
        if (!guest_str_ok(a1, 4096)) return -L_EFAULT;
        char hpath[1024];
        if (guest_to_host_path((const char *)a1, hpath, sizeof(hpath)) < 0) return -L_ENAMETOOLONG_;
        int r = (a0 == -100) ? access(hpath, (int)a2)
                             : faccessat(guest_fd_host((int)a0), hpath, (int)a2, 0);
        return r < 0 ? -errno : 0;
    }
    case SYS_readlinkat: {
        // v1.2：ld.so 与 libc 会读 /proc/self/exe 找自身路径，返回客户机看到的可执行路径
        if (!guest_str_ok(a1, 4096)) return -L_EFAULT;
        const char *lp = (const char *)a1;
        if (strcmp(lp, "/proc/self/exe") == 0) {
            if (!guest_ptr_ok(a2, a3)) return -L_EFAULT;
            size_t n = strlen(g_execfn) + 1;
            if (n > a3) n = a3;
            memcpy((void *)a2, g_execfn, n);
            return (int64_t)n;
        }
        // F64（2026-11-06 实测，100% 复现）：原实现把 /proc/self/exe 以外的路径一律
        // 返回 ENOENT，于是任何含符号链接的目录 ls -l 全线失败、退出码 1
        // （/etc 2 处、/ 3 处、/usr/bin 23 处，与符号链接数严格相等）。
        // 改成翻译成宿主路径后调宿主 readlinkat，结果抄回客户机缓冲区。
        // Linux readlinkat 不补 NUL，返回值就是写进 buf 的字节数，这里照做。
        if (a3 > 65536) return -L_EINVAL;
        if (a3 && !guest_ptr_ok(a2, a3)) return -L_EFAULT;
        char hpath[1024];
        if (guest_to_host_path(lp, hpath, sizeof(hpath)) < 0) return -L_ENAMETOOLONG_;
        char *tmp = (char *)malloc(a3 ? (size_t)a3 : 1);
        if (!tmp) return -L_ENOMEM;
        int hdir = (a0 == (uint64_t)-100) ? AT_FDCWD : guest_fd_host((int)a0);
        ssize_t r = readlinkat(hdir, hpath, tmp, (size_t)a3);
        if (r < 0) { int e = errno; free(tmp); return -e; }
        memcpy((void *)a2, tmp, (size_t)r);
        free(tmp);
        return (int64_t)r;
    }
    case SYS_nanosleep:
    case SYS_clock_nanosleep: {
        // Linux 签名：nanosleep(req, rem)；clock_nanosleep(clockid, flags, req, rem)
        // v1.1 F10：旧实现把 clock_nanosleep 的 a1（flags）当 rem 解引用，会写坏调用方内存。
        uint64_t reqp = (nr == SYS_nanosleep) ? a0 : a2;
        uint64_t remp = (nr == SYS_nanosleep) ? a1 : a3;
        if (!guest_ptr_ok(reqp, 16)) return -L_EFAULT;
        if (remp && !guest_ptr_ok(remp, 16)) return -L_EFAULT;
        struct timespec req, rem;
        memcpy(&req, (void *)reqp, 16);
        int r = nanosleep(&req, &rem);
        if (r < 0 && remp) memcpy((void *)remp, &rem, 16);
        return r < 0 ? -errno : 0;
    }
    case SYS_clock_gettime: {
        // Linux: 0=REALTIME 1=MONOTONIC 4=MONOTONIC_RAW 7=BOOTTIME
        if (!guest_ptr_ok(a1, 16)) return -L_EFAULT;
        clockid_t cid = CLOCK_MONOTONIC;
        if (a0 == 0) cid = CLOCK_REALTIME;
        else if (a0 == 4) cid = CLOCK_MONOTONIC_RAW;
        struct timespec ts;
        clock_gettime(cid, &ts);
        ((struct timespec *)a1)->tv_sec = ts.tv_sec;
        ((struct timespec *)a1)->tv_nsec = ts.tv_nsec;
        return 0;
    }
    case SYS_kill:
    case SYS_tgkill:
        return 0;
    case SYS_prlimit64: {
        struct rlimit rl;
        int which = (int)a1;
        if (a2) {  // 设置
            if (!guest_ptr_ok(a2, 16)) return -L_EFAULT;
            struct rlimit n;
            n.rlim_cur = ((uint64_t *)a2)[0];
            n.rlim_max = ((uint64_t *)a2)[1];
            setrlimit(which, &n);
        }
        if (a3) {  // 读取
            if (!guest_ptr_ok(a3, 16)) return -L_EFAULT;
            if (getrlimit(which, &rl) < 0) return -errno;
            ((uint64_t *)a3)[0] = rl.rlim_cur;
            ((uint64_t *)a3)[1] = rl.rlim_max;
        }
        return 0;
    }
    case SYS_capget:
        if (a1 && !guest_ptr_ok(a1, 16)) return -L_EFAULT;
        if (a1) { memset((void *)a1, 0, 16); ((uint32_t *)a1)[0] = 0; }
        return 0;
    // bash 的作业控制初始化要这几个。getpgid 直接透传宿主（glibc 的 getpgrp 就是
    // getpgid(0) 的内联包装，所以 155 号是它真正的落点）；
    // rt_sigprocmask 透传 pthread_sigmask（屏蔽集合只在本进程内有意义）。
    // 169 是 gettimeofday 而不是 getpgrp——一开始按 getpgrp 实现，客户机每次取时间
    // 都拿到一个进程组号，属静默数据损坏，靠 trace 的实参形状才纠正过来（v1.2 F36）。
    case SYS_getpgid:
        return getpgid((pid_t)a0) < 0 ? -errno : getpgid((pid_t)a0);
    case SYS_gettimeofday: {
        if (!a0) return 0;
        if (!guest_ptr_ok(a0, 16)) return -L_EFAULT;
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) < 0) return -errno;
        int64_t *tv = (int64_t *)a0;
        tv[0] = (int64_t)ts.tv_sec;      // tv_sec
        tv[1] = (int64_t)ts.tv_nsec / 1000;   // tv_usec
        if (a1) { if (!guest_ptr_ok(a1, 8)) return -L_EFAULT; *(int32_t *)a1 = 0; }   // timezone：固定 UTC 偏移 0
        return 0;
    }
    case SYS_rt_sigprocmask: {
        // 第 4 个参数是 sigsetsize（8），不是指针；屏蔽集按 8 字节 memcpy，
        // 避免直接解引用可能未对齐的客户机指针
        if (!guest_ptr_ok(a2, 8)) return -L_EFAULT;
        sigset_t set, oldset;
        if (a1 && guest_ptr_ok(a1, 8)) {
            // macOS sigset_t 只有 4 字节位图，客户机 sigsetsize 是 8 字节。
            // 只搬低 4 字节（Linux 信号 1..32），高位清零：多搬会把客户机位图
            // 溢出到 macOS sigset_t 之外的内存上。
            uint32_t lo; memcpy(&lo, (void *)a1, 4);
            sigemptyset(&set);
            for (int b = 0; b < 32; b++) if (lo & (1u << b)) sigaddset(&set, b + 1);
        } else sigemptyset(&set);
        sigemptyset(&oldset);
        int r = pthread_sigmask((int)a0, a1 ? &set : NULL, &oldset);
        if (r == 0 && a2) {
            uint32_t lo = 0;
            for (int b = 0; b < 32; b++) if (sigismember(&oldset, b + 1)) lo |= (1u << b);
            memcpy((void *)a2, &lo, 4);
            memset((void *)(a2 + 4), 0, 4);
        }
        return r < 0 ? -errno : 0;
    }
    case SYS_sigaltstack: {
        // Linux aarch64 stack_t 布局：{void *ss_sp; int ss_flags; size_t ss_size;} 共 24 字节。
        // 关键：标志位取值两侧不同——Linux SS_ONSTACK=1/SS_DISABLE=2/SS_AUTODISARM=0x80000000，
        // macOS SS_DISABLE=4。所以这里按客户机布局自己解，不调宿主 sigaltstack。
        // 2026-11-06 审计 F46：原先返回 ENOSYS，实测有约 2% 的概率让 glibc 早期初始化
        // 把 TPIDR_EL0 写成 0x1006/0x1008 一类的野值，随后 errno 写入点崩在 NULL+0x9bf。
        // 崩溃点恒定在两次 sigaltstack 之后，补上本实现后复测三百次零复现。
        g_stack_t ns, old;
        if (a1) {
            if (!guest_ptr_ok(a1, 24)) return -L_EFAULT;
            memset(&old, 0, sizeof(old));
            if (g_altstack_set) {
                old.ss_sp = g_altstack.ss_sp; old.ss_flags = g_altstack.ss_flags;
                old.ss_size = g_altstack.ss_size;
            } else {
                old.ss_flags = 2;   // SS_DISABLE
            }
            memcpy((void *)a1, &old, 24);
        }
        if (a0) {
            if (!guest_ptr_ok(a0, 24)) return -L_EFAULT;
            memcpy(&ns, (void *)a0, 24);
            if (ns.ss_flags != 0 && ns.ss_flags != 2 && ns.ss_flags != (int32_t)0x80000000)
                return -L_EINVAL;
            if (ns.ss_flags == 2 || ns.ss_sp == 0) {
                g_altstack_set = 0;
                memset(&g_altstack, 0, sizeof(g_altstack));
            } else {
                if (ns.ss_size && !guest_ptr_ok(ns.ss_sp, ns.ss_size)) return -L_ENOMEM;
                g_altstack = ns; g_altstack_set = 1;
            }
        }
        return 0;
    }
    case SYS_rt_sigaction:
        // 假成功：只登记不投递。真实信号投递是整改清单 C4（M3），未做之前
        // bash/交互式程序拿到的"handler 已装"是假的——这里显式记录该取舍，
        // 不做成看似完整的实现。返回 0 是为了让 bash 的非交互用法能跑下去。
        if (a2 && !guest_ptr_ok(a2, 8)) return -L_EFAULT;
        if (a2) memset((void *)a2, 0, 8);
        return 0;
    case SYS_sysinfo: {
        // struct sysinfo 主要字段：uptime, loads[3], totalram, freeram, sharedram, bufferram,
        // totalswap, freeswap, procs, totalhigh, freehigh, mem_unit
        if (!guest_ptr_ok(a0, 112)) return -L_EFAULT;
        memset((void *)a0, 0, 112);
        *(uint64_t *)(a0 + 32) = 4096;   // mem_unit
        *(uint64_t *)(a0 + 16) = 64;     // procs
        return 0;
    }
    default:
        fprintf(stderr, "[mlc] 未实现的系统调用 nr=%llu (a0=%llx a1=%llx a2=%llx)\n",
                (unsigned long long)nr, (unsigned long long)a0,
                (unsigned long long)a1, (unsigned long long)a2);
        return -L_ENOSYS;
    }
}



static image_t *load_image2(const char *path, int from_high) {
    if (g_nimg >= MAX_IMAGES) die("镜像数超过上限（24）");
    image_t *im = &g_img[g_nimg];
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("无法打开客户机 ELF");
    struct stat st;
    if (fstat(fd, &st) < 0) die("无法读取 ELF 大小");
    uint8_t *img = mmap(NULL, page_up(st.st_size), PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (img == MAP_FAILED) die("无法分配镜像缓冲");
    if (read(fd, img, st.st_size) != st.st_size) die("读取 ELF 失败");
    close(fd);

    Elf64_Ehdr *eh = (Elf64_Ehdr *)img;
    if (memcmp(eh->e_ident, "\x7f""ELF", 4) != 0) die("不是 ELF 文件");
    if (eh->e_ident[4] != 2) die("不是 64 位 ELF");
    if (eh->e_machine != 0xB7) die("不是 AArch64 ELF (e_machine=0x%x)");
    Elf64_Phdr *ph = (Elf64_Phdr *)(img + eh->e_phoff);
    uint64_t lo = ~0ULL, hi = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
        if (ph[i].p_vaddr + ph[i].p_memsz > hi) hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    if (lo == ~0ULL) die("没有 PT_LOAD 段");
    uint64_t span = page_up(hi - lo);

    // body 从客户机窗口取，蹦桌进蹦桌池（统一架构）：
    // ld.so 按 phdr 推算主程序映射末端，若我们的映射多占 GAP+蹦桌，
    // 它的 MAP_FIXED 会落回我们映射内部而被保护区拒绝（v1.2 修）。
    // 先数本镜像可执行段里要拦的指令，蹦桌区随之定大小（紧随映射，同一次分配）。
    // 三类都拦：svc #0（0xD4000001）、msr TPIDR_EL0, xN（0xD51BD040|N，写线程指针）、
    // mrs xN, TPIDR_EL0（0xD53BD040|N，读线程指针）。后两类只有 ld.so 与 libc 一类
    // 的库有（全 rootfs 扫过），而它们正是走本函数与 patch_svc_in_range 加载的——
    // 漏了这里，K1 的线程指针校验就形同虚设。注意 0xD53BD040 是 mrs 不是 msr，
    // 这点 v1.4 排查时认错过，把 libc 的 1530 处读全当成写，白跑一圈。
    int nsvc = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X)) continue;
        uint32_t *s0 = (uint32_t *)(img + ph[i].p_offset);
        for (size_t j = 0; j < ph[i].p_filesz / 4; j++) {
            uint32_t v = s0[j];
            if (v == 0xD4000001u ||
                (v >= 0xD51BD040u && v <= 0xD51BD05Fu) ||
                (v >= 0xD53BD040u && v <= 0xD53BD05Eu)) nsvc++;
        }
    }
    const uint64_t TRAMP_GAP = 0x10000;
    uint64_t tramp_span = (uint64_t)(nsvc > 0 ? nsvc : 1) * ML_STUB_SLOT;
    uint64_t total = span + TRAMP_GAP + page_up(tramp_span);

    uint64_t body_at;
    if (eh->e_type == 3) {
        body_at = from_high ? win_alloc_high(total) : win_alloc(total);
        if (!body_at) die("客户机窗口不足，无法加载镜像");
        if (!from_high) {
            // 主程序落位后，把高端起点压到「主程序末端 + 间隙」，
            // interp 与其后所有库都在这段间隙上方活动，绝不会压回主程序
            uint64_t gap_end = body_at + total + COMPAT_LD_GAP;
            if (gap_end < (uint64_t)g_win_high) g_win_high = (uint8_t *)gap_end;
        }
    } else {
        body_at = page_down(lo);   // ET_EXEC：固有地址
    }
    uint64_t lbase = body_at - page_down(lo);
    im->img = img; im->mem = (uint8_t *)body_at; im->span = span; im->base = lbase; im->total = total;
    im->entry = lbase + eh->e_entry; im->phnum = eh->e_phnum;
    snprintf(im->name, sizeof(im->name), "%s", path);

    // 报大前先留底：mprotect、svc 扫描与段映射都必须用原始尺寸，
    // 否则报大后的第一个 LOAD 会盖住后续段，触发"保护不同"误判或扫进数据段
    uint64_t *orig_memsz = (uint64_t *)malloc((size_t)eh->e_phnum * sizeof(uint64_t));
    uint64_t *orig_filesz = (uint64_t *)malloc((size_t)eh->e_phnum * sizeof(uint64_t));
    if (!orig_memsz || !orig_filesz) die("内存不足");
    for (int i = 0; i < eh->e_phnum; i++) { orig_memsz[i] = ph[i].p_memsz; orig_filesz[i] = ph[i].p_filesz; }

    // 一次映射 span + 间隔 + 蹦桌区：蹦桌紧随本镜像，B 距离必然可及，
    // 且不会与 ld.so 后来映射的库抢地址（本镜像整体是保护区）
    if (mmap((void *)body_at, total, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0) == MAP_FAILED)
        die("无法映射客户机段（非 PIE 镜像请用基址重写引擎，见 docs/01）");
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        uint8_t *dst = (uint8_t *)(lbase + ph[i].p_vaddr);
        memcpy(dst, img + ph[i].p_offset, orig_filesz[i]);
        memset(dst + orig_filesz[i], 0, orig_memsz[i] - orig_filesz[i]);
    }
    region_add(body_at, body_at + span);   // M1：只登记客户机范围
    // 保护区只从 span 之后开始：客户机内容 [body_at, body_at+span) 是它自己的段，
    // glibc 收尾要对自己的 RELRO 发 mprotect，整块护住会把它挡成 ENOMEM
    // （v1.2 F33 修：ls 走到最后一步报 cannot apply additional memory protection）。
    // span 之后是间隔与蹦桌，那才是引擎自己的东西。
    guard_add(body_at + span, body_at + total);

    // phdr 在内存中的地址（auxv 的 AT_PHDR 用）；第一个 LOAD 通常 offset=0/vaddr=0
    im->phdr_addr = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD &&
            eh->e_phoff >= ph[i].p_offset &&
            eh->e_phoff + eh->e_phnum * eh->e_phentsize <= ph[i].p_offset + orig_filesz[i]) {
            im->phdr_addr = lbase + ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset);
            break;
        }
    }
    if (!im->phdr_addr) im->phdr_addr = lbase + eh->e_phoff;

    // 可执行段里的 svc #0 改 B 到本镜像蹦桌（每个 svc 一份副本，返回地址运行时修补）。
    // 同一遍还拦 msr TPIDR_EL0, xN，改走 mlc_tp_write_probe 校验写入值（缺陷 K1）。
    // 这一点关键：会写客户机线程指针的只有 ld.so，而 ld.so 正是走本函数加载的，
    // patch_svc_in_range 那条路（mmap/mprotect）永远扫不到它。
    int patched = 0;
    {
        uint64_t tramp_base = body_at + span + TRAMP_GAP;
        uint64_t handler = (uint64_t)(void *)&mlc_syscall_handler;
        uint32_t halves[4] = { (uint32_t)(handler & 0xFFFF), (uint32_t)((handler >> 16) & 0xFFFF),
                               (uint32_t)((handler >> 32) & 0xFFFF), (uint32_t)((handler >> 48) & 0xFFFF) };
        uint64_t tpfn = (uint64_t)(void *)&mlc_tp_write_probe;
        uint32_t tphalves[4] = { (uint32_t)(tpfn & 0xFFFF), (uint32_t)((tpfn >> 16) & 0xFFFF),
                                 (uint32_t)((tpfn >> 32) & 0xFFFF), (uint32_t)((tpfn >> 48) & 0xFFFF) };
        uint64_t tpgood = (uint64_t)(void *)&g_guest_tp_good;
        uint32_t tghalves[4] = { (uint32_t)(tpgood & 0xFFFF), (uint32_t)((tpgood >> 16) & 0xFFFF),
                                 (uint32_t)((tpgood >> 32) & 0xFFFF), (uint32_t)((tpgood >> 48) & 0xFFFF) };
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X)) continue;
            uint32_t *svc = (uint32_t *)(lbase + ph[i].p_vaddr);
            size_t n = orig_filesz[i] / 4;
            for (size_t j = 0; j < n; j++) {
                uint32_t v = svc[j];
                int is_svc = (v == 0xD4000001u);
                int is_msr_tp = (v >= 0xD51BD040u && v <= 0xD51BD05Fu);
                int is_mrs_tp = (v >= 0xD53BD040u && v <= 0xD53BD05Eu);
                if (!is_svc && !is_msr_tp && !is_mrs_tp) continue;
                uint64_t stub = tramp_base + (uint64_t)patched * ML_STUB_SLOT;
                uint32_t *t = (uint32_t *)stub;
                int nwords_stub;
                if (is_svc) {
                    memcpy(t, ML_STUB, sizeof(ML_STUB));
                    nwords_stub = ML_STUB_WORDS;
                    for (int h = 0; h < 4; h++)
                        t[21 + h] = (t[21 + h] & ~(0xFFFFU << 5)) | ((halves[h] & 0xFFFF) << 5);
                } else if (is_msr_tp) {
                    memcpy(t, ML_TP_STUB, sizeof(ML_TP_STUB));
                    nwords_stub = ML_TP_STUB_WORDS;
                    // 参数 2 = 被写寄存器下标（movz w1, #N）
                    t[ML_TP_STUB_IDX_N] = 0x52800001u | ((v & 31u) << 5);
                    for (int h = 0; h < 4; h++)
                        t[ML_TP_STUB_IDX_FN + h] =
                            (t[ML_TP_STUB_IDX_FN + h] & ~(0xFFFFU << 5)) | ((tphalves[h] & 0xFFFF) << 5);
                } else {
                    memcpy(t, ML_MRS_STUB, sizeof(ML_MRS_STUB));
                    nwords_stub = ML_MRS_STUB_WORDS;
                    for (int h = 0; h < 4; h++)
                        t[ML_MRS_STUB_IDX_ADDR + h] =
                            (t[ML_MRS_STUB_IDX_ADDR + h] & ~(0xFFFFU << 5)) | ((tghalves[h] & 0xFFFF) << 5);
                    t[ML_MRS_STUB_IDX_DST] = 0xAA0903E0u | (v & 31u);
                    if ((v & 31u) == 9u) t[ML_MRS_STUB_IDX_X9REST] = AARCH64_NOP;
                }
                int64_t to_stub = (int64_t)stub - (int64_t)&svc[j];
                int64_t to_ret  = (int64_t)(&svc[j] + 1) - (int64_t)(stub + (nwords_stub - 1) * 4);
                if (to_stub > 0x08000000LL || to_stub < -0x08000000LL ||
                    to_ret  > 0x08000000LL || to_ret  < -0x08000000LL)
                    die("svc/msr 与蹦桌距离超出 B ±128MB 范围（审计 L2）");
                svc[j] = 0x14000000u | ((uint32_t)(to_stub / 4) & 0x03FFFFFFu);
                uint32_t *bret = (uint32_t *)(stub + (nwords_stub - 1) * 4);
                bret[0] = 0x14000000u | ((uint32_t)(to_ret / 4) & 0x03FFFFFFu);
                patched++;
            }
        }
        im->tramp = tramp_base;
        // 最后才设蹦桌 RX（F01 顺序教训）
        if (nsvc && mprotect((void *)page_down(tramp_base), page_up(tramp_span),
                             PROT_READ | PROT_EXEC) < 0)
            die("蹦桌 mprotect 失败");
    }
    fprintf(stderr, "[mlc] 加载 %s：基址 0x%llx，跨度 %llu，入口 0x%llx，拦截 %d 处"
                    "（svc + msr/mrs TPIDR_EL0）\n",
            im->name, (unsigned long long)lbase, (unsigned long long)span,
            (unsigned long long)im->entry, patched);

    // 按段 mprotect（先写完再设保护，F01），并做宿主 16K 页重叠检测（F05）
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        int hprot = PROT_READ;
        if (ph[i].p_flags & PF_W) hprot |= PROT_WRITE;
        if (ph[i].p_flags & PF_X) hprot |= PROT_EXEC;
        uint64_t pstart = page_down(lbase + ph[i].p_vaddr);
        uint64_t pend   = page_up(lbase + ph[i].p_vaddr + orig_memsz[i]);   // 用原始 memsz
        for (int k = 0; k < i; k++) {
            if (ph[k].p_type != PT_LOAD) continue;
            uint64_t ks = page_down(lbase + ph[k].p_vaddr);
            uint64_t ke = page_up(lbase + ph[k].p_vaddr + orig_memsz[k]);   // 用原始 memsz
            if (pstart < ke && ks < pend) {
                int kprot = PROT_READ | (ph[k].p_flags & PF_W ? PROT_WRITE : 0)
                                       | (ph[k].p_flags & PF_X ? PROT_EXEC : 0);
                if (kprot != hprot)
                    die("两个段落入同一宿主 16K 页且保护不同：请用 -Wl,-z,max-page-size=16384 重新链接");
            }
        }
        if (mprotect((void *)pstart, pend - pstart, hprot) < 0)
            die("mprotect 客户机段失败");
    }

    free(orig_memsz); free(orig_filesz);
    g_nimg++;
    return im;
}

static image_t *load_image(const char *path) { return load_image2(path, 0); }

// 包装层：打印调用与返回值。没有返回值就分不清"崩在调用后"还是"返回值不对"。
// 返回值用十六进制：十进制要靠心算换算，B6 排查时已经因此误判过一次。
static int64_t mlc_syscall_handler(uint64_t *regs) {
    g_sc_total++;
    if (regs[REG_X8] < 512) g_sc_by_nr[regs[REG_X8]]++;
    // 兼记有效客户机 TCB：msr TPIDR_EL0 写入点已由 mlc_tp_write_probe 记录，
    // 这里再兜一层——万一将来有别的路径设了线程指针（或写入点漏拦），
    // 顶替时手里仍有可用的值。判据与 TP_PLAUSIBLE_MIN 相同。
    if (regs[REG_TPIDR] >= TP_PLAUSIBLE_MIN) g_guest_tp_good = regs[REG_TPIDR];
    // 把被 macOS 冲掉的客户机线程指针救回来（缺陷 K1 的收口）。
    // 实测：客户机只在 ld.so 启动期写一次 TPIDR_EL0（全 rootfs 扫过，msr 只有
    // ld.so 两处，运行期只进入其中一处），写的是有效 TCB；但运行到 prlimit64
    // 与 munmap 之间，TPIDR_EL0 会变成 0x1006 一类的小值——那是 macOS libSystem
    // 自己的线程槽位遗留值，它在我们的宿主调用里把它写进去，蹦桌随后虽然还原，
    // 却挡不住它在两次系统调用之间被再写一次。客户机接着 mrs TPIDR_EL0 拿到小值，
    // libc 的 __libc_start_main 尾部就以 TP-0x648 为地址访问 TCB，SIGSEGV。
    // 这里在每次系统调用入口核对一次：保存块里的值是野的，就换成有效 TCB，
    // 蹦桌出口的 msr tpidr_el0 于是写回有效值。两次系统调用之间的窗口由
    // mlc_tp_write_probe 那条路兜（客户机自己写野值时顶替）。
    if (regs[REG_TPIDR] < TP_PLAUSIBLE_MIN && g_guest_tp_good) {
        if (g_tp_fixups < 8)
            fprintf(stderr,
                    "[mlc][警告] 系统调用 nr=%llu 入口客户机 TPIDR_EL0 是野值 0x%llx，换成有效 TCB 0x%llx\n",
                    (unsigned long long)regs[REG_X8], (unsigned long long)regs[REG_TPIDR],
                    (unsigned long long)g_guest_tp_good);
        else if (g_tp_fixups == 8)
            fprintf(stderr, "[mlc][警告] 后续同类顶替不再逐次打印，累计次数见退出诊断\n");
        g_tp_fixups++;
        g_tp_last_write = g_guest_tp_good;
        regs[REG_TPIDR] = g_guest_tp_good;
    }
    // 探针（MLC_TP_TRACE=1 开启）：stub.s 把客户机 TPIDR_EL0 存在保存块里，
    // 即 regs[REG_TPIDR]（v5 布局下标 31）。缺陷 K1 排查期用它逐次打印线程指针
    // 的变化，用来定位「哪一次系统调用把它弄丢的」。修复后保留作回归工具。
    static uint64_t last_tp = 0;
    static int tp_trace = -1;
    if (tp_trace < 0) { const char *e = getenv("MLC_TP_TRACE"); tp_trace = e ? atoi(e) : 0; }
    if (tp_trace) {
        uint64_t tp = regs[REG_TPIDR];
        if (tp_trace >= 2 || tp != last_tp) {
            fprintf(stderr, "[mlc][tp] nr=%llu 客户机 TPIDR_EL0 0x%llx -> 0x%llx\n",
                    (unsigned long long)regs[REG_X8],
                    (unsigned long long)last_tp, (unsigned long long)tp);
            last_tp = tp;
        }
    }
    static int trace = -1;
    if (trace < 0) trace = getenv("MLC_DEBUG") ? 1 : 0;
    // K2 排查：MLC_DEBUG=1 时 perl 的符号查找失败率从约五成降到 0，而 MLC_DEBUG
    // 只控制打印。这里用一个纯粹消耗 CPU 的探针验证「是不是时序」：
    // 若 MLC_SLOW 也能把失败率打到 0，说明失败由时序决定，与打印内容无关。
    if (getenv("MLC_SLOW")) {
        volatile uint64_t acc = 0;
        for (int k = 0; k < 20000; k++) acc += (uint64_t)k * 2654435761u;
    }
    int64_t r = mlc_syscall_handler_impl(regs);
    // K1 排查：regs[REG_TPIDR] 此刻就是蹦桌出口 msr tpidr_el0 将要写回的值。
    // 崩溃时把它与现场读到的 TPIDR_EL0 对比：相等说明翻野发生在最后一次系统调用
    // 之后的纯客户机代码里；不相等说明蹦桌的还原本身就漏了。
    g_tp_last_restored = regs[REG_TPIDR];
    g_sc_last_nr = regs[REG_X8];
    // 出口探针：此时 stub.s 的 msr tpidr_el0 还原还没执行（它在 blr 返回之后），
    // 所以这里读到的是「宿主调用之后」的值。若它不等于入口的保存值，
    // 说明宿主 libSystem 在我们清零之后自己写了 TPIDR_EL0。
    if (tp_trace == 2) {
        uint64_t now = 0;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(now));
        fprintf(stderr, "[mlc][tp-out] nr=%llu 宿主调用后 TPIDR_EL0=0x%llx\n",
                (unsigned long long)regs[REG_X8], (unsigned long long)now);
    }
    if (trace) {
        fprintf(stderr, "[mlc] 系统调用 nr=%llu x0=%llx x1=%llx x2=%llx -> %llx\n",
                (unsigned long long)regs[REG_X8], (unsigned long long)regs[0],
                (unsigned long long)regs[1], (unsigned long long)regs[2],
                (unsigned long long)(uint64_t)r);
        // K2 排查用：openat/newfstatat/readlinkat 的路径参数是客户机指针，
        // 只看 x1 的数值认不出加载的是哪个库，补一条翻译后的宿主路径。
        uint64_t nr2 = regs[REG_X8];
        if (nr2 == 56 || nr2 == 79 || nr2 == 78) {
            const char *gp = (const char *)(uintptr_t)regs[1];
            if (guest_str_ok((uint64_t)(uintptr_t)gp, 4096)) {
                char hp[1024];
                if (guest_to_host_path(gp, hp, sizeof(hp)) == 0)
                    fprintf(stderr, "[mlc][路径] nr=%llu %s\n",
                            (unsigned long long)nr2, hp);
            }
        }
    }
    return r;
}

// ---------- 主流程 ----------
static uint8_t *g_load_base, *g_load_end;

// 信号处理里读客户机内存必须自己兜住（2026-11-07，缺陷 K3）。
// 原来 crash_handler 直接解引用 pc-8、pc-4、pc+4，而 glibc 的 _dl_map_segments
// 会给段间对齐填充发 mprotect(PROT_NONE)，pc 恰好在段首时前两条就在那种页里。
// 一读就二次故障，同一信号在处理器里反复重入，进程在 100% CPU 上原地打转，
// 永远走不到末尾的 _exit(99)。实测抓到两个这样的进程，一个已经跑了 11.5 小时、
// 烧掉 414 分钟 CPU；本机负载因此长期挂在 3.5 以上，同期所有失败率测量都被污染。
// 现在按区域表先判可读性，不可读就返回一个不可能是指令的哨兵值，
// 由调用方换成「不可读」字样。判据用区域表而不是 mprotect 试探：
// 信号处理里不能再抛异常，试探本身就会二次故障。
static uint32_t crash_rd32(uint64_t a) {
    for (int i = 0; i < g_region_n; i++)
        if (a >= g_region[i].start && a + 4 <= g_region[i].end)
            return *(uint32_t *)(uintptr_t)a;
    return 0xFFFFFFFFu;   // AArch64 未分配空间，任何真指令都不可能是它
}
#define CRASH_UNREADABLE 0xFFFFFFFFu

static void crash_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    // 兜底：第一件事就是把同一信号改回默认动作。crash_rd32 已经挡住了已知的
    // 二次故障路径，但信号处理里读客户机内存这件事本身没有通用安全保证——
    // 万一还有漏网的解引用，默认动作会让进程立刻终止，而不是让同一个信号在
    // 处理器里反复重入、100% CPU 原地打转且永远到不了 _exit（缺陷 K3）。
    // 代价是这种"处理器里的二次故障"拿不到完整诊断，但它本来也拿不到。
    signal(sig, SIG_DFL);
    uint64_t pc = (uint64_t)uc->uc_mcontext->__ss.__pc;
    uint64_t fa = (uint64_t)info->si_addr;
    // 客户机 TLS 指针：glibc 靠它找 TCB，值不对时 errno 写入点就是 NULL+小偏移。
    // 排查动态链接偶发崩溃时靠这一行定性（2026-11-06 实测抓到过 0x1006/0x1008 这类野值）。
    { uint64_t _tp = 0; __asm__ volatile("mrs %0, tpidr_el0" : "=r"(_tp));
      fprintf(stderr, "[mlc][崩溃] 客户机 TPIDR_EL0=0x%llx\n", (unsigned long long)_tp); }
    // 这一行必须打在崩溃现场而不是只在 exit_group 诊断里：崩溃的进程经 _exit(99)
    // 出去，永远走不到 exit 那条路，于是"野值到底有没有被顶替过"在出事的运行里
    // 反而是看不见的（K1 排查期因此误判过一轮）。
    fprintf(stderr, "[mlc][崩溃] TP 存根进入 %d 次，最后写入 0x%llx，有效 TCB 0x%llx，野值顶替 %d 次\n",
            g_tp_writes, (unsigned long long)g_tp_last_write,
            (unsigned long long)g_guest_tp_good, g_tp_fixups);
    fprintf(stderr, "[mlc][崩溃] 蹦桌末次还原 0x%llx（系统调用 nr=%llu）\n",
            (unsigned long long)g_tp_last_restored, (unsigned long long)g_sc_last_nr);
    fprintf(stderr, "[mlc][崩溃] 信号 %d 故障地址 %p PC=0x%llx LR=0x%llx SP=0x%llx\n",
            sig, info->si_addr, (unsigned long long)pc,
            (unsigned long long)uc->uc_mcontext->__ss.__lr,
            (unsigned long long)uc->uc_mcontext->__ss.__sp);
    // B6：故障地址到底归谁。没有这张表就只能猜"是不是被 munmap 多卸了"。
    int covered = 0;
    for (int i = 0; i < g_region_n; i++) {
        if (fa >= g_region[i].start && fa < g_region[i].end) { covered = 1; break; }
    }
    fprintf(stderr, "[mlc][崩溃] 故障地址 0x%llx 在客户机区域表内=%s（共 %d 段）\n",
            (unsigned long long)fa, covered ? "是" : "否", g_region_n);
    for (int i = 0; i < g_region_n; i++)
        fprintf(stderr, "[mlc][崩溃]   区域 [0x%llx,0x%llx)\n",
                (unsigned long long)g_region[i].start, (unsigned long long)g_region[i].end);
    for (int i = 0; i < g_nimg; i++)
        fprintf(stderr, "[mlc][崩溃]   镜像 %s 宿主 [0x%llx,0x%llx) 客户机基址 0x%llx\n",
                g_img[i].name, (unsigned long long)(uintptr_t)g_img[i].mem,
                (unsigned long long)((uintptr_t)g_img[i].mem + g_img[i].total),
                (unsigned long long)g_img[i].base);
    fprintf(stderr, "[mlc][崩溃]   蹦桌池 [0x%llx,0x%llx) 已用到 0x%llx，窗口 [0x%llx,0x%llx) 游标 low=0x%llx high=0x%llx\n",
            (unsigned long long)(uintptr_t)g_tp_base, (unsigned long long)(uintptr_t)g_tp_end,
            (unsigned long long)(uintptr_t)g_tp_next,
            (unsigned long long)(uintptr_t)g_win_base, (unsigned long long)(uintptr_t)g_win_end,
            (unsigned long long)(uintptr_t)g_win_low, (unsigned long long)(uintptr_t)g_win_high);
    // 故障指令与所在宿主页的真实权限：只有这两项能把"多卸了"与"被 PROT_NONE 了"
    // 区分开，否则 B6 只能靠猜。四处取值都经 crash_rd32 兜住——pc 落在段首时，
    // 前两条在 glibc 发的 PROT_NONE 对齐填充页里，直接解引用会让处理器自己二次
    // 故障并反复重入，进程 100% CPU 打转、永远到不了 _exit（缺陷 K3）。
    {
        char line[256];
        int n = 0;
        n += snprintf(line + n, sizeof(line) - n, "[mlc][崩溃] 故障指令");
        uint32_t v[4]; uint64_t a[4];
        v[0] = crash_rd32(pc);     a[0] = pc;
        v[1] = crash_rd32(pc - 4); a[1] = pc - 4;
        v[2] = crash_rd32(pc - 8); a[2] = pc - 8;
        v[3] = crash_rd32(pc + 4); a[3] = pc + 4;
        for (int k = 0; k < 4; k++) {
            if (n >= (int)sizeof(line) - 32) break;
            if (v[k] == CRASH_UNREADABLE)
                n += snprintf(line + n, sizeof(line) - n, " 0x%llx=不可读", (unsigned long long)a[k]);
            else
                n += snprintf(line + n, sizeof(line) - n, " 0x%llx=%08x",
                              (unsigned long long)a[k], v[k]);
        }
        snprintf(line + n, sizeof(line) - n, "\n");
        fputs(line, stderr);
    }
    // 全部通用寄存器：野指针是从哪个值算出来的，只有寄存器全表能回答
    {
        const uint64_t *g = (const uint64_t *)&uc->uc_mcontext->__ss.__x[0];
        fprintf(stderr, "[mlc][崩溃] x0=%016llx x1=%016llx x2=%016llx x3=%016llx\n",
                (unsigned long long)g[0], (unsigned long long)g[1],
                (unsigned long long)g[2], (unsigned long long)g[3]);
        fprintf(stderr, "[mlc][崩溃] x4=%016llx x5=%016llx x6=%016llx x7=%016llx\n",
                (unsigned long long)g[4], (unsigned long long)g[5],
                (unsigned long long)g[6], (unsigned long long)g[7]);
        fprintf(stderr, "[mlc][崩溃] x8=%016llx x9=%016llx x10=%016llx x11=%016llx\n",
                (unsigned long long)g[8], (unsigned long long)g[9],
                (unsigned long long)g[10], (unsigned long long)g[11]);
        fprintf(stderr, "[mlc][崩溃] x12=%016llx x13=%016llx x14=%016llx x15=%016llx\n",
                (unsigned long long)g[12], (unsigned long long)g[13],
                (unsigned long long)g[14], (unsigned long long)g[15]);
        fprintf(stderr, "[mlc][崩溃] x16=%016llx x17=%016llx x18=%016llx x19=%016llx\n",
                (unsigned long long)g[16], (unsigned long long)g[17],
                (unsigned long long)g[18], (unsigned long long)g[19]);
        fprintf(stderr, "[mlc][崩溃] x20=%016llx x21=%016llx x22=%016llx x23=%016llx\n",
                (unsigned long long)g[20], (unsigned long long)g[21],
                (unsigned long long)g[22], (unsigned long long)g[23]);
        fprintf(stderr, "[mlc][崩溃] x24=%016llx x25=%016llx x26=%016llx x27=%016llx\n",
                (unsigned long long)g[24], (unsigned long long)g[25],
                (unsigned long long)g[26], (unsigned long long)g[27]);
        fprintf(stderr, "[mlc][崩溃] x28=%016llx x29=%016llx x30=%016llx\n",
                (unsigned long long)g[28], (unsigned long long)g[29],
                (unsigned long long)uc->uc_mcontext->__ss.__lr);
    }
    {
        mach_vm_address_t qa = (mach_vm_address_t)(fa & ~0x3FFFULL);
        mach_vm_size_t qs = 0;
        vm_region_basic_info_data_64_t ri;
        mach_msg_type_number_t cn = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = 0;
        if (mach_vm_region(mach_task_self(), &qa, &qs, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&ri, &cn, &obj) == KERN_SUCCESS)
            fprintf(stderr, "[mlc][崩溃] 故障页所在宿主区域 [0x%llx,0x%llx) prot=%d max_prot=%d\n",
                    (unsigned long long)qa, (unsigned long long)(qa + qs),
                    ri.protection, ri.max_protection);
        else
            fprintf(stderr, "[mlc][崩溃] 故障页 0x%llx 无宿主区域（已被卸载）\n",
                    (unsigned long long)(fa & ~0x3FFFULL));
    }
    if (sig == SIGSYS) {
        uint32_t c0 = crash_rd32(pc), cp1 = crash_rd32(pc + 4);
        fprintf(stderr, "[mlc][崩溃] SIGSYS：客户机执行了未拦截的 svc #0。故障指令=%s 下一条=%s\n",
                c0 == CRASH_UNREADABLE ? "不可读" : "见下一行",
                cp1 == CRASH_UNREADABLE ? "不可读" : "见下一行");
        if (c0 != CRASH_UNREADABLE)
            fprintf(stderr, "[mlc][崩溃] 故障指令 %08x\n", c0);
        if (cp1 != CRASH_UNREADABLE)
            fprintf(stderr, "[mlc][崩溃] 下一条 %08x\n", cp1);
        for (int i = 0; i < g_nimg; i++) {
            uint64_t bs = (uint64_t)g_img[i].mem, be = bs + g_img[i].span;
            if (pc >= bs && pc < be)
                fprintf(stderr, "[mlc][崩溃] 位于镜像 %s 内偏移 0x%llx\n",
                        g_img[i].name, (unsigned long long)(pc - g_img[i].base));
        }
    }
    // 残留 msr TPIDR_EL0 扫描（MLC_TP_SCAN=1）：K1 排查用。
    // 已知野值只可能由 msr TPIDR_EL0, xN 写出来，而全 rootfs 816 个 ELF 静态
    // 扫描只有 ld.so 两处（都已修补）。若这里还能扫到，说明有站点漏拦——那就是根因。
    // 只扫 PC 所在区域与前后各 64KB：PC 一定落在已映射内存里，不会在信号处理里二次崩溃。
    if (getenv("MLC_TP_SCAN")) {
        int found = 0;
        uint64_t lo = (pc > 0x10000) ? pc - 0x10000 : 0x1000;
        uint64_t hi = pc + 0x10000;
        for (int i = 0; i < g_region_n; i++) {
            uint64_t s = g_region[i].start, e = g_region[i].end;
            if (e <= lo || s >= hi) continue;
            uint64_t a = (s > lo) ? s : lo, b = (e < hi) ? e : hi;
            a &= ~3ULL; b &= ~3ULL;
            for (uint64_t p = a; p + 4 <= b; p += 4) {
                uint32_t w = *(uint32_t *)p;
                if (w >= 0xD51BD040u && w <= 0xD51BD05Fu) {
                    if (found < 16)
                        fprintf(stderr, "[mlc][崩溃] 残留 msr TPIDR_EL0 @0x%llx enc=%08x\n",
                                (unsigned long long)p, w);
                    found++;
                }
            }
        }
        fprintf(stderr, "[mlc][崩溃] PC 前后 64KB 内残留 msr TPIDR_EL0 共 %d 处\n", found);
    }
    _exit(99);
}


// ---------- 看门狗诊断（MLC_WATCHDOG=秒数）----------
// 死循环时 CPU 100% 且不再有系统调用，trace 完全看不到卡点。
// 看门狗在超时时直接读故障线程的 PC，并报告它落在哪个镜像或蹦床里。
static void watchdog_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig; (void)info;
    ucontext_t *uc = (ucontext_t *)ctx;
    uint64_t pc = uc->uc_mcontext->__ss.__pc;
    uint64_t lr = uc->uc_mcontext->__ss.__lr;
    const char *where = "未知区域（宿主自身或已卸载映射）";
    char buf[256];
    for (int i = 0; i < g_nimg; i++) {
        uint64_t s = (uint64_t)g_img[i].mem, e = s + g_img[i].span;
        if (pc >= s && pc < e) { where = g_img[i].name; break; }
        if (pc >= g_img[i].tramp && pc < g_img[i].tramp + 0x4000) {
            snprintf(buf, sizeof(buf), "%s 的系统调用蹦床", g_img[i].name);
            where = buf; break;
        }
    }
    fprintf(stderr, "[mlc][看门狗] 超时未退出。PC=0x%llx（%s）LR=0x%llx\n",
            (unsigned long long)pc, where, (unsigned long long)lr);
    // 打印通用寄存器：死循环无系统调用，只能靠寄存器推断循环变量
    fprintf(stderr, "[mlc][看门狗] x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx\n",
            (unsigned long long)uc->uc_mcontext->__ss.__x[0],
            (unsigned long long)uc->uc_mcontext->__ss.__x[1],
            (unsigned long long)uc->uc_mcontext->__ss.__x[2],
            (unsigned long long)uc->uc_mcontext->__ss.__x[3],
            (unsigned long long)uc->uc_mcontext->__ss.__x[4]);
    fprintf(stderr, "[mlc][看门狗] x19=%llx x20=%llx x21=%llx x22=%llx x23=%llx x24=%llx x25=%llx x26=%llx x27=%llx x28=%llx\n",
            (unsigned long long)uc->uc_mcontext->__ss.__x[19],
            (unsigned long long)uc->uc_mcontext->__ss.__x[20],
            (unsigned long long)uc->uc_mcontext->__ss.__x[21],
            (unsigned long long)uc->uc_mcontext->__ss.__x[22],
            (unsigned long long)uc->uc_mcontext->__ss.__x[23],
            (unsigned long long)uc->uc_mcontext->__ss.__x[24],
            (unsigned long long)uc->uc_mcontext->__ss.__x[25],
            (unsigned long long)uc->uc_mcontext->__ss.__x[26],
            (unsigned long long)uc->uc_mcontext->__ss.__x[27],
            (unsigned long long)uc->uc_mcontext->__ss.__x[28]);
    fprintf(stderr, "[mlc][看门狗] handler 累计 %llu 次，munmap %llu 次，mmap %llu 次，write %llu 次，mprotect %llu 次\n",
            (unsigned long long)g_sc_total,
            (unsigned long long)g_sc_by_nr[215], (unsigned long long)g_sc_by_nr[222],
            (unsigned long long)g_sc_by_nr[64], (unsigned long long)g_sc_by_nr[226]);
    _exit(88);
}

// ---------- 信号监听（MLC_SIG_LOG=1，K1 排查）----------
// K1 的未解之处：蹦桌在最后一次系统调用出口把有效 TCB 写回了 TPIDR_EL0，
// 之后只剩客户机代码在跑，而全 rootfs 816 个 ELF 里只有 ld.so 两处
// msr TPIDR_EL0 且都已修补——客户机代码不可能写它。剩下的唯一能让宿主代码
// 在两个系统调用之间插进来的机制就是信号。这里把所有可捕获信号都记下来，
// 用来看崩溃前到底有没有信号到达、到达的是哪一个。
static void sig_log_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *)ctx;
    uint64_t tp = 0;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    fprintf(stderr, "[mlc][信号] 收到 %d，PC=0x%llx TPIDR_EL0=0x%llx si_addr=%p\n",
            sig, (unsigned long long)uc->uc_mcontext->__ss.__pc,
            (unsigned long long)tp, info ? info->si_addr : NULL);
}

int main(int argc, char **argv) {
    // stderr 必须是裸写的：诊断要经 _exit() 退出，任何缓冲都会在退出时丢掉
    setbuf(stderr, NULL);
    struct sigaction sa = {0};
    sa.sa_sigaction = crash_handler; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL); sigaction(SIGSEGV, &sa, NULL);
    // SIGSYS：客户机执行了未被拦截的 svc #0。打 PC 与故障指令，用来定位漏拦位置
    sigaction(SIGSYS, &sa, NULL); sigaction(SIGILL, &sa, NULL);
    if (getenv("MLC_SIG_LOG")) {
        struct sigaction la = {0};
        la.sa_sigaction = sig_log_handler; la.sa_flags = SA_SIGINFO;
        for (int s = 1; s <= 31; s++) {
            if (s == SIGSEGV || s == SIGBUS || s == SIGILL || s == SIGSYS ||
                s == SIGALRM || s == SIGKILL || s == SIGSTOP) continue;
            sigaction(s, &la, NULL);
        }
        fprintf(stderr, "[mlc] 信号监听已启用\n");
    }
    if (getenv("MLC_WATCHDOG")) {
        struct sigaction wa = {0};
        wa.sa_sigaction = watchdog_handler; wa.sa_flags = SA_SIGINFO;
        sigaction(SIGALRM, &wa, NULL);
        alarm((unsigned)atoi(getenv("MLC_WATCHDOG")));
        fprintf(stderr, "[mlc] 看门狗已启用：%s 秒\n", getenv("MLC_WATCHDOG"));
    }
    if (argc < 2) {
        fprintf(stderr, "用法: %s <linux-arm64-ELF（静态或动态）> [参数...]\n", argv[0]);
        return 2;
    }
    const char *guest_path = argv[1];
    rootfs_init(argv[0]);
    compat_window_init();
    snprintf(g_execfn, sizeof(g_execfn), "%s", guest_path);
    fprintf(stderr, "[mlc] rootfs 前缀: %s\n", g_rootfs);

    // 1. 加载主镜像
    // execve 会 longjmp 回这里形成循环：首次加载 guest_path，之后每次加载
    // sys_execve 记下的 g_exec_path。fd 表只在首次初始化（execve 保留 fd）。
    int is_exec = 0;
    for (;;) {
        if (setjmp(g_exec_jmp) != 0) {
            // execve 请求到达。此时客户机旧镜像仍在内存里，sys_execve 记下的
            // argv/envp 指针还可读；guest_state_reset 只清簿记，不动 fd 表。
            is_exec = 1;
            guest_state_reset();
            fprintf(stderr, "[mlc] execve：%s（argc=%d envc=%d）\n",
                    g_exec_path, g_exec_argc, g_exec_envc);
        }
        char load_path[1024];
        if (is_exec) {
            // execve 给的是客户机路径（如 /bin/echo），要重写进 rootfs。
            // 首次运行的 guest_path 是调用方给的宿主路径，原样用——再重写一次
            // 就会拼成 rootfs/rootfs/... 而打不开。
            if (guest_to_host_path(g_exec_path, load_path, sizeof(load_path)) < 0)
                die("镜像路径过长");
        } else {
            snprintf(load_path, sizeof(load_path), "%s", guest_path);
        }
        image_t *main_im = load_image(load_path);
        g_load_base = main_im->mem; g_load_end = main_im->mem + main_im->span;

    // 2. 动态链接：有 PT_INTERP 就加载 interp，控制权交给 ld.so
    image_t *interp = NULL;
    {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)main_im->img;
        Elf64_Phdr *ph = (Elf64_Phdr *)(main_im->img + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_INTERP) continue;
            char ipath[512], hpath[1024];
            size_t n = ph[i].p_filesz;
            if (n >= sizeof(ipath)) n = sizeof(ipath) - 1;
            memcpy(ipath, main_im->img + ph[i].p_offset, n);
            ipath[n] = 0;
            if (guest_to_host_path(ipath, hpath, sizeof(hpath)) < 0) die("interp 路径过长");
            fprintf(stderr, "[mlc] 动态链接镜像，interp=%s -> %s\n", ipath, hpath);
            interp = load_image2(hpath, 1);
            break;
        }
    }
    // 3. brk 独立预留区（与镜像、蹦床、其他映射都不重叠）
    uint8_t *brk_region = mmap(NULL, BRK_RESERVE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANON, -1, 0);
    if (brk_region == MAP_FAILED) die("无法分配 brk 预留区");
    g_brk_start = (uint64_t)brk_region;
    g_brk_cur = g_brk_start;
    g_brk_region_end = (uint64_t)brk_region + BRK_RESERVE;
    // 只登记到当前断点，不登记整块预留区（审计 F50）。
    // 曾把 32MB 预留区整体注册成"活区间"，后果有两个：
    //   1. 客户机一次 MAP_FIXED 落在预留区未提交部分时， overlap 检查认为它在覆盖
    //      活内存，先 munmap 再 mmap 会把预留区啃掉一块，之后 brk 增长的 MAP_FIXED
    //      落到已卸载页上直接失败，客户机堆就此坏掉（实测崩溃：故障地址"在区域表内"）；
    //   2. 未提交部分被当成合法内存，野指针校验对它们放行。
    // brk 增长/收缩本身已经在 SYS_brk 里同步登记与摘除，这里只兜底登记已提交部分。
    region_add(g_brk_start, g_brk_cur);
    fprintf(stderr, "[mlc] brk 预留区 0x%llx-0x%llx（%llu MB）\n",
            (unsigned long long)g_brk_start, (unsigned long long)g_brk_region_end,
            (unsigned long long)(BRK_RESERVE >> 20));
    if (interp) fprintf(stderr, "[mlc] 控制权将交给 interp（入口 0x%llx）\n",
                        (unsigned long long)interp->entry);

    // 5. 客户机 fd 表初始化（仅首次；execve 保留已打开的 fd）
    if (!is_exec) {
        for (int i = 0; i < GUEST_FD_MAX; i++) g_fd_map[i] = -1;
        g_fd_map[0] = 0; g_fd_map[1] = 1; g_fd_map[2] = 2;
    }

    // 6. 搭建客户机栈
    // 栈顶留白：argv/envp 字符串从这里往下写。审计 F37：原为 4096，而真实
    // 环境变量总量常有好几 KB，写出去就是 SIGSEGV（客户机看到的是"莫名崩了"）。
    #define GUEST_STACK_SLACK 65536
    size_t stack_size = 8 * 1024 * 1024;
    uint8_t *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stack == MAP_FAILED) die("无法分配客户机栈");
    region_add((uint64_t)stack, (uint64_t)stack + stack_size);   // M1：栈纳入可访问区域
    uint8_t *sp_top = stack + stack_size - GUEST_STACK_SLACK;

    // 6a. 写字符串（argv 与 envp）
    // 审计 F37：这三个数组原先都写在不检查边界的宿主栈上。strptr[256] 与
    // words[600] 只由"环境变量条数"间接约束，而 argv 条数完全没人管——
    // `mlc $(seq 1 500)` 就能让宿主栈溢出，属可由客户机参数直接触发的
    // 宿主内存破坏。现在三处都设硬上限，超限直接报用法错误退出。
    #define GUEST_ARGC_MAX 128
    #define GUEST_ENVC_MAX 128
    #define GUEST_WORDS_MAX 512
    int gargc;
    char **gargv;
    if (is_exec) {
        // g_exec_argv 已在 sys_execve 里抄成宿主缓冲区（客户机栈会被新镜像盖掉）
        gargc = g_exec_argc;
        gargv = g_exec_argv;
    } else {
        gargc = argc - 1;
        gargv = &argv[1];
    }
    if (gargc > GUEST_ARGC_MAX) {
        fprintf(stderr, "[mlc][致命] 参数过多（%d，上限 %d）\n", gargc, GUEST_ARGC_MAX);
        return 2;
    }
    const char *envp_def[] = { "TERM=xterm-256color", "PATH=/usr/bin:/bin", "HOME=/root", NULL };
    uint64_t strptr[GUEST_ARGC_MAX]; int nstr = 0;
    uint8_t *p = sp_top;
    for (int i = gargc - 1; i >= 0; i--) {
        size_t l = strlen(gargv[i]) + 1;
        if ((uint64_t)(p - l) < (uint64_t)(stack + GUEST_STACK_SLACK)) {
            fprintf(stderr, "[mlc][致命] 客户机字符串超出栈预留空间\n");
            return 2;
        }
        p -= l; memcpy(p, gargv[i], l); strptr[nstr++] = (uint64_t)p;
    }
    // v1.2：透传宿主环境变量（客户机需要 PATH、LD_DEBUG、LANG、MLC_ROOT 等），
    // 只对缺失的几个关键项补默认值。
    // execve 之后改用客户机自己给的那份 envp——execve 的语义就是换环境，
    // 再透传宿主 environ 会让 PATH 之类回到宿主值，exec 出来的程序立刻跑偏。
    extern char **environ;
    uint64_t envptr[GUEST_ENVC_MAX]; int nenv = 0;
    char **env_src; int env_count;
    if (is_exec) {
        env_src = g_exec_envp;
        env_count = g_exec_envc;
    } else {
        env_src = environ;
        env_count = -1;                       // 遍历到 NULL 为止
    }
    for (int i = 0; nenv < GUEST_ENVC_MAX; i++) {
        if (env_count >= 0) { if (i >= env_count) break; }
        else if (!env_src[i]) break;
        size_t l = strlen(env_src[i]) + 1;
        if ((uint64_t)(p - l) < (uint64_t)(stack + GUEST_STACK_SLACK)) {
            fprintf(stderr, "[mlc][致命] 环境变量总量超出栈预留空间\n");
            return 2;
        }
        p -= l; memcpy(p, env_src[i], l); envptr[nenv++] = (uint64_t)p;
    }
    for (int i = 0; envp_def[i] && nenv < GUEST_ENVC_MAX; i++) {
        size_t fl = strcspn(envp_def[i], "=");
        int have = 0;
        for (int k = 0; k < nenv; k++)
            if (strncmp((const char *)envptr[k], envp_def[i], fl) == 0 &&
                ((const char *)envptr[k])[fl] == '=') { have = 1; break; }
        if (have) continue;
        size_t l = strlen(envp_def[i]) + 1;
        p -= l; memcpy(p, envp_def[i], l); envptr[nenv++] = (uint64_t)p;
    }
    // AT_EXECFN：argv[0]。execve 可能给空 argv（gargc=0），此时补一个可读的
    // 占位——glibc 的 __libc_start_main 会读它，给空指针反而崩。
    uint64_t execfn;
    if (gargc > 0) {
        execfn = strptr[0];
    } else {
        const char *self = is_exec ? g_exec_path : load_path;
        size_t l = strlen(self) + 1;
        if ((uint64_t)(p - l) < (uint64_t)(stack + GUEST_STACK_SLACK)) {
            fprintf(stderr, "[mlc][致命] 客户机字符串超出栈预留空间\n");
            return 2;
        }
        p -= l; memcpy(p, self, l); execfn = (uint64_t)p;
    }
    uint64_t platform = 0;
    { const char *plat = "aarch64"; size_t l = strlen(plat) + 1; p -= l; memcpy(p, plat, l); platform = (uint64_t)p; }
    uint8_t randbytes[16]; arc4random_buf(randbytes, sizeof(randbytes));
    uint64_t randptr = 0;
    { p -= 16; memcpy(p, randbytes, 16); randptr = (uint64_t)p; }

    // 6b. 16 字节对齐，压入 auxv/envp/argv/argc（AArch64 PCS 要求 SP 16 对齐）
    p = (uint8_t *)((uint64_t)p & ~15ULL);
    struct { uint64_t a, b; } aux[32]; int naux = 0;
    // AT_PHDR：主程序程序头在内存中的地址（load_image 已算好）
    uint64_t phdr_addr = main_im->phdr_addr;
    aux[naux++] = (typeof(aux[0])){3, phdr_addr};        // AT_PHDR
    aux[naux++] = (typeof(aux[0])){4, 56};               // AT_PHENT
    aux[naux++] = (typeof(aux[0])){5, main_im->phnum};   // AT_PHNUM
    aux[naux++] = (typeof(aux[0])){6, 16384};            // AT_PAGESZ：必须报宿主真实页大小
    // 曾报 4096，于是 ld.so 按 4K 对齐算 mapstart/mapsize，而引擎只能按宿主 16K 页
    // 落位。客户机一次 4K 边界的 MAP_FIXED 被展成 16K，同页内相邻映射的数据被连带
    // 卸掉重建成零页——libc 的 .data 尾部（含 _IO_2_1_stdout_）就是这样没的，
    // stdout 的 _fileno 变成 0，ls 把目录列表写到了 fd 0（v1.2 F35 修）。
    aux[naux++] = (typeof(aux[0])){7, interp ? interp->base : 0};  // AT_BASE：interp 基址
    aux[naux++] = (typeof(aux[0])){8, 0};                // AT_FLAGS
    aux[naux++] = (typeof(aux[0])){9, main_im->entry};   // AT_ENTRY：主程序入口
    aux[naux++] = (typeof(aux[0])){11, getuid()};        // AT_UID
    aux[naux++] = (typeof(aux[0])){12, geteuid()};       // AT_EUID
    aux[naux++] = (typeof(aux[0])){13, getgid()};        // AT_GID
    aux[naux++] = (typeof(aux[0])){14, getegid()};       // AT_EGID
    aux[naux++] = (typeof(aux[0])){16, 0};               // AT_HWCAP
    aux[naux++] = (typeof(aux[0])){17, 100};             // AT_CLKTCK
    aux[naux++] = (typeof(aux[0])){23, 0};               // AT_SECURE
    aux[naux++] = (typeof(aux[0])){25, randptr};         // AT_RANDOM
    aux[naux++] = (typeof(aux[0])){26, 0};               // AT_HWCAP2
    aux[naux++] = (typeof(aux[0])){15, platform};        // AT_PLATFORM
    aux[naux++] = (typeof(aux[0])){31, execfn};          // AT_EXECFN
    aux[naux++] = (typeof(aux[0])){0, 0};                // AT_NULL（必须最后）

    // 布局：[argc][argv...][NULL][envp...][NULL][auxv...][可选补齐]
    // 先收集成字数组，整块落盘，确保 argc 位于 16 字节对齐处
    // 先算总词数再落盘：写在数组里之后才检查等于没检查（审计 F37）
    int need = 1 + gargc + 1 + nenv + 1 + 2 * naux + 1;   // 末尾 +1 是 16 字节补齐
    if (need > GUEST_WORDS_MAX) {
        fprintf(stderr, "[mlc][致命] 客户机初始栈词数 %d 超出上限 %d\n", need, GUEST_WORDS_MAX);
        return 2;
    }
    uint64_t words[GUEST_WORDS_MAX]; int nw = 0;
    words[nw++] = (uint64_t)gargc;
    for (int i = 0; i < gargc; i++) words[nw++] = strptr[gargc - 1 - i];
    words[nw++] = 0;                                 // argv 结尾 NULL
    for (int i = 0; i < nenv; i++) words[nw++] = envptr[i];
    words[nw++] = 0;                                 // envp 结尾 NULL
    for (int i = 0; i < naux; i++) { words[nw++] = aux[i].a; words[nw++] = aux[i].b; }
    if (nw & 1) words[nw++] = 0;                     // 补齐到 16 字节倍数
    p -= nw * 8;
    memcpy(p, words, nw * 8);
    uint64_t guest_sp = (uint64_t)p;

    // 跳转目标：有 interp 交给 ld.so（它自 relocation 后调主程序入口），否则直接进主程序
    uint64_t jump_target = interp ? interp->entry : main_im->entry;
    fprintf(stderr, "[mlc] 客户机栈就绪 sp=0x%llx，跳转入口 0x%llx%s\n",
            (unsigned long long)guest_sp, (unsigned long long)jump_target,
            interp ? "（ld.so）" : "（主程序）");

    // 7. 跳转到客户机入口（不再返回）
    // execve 会 longjmp 回循环开头重新加载，所以这里不能只是 unreachable——
    // 万一 br 之后还能回来（例如客户机入口自己返回），就接着跑下一轮加载。
    __asm__ volatile(
        "mov sp, %0\n\t"
        "br  %1\n\t"
        :: "r"(guest_sp), "r"(jump_target) : "memory");
    // 到这里说明客户机入口返回了：按 Linux 语义这不该发生，直接按 127 收尾
    fprintf(stderr, "[mlc][警告] 客户机入口返回了，按退出码 127 处理\n");
    return 127;
    }
}
