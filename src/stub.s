// MLC 系统调用存根 v5：由 B（无条件分支）从 svc 修补点跳入
//
// v2 及以前用 BL，这是错的：Linux 的 svc #0 不碰 LR(x30)，而 BL 会把 LR 覆写成
// 「svc 下一条」。glibc 大量使用 leaf 形式的 inline syscall 包装（如 __munmap：
// svc; cmn x0,#0xfff; ret），它们直接靠 LR 返回，LR 一被覆写，ret 就跳回自己
// 形成死循环（实测：ld.so 卡在 munmap 返回点，PC==LR，无任何后续系统调用）。
//
// v3 改法：
//   1. svc #0 修补成 B 蹦桌_i（B 不写 LR，客户机 LR 原样保留）
//   2. 每个 svc 修补点配一份独立蹦桌副本，末尾的 B 立即数运行时修补成
//      「该 svc 的下一条地址」，用它返回客户机
//   3. 蹦桌内部仍用 blr 调 C 处理器，LR 靠 str/ldr x30 保存恢复
//
// v5 改法（2026-11-06，缺陷 K1 根因）：
//   v3/v4 只保存 x0-x9、x16-x23、x28、x30，**漏掉 x10-x15、x24-x27、x29**。
//   Linux aarch64 的系统调用 ABI 规定：除 x0（返回值）外所有寄存器原样保留。
//   而 blr 进 C 处理器会按 AAPCS 把 x10-x15 当调用者保存寄存器踩掉，
//   我们又不还原——客户机在 svc 前后放在 x10-x15 里的活值就被抹了。
//   后果不是立刻可见的：glibc 的 malloc（sysmalloc/_int_malloc）在 mmap/brk
//   这类 svc 两侧用 x10-x15 存临时量，被抹后堆内部状态出错，2% 到 5% 的概率
//   返回一个野指针；这个野指针一路传到 ld.so 的 msr TPIDR_EL0, x20，
//   客户机线程指针变成 0x1006 一类的小值，随后 __libc_init_first 里
//   mrs x0, TPIDR_EL0 拿到它，ldur q0, [x4, #-0x48] 就以 TPIDR-0x648 为地址
//   触发 SIGSEGV（实测故障地址 0x9be、退出码 99，成功路径不复现）。
//   现在 x0-x30 全部保存还原，与 Linux 系统调用 ABI 对齐。
    .text
    .globl _mlc_stub
_mlc_stub:
    sub   sp, sp, #0x110
    stp   x0,  x1,  [sp, #0x00]
    stp   x2,  x3,  [sp, #0x10]
    stp   x4,  x5,  [sp, #0x20]
    stp   x6,  x7,  [sp, #0x30]
    stp   x8,  x9,  [sp, #0x40]
    stp   x10, x11, [sp, #0x50]
    stp   x12, x13, [sp, #0x60]
    stp   x14, x15, [sp, #0x70]
    stp   x16, x17, [sp, #0x80]
    stp   x18, x19, [sp, #0x90]
    stp   x20, x21, [sp, #0xA0]
    stp   x22, x23, [sp, #0xB0]
    stp   x24, x25, [sp, #0xC0]
    stp   x26, x27, [sp, #0xD0]
    stp   x28, x29, [sp, #0xE0]
    str   x30, [sp, #0xF0]
    // 客户机 TLS 指针（TPIDR_EL0）必须由我们保管。macOS 的 libSystem 会把它
    // 写成自己的小值（实测普通进程里是 0x0/0x1/0x3，本进程里是 0x1006 一类），
    // glibc 随后 mrs TPIDR_EL0 拿到它，errno/TLS 全部写成野地址（v1.2 F34）。
    // 进 C 处理器前先清成 0，macOS libSystem 才不会把客户机的 TCB 当成它自己的
    // pthread 结构用；出来时再还原。
    mrs   x9, tpidr_el0
    str   x9, [sp, #0xF8]
    msr   tpidr_el0, xzr
    mov   x0, sp                   // 参数 = 寄存器保存块指针
    movz  x9, #0                   // ┐ 立即数运行时修补
    movk  x9, #0, lsl #16          // │ 指向 mlc_syscall_handler
    movk  x9, #0, lsl #32          // │
    movk  x9, #0, lsl #48          // ┘
    blr   x9
    ldr   x9, [sp, #0xF8]          // 把客户机 TLS 指针还回去
    msr   tpidr_el0, x9
    str   x0, [sp, #0x100]         // 返回值先存槽，等会儿单独放回 x0
    ldp   x0,  x1,  [sp, #0x00]
    ldp   x2,  x3,  [sp, #0x10]
    ldp   x4,  x5,  [sp, #0x20]
    ldp   x6,  x7,  [sp, #0x30]
    ldp   x8,  x9,  [sp, #0x40]
    ldp   x10, x11, [sp, #0x50]
    ldp   x12, x13, [sp, #0x60]
    ldp   x14, x15, [sp, #0x70]
    ldp   x16, x17, [sp, #0x80]
    ldp   x18, x19, [sp, #0x90]
    ldp   x20, x21, [sp, #0xA0]
    ldp   x22, x23, [sp, #0xB0]
    ldp   x24, x25, [sp, #0xC0]
    ldp   x26, x27, [sp, #0xD0]
    ldp   x28, x29, [sp, #0xE0]
    ldr   x30, [sp, #0xF0]
    ldr   x0,  [sp, #0x100]        // 最后才覆盖 x0，避免冲掉刚还原的寄存器
    add   sp, sp, #0x110
    b     _mlc_stub_ret            // 运行时修补为 26 位相对偏移（返回客户机）
