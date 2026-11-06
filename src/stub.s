// MLC 系统调用存根 v3：由 B（无条件分支）从 svc 修补点跳入
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
    .text
    .globl _mlc_stub
_mlc_stub:
    sub   sp, sp, #0xB0
    stp   x0, x1, [sp, #0x00]
    stp   x2, x3, [sp, #0x10]
    stp   x4, x5, [sp, #0x20]
    stp   x6, x7, [sp, #0x30]
    stp   x8, x9, [sp, #0x40]      // x8 = Linux 系统调用号
    stp   x16, x17, [sp, #0x50]
    stp   x18, x19, [sp, #0x60]
    stp   x20, x21, [sp, #0x70]
    stp   x22, x23, [sp, #0x80]
    str   x28, [sp, #0x90]
    str   x30, [sp, #0xA0]         // 客户机原始 LR（B 不写它，但 blr 会，故仍须保存）
    // 客户机 TLS 指针（TPIDR_EL0）必须由我们保管。macOS 的 libSystem 会把它清 0
    // （实测：客户机 msr 写进去之后，只要 open() 一次就读回 0），glibc 随后
    // mrs TPIDR_EL0 拿到 0，errno/TLS 全部写成空指针，SIGSEGV 在 __open_nocancel
    // 收尾（v1.2 F34 修）。进 C 处理器前先清成 0，macOS libSystem 才不会把
    // 客户机的 TCB 当成它自己的 pthread 结构用。
    mrs   x9, tpidr_el0
    str   x9, [sp, #0xA8]
    msr   tpidr_el0, xzr
    mov   x0, sp                   // 参数 = 寄存器保存块指针
    movz  x9, #0                   // ┐ 立即数运行时修补
    movk  x9, #0, lsl #16          // │ 指向 mlc_syscall_handler
    movk  x9, #0, lsl #32          // │
    movk  x9, #0, lsl #48          // ┘
    blr   x9
    ldr   x9, [sp, #0xA8]          // 把客户机 TLS 指针还回去
    msr   tpidr_el0, x9
    str   x0, [sp, #0x98]          // 返回值存槽
    ldr   x30, [sp, #0xA0]         // 恢复客户机 LR
    ldp   x2, x3, [sp, #0x10]
    ldp   x4, x5, [sp, #0x20]
    ldp   x6, x7, [sp, #0x30]
    ldp   x8, x9, [sp, #0x40]
    ldp   x16, x17, [sp, #0x50]
    ldp   x18, x19, [sp, #0x60]
    ldp   x20, x21, [sp, #0x70]
    ldp   x22, x23, [sp, #0x80]
    ldr   x28, [sp, #0x90]
    ldr   x0, [sp, #0x98]
    add   sp, sp, #0xB0
    b     _mlc_stub_ret            // 运行时修补为 26 位相对偏移（返回客户机）
