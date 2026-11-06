// MLC 客户机 TPIDR_EL0 写入校验存根（2026-11-06，缺陷 K1 收口）
//
// 背景：macOS 的 libSystem 会把 TPIDR_EL0 当成自己的线程槽位用（实测普通进程里
// 是 0x0/0x1/0x3，本进程里是 0x1006 一类的小值）。glibc 只认 TPIDR_EL0 是 TCB
// 指针，一旦拿到小值，所有 TP 相对访问（errno、栈保护值、cleanup_jmp_buf）
// 全部落到接近 0 的地址上。实测崩溃点：libc 的 __libc_start_main 尾部
//     mrs x0, TPIDR_EL0
//     sub x4, x0, #0x600
//     ldur q0, [x4, #-0x48]        ; 读 TCB+0xF8
//     str  x3, [x0, #0x100]        ; 写 TCB+0x100
// TPIDR 是 0x1006 时故障地址就是 0x1006-0x648 = 0x9be，与实测完全一致。
//
// 为什么在写入点校验而不是在系统调用进出口校验：崩溃发生在最后一次系统调用
// （brk）之后、__libc_start_main 尾部之前，中间没有任何 svc，蹦桌根本不该
// 被执行到。而客户机二进制里会写 TPIDR_EL0 的只有 ld.so 的两处 msr
// （libc.so.6 里一处都没有，全文件扫过），所以拦住这两处就拦住了全部路径。
//
// 判据：客户机 TCB 一定在 mmap 出来的高地址（本进程客户机窗口在 0x100000000
// 以上），macOS 的遗留值都小于 0x10000。写入值低于阈值且手里已有一个有效 TCB
// 时，用有效 TCB 顶替——宁可让客户机继续用旧 TCB，也不能让线程指针变成野值。
    .text
    .globl _mlc_tp_stub
_mlc_tp_stub:
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
    msr   tpidr_el0, xzr        // 校验期间也要护住客户机 TCB，理由同 stub.s
    mov   x0, sp                // 参数 1 = 寄存器保存块
    mov   w1, #0                // ┐ 参数 2 = 被写寄存器下标，运行时修补
    movz  x9, #0                // │
    movk  x9, #0, lsl #16       // │ 指向 mlc_tp_write_probe
    movk  x9, #0, lsl #32       // │
    movk  x9, #0, lsl #48       // ┘
    blr   x9
    msr   tpidr_el0, x0         // 写入校验后的值（x0 = 探针返回值）
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
    add   sp, sp, #0x110
    b     _mlc_tp_stub_ret      // 运行时修补，返回客户机 msr 的下一条
