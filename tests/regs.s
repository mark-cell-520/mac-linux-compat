// MLC 回归载荷：客户机寄存器跨系统调用保存（缺陷 K1 排查期发现的蹦桌缺陷）
//
// Linux aarch64 系统调用 ABI 规定：除 x0（返回值）外所有寄存器原样保留。
// 蹦桌 v4 及以前只保存 x0-x9、x16-x23、x28、x30，漏掉 x10-x15、x24-x27、x29。
// blr 进 C 处理器会按 AAPCS 把 x10-x15 当调用者保存寄存器踩掉，而我们不还原，
// 客户机放在这些寄存器里的活值就被抹了——glibc 的 malloc 在 mmap/brk 两侧正是
// 用 x10-x15 存临时量。本载荷把可怀疑的寄存器全部填成哨兵值，发一次 getpid，
// 再逐一比对，任何一个被改动就以非零退出码失败。
    .text
    .globl _start
_start:
    // 哨兵值：用立即数装不进去的大数，走 movz/movk 拼
    movz x10, #0x1234
    movk x10, #0x5678, lsl #16
    movz x11, #0x9abc
    movk x11, #0xdef0, lsl #16
    movz x12, #0x1111
    movk x12, #0x2222, lsl #16
    movz x13, #0x3333
    movk x13, #0x4444, lsl #16
    movz x14, #0x5555
    movk x14, #0x6666, lsl #16
    movz x15, #0x7777
    movk x15, #0x8888, lsl #16
    movz x24, #0x0f0f
    movk x24, #0xf0f0, lsl #16
    movz x25, #0xdead
    movk x25, #0xbeef, lsl #16
    movz x26, #0xcafe
    movk x26, #0xbabe, lsl #16
    movz x27, #0x1357
    movk x27, #0x9bdf, lsl #16
    mov  x29, #0            // 帧指针单独验：必须还是 0

    mov  x8, #172           // getpid：不写内存、不改寄存器，只留返回值在 x0
    svc  #0

    // 逐个比对，失败就把退出码设成该项序号后走到 exit
    movz x9, #0x1234
    movk x9, #0x5678, lsl #16
    cmp  x10, x9
    b.ne fail10
    movz x9, #0x9abc
    movk x9, #0xdef0, lsl #16
    cmp  x11, x9
    b.ne fail11
    movz x9, #0x1111
    movk x9, #0x2222, lsl #16
    cmp  x12, x9
    b.ne fail12
    movz x9, #0x3333
    movk x9, #0x4444, lsl #16
    cmp  x13, x9
    b.ne fail13
    movz x9, #0x5555
    movk x9, #0x6666, lsl #16
    cmp  x14, x9
    b.ne fail14
    movz x9, #0x7777
    movk x9, #0x8888, lsl #16
    cmp  x15, x9
    b.ne fail15
    movz x9, #0x0f0f
    movk x9, #0xf0f0, lsl #16
    cmp  x24, x9
    b.ne fail24
    movz x9, #0xdead
    movk x9, #0xbeef, lsl #16
    cmp  x25, x9
    b.ne fail25
    movz x9, #0xcafe
    movk x9, #0xbabe, lsl #16
    cmp  x26, x9
    b.ne fail26
    movz x9, #0x1357
    movk x9, #0x9bdf, lsl #16
    cmp  x27, x9
    b.ne fail27
    cbnz x29, fail29

    // 全过：exit_group(0)
    mov  x0, #0
    mov  x8, #94
    svc  #0
    b .

fail10: mov x0, #10
    b out
fail11: mov x0, #11
    b out
fail12: mov x0, #12
    b out
fail13: mov x0, #13
    b out
fail14: mov x0, #14
    b out
fail15: mov x0, #15
    b out
fail24: mov x0, #24
    b out
fail25: mov x0, #25
    b out
fail26: mov x0, #26
    b out
fail27: mov x0, #27
    b out
fail29: mov x0, #29
out:
    mov  x8, #94
    svc  #0
    b .
