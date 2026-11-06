// MLC 回归载荷：客户机线程指针跨 msr/mrs 的完整性（缺陷 K1 的收口，v1.5 F55）
//
// 背景：蹦桌在每次系统调用出口都把有效 TCB 写回 TPIDR_EL0，可全 rootfs 816 个 ELF
// 里 msr TPIDR_EL0 只有 ld.so 两处且都已修补，崩溃运行里也没有任何信号到达——
// 翻野只可能发生在「最后一次系统调用之后」那段纯客户机代码里，而那段代码里
// 没有任何 msr 会执行。写野值的是 macOS libSystem，但触发点不可观测。
// v1.5 因此改为拦住读：mrs xN, TPIDR_EL0 一律走存根核对，与已知有效 TCB 不一致
// 就换成有效 TCB。客户机于是永远拿不到野线程指针。
//
// 本载荷把这条链端到端钉住：
//   1. msr 写一个高地址（有效 TCB）→ TP 存根记下它；
//   2. mrs 读回来必须等于刚写的值；
//   3. msr 写一个小值（模拟 macOS libSystem 的野值）→ 必须被顶替成有效 TCB；
//   4. mrs 再读，必须还是有效 TCB，不是小值；
//   5. 换不同目标寄存器读（x0/x1/x9/x10/x19/x28/x30，覆盖存根里全部难缠的情形），
//      读到的必须都是同一个有效 TCB；
//   6. mrs 存根只保存 x0/x1/x9/x10，其余寄存器必须原样不动。
// 任一环不成立就以对应序号为退出码失败。
    .text
    .globl _start
_start:
    // 0. 先在任何 msr 之前读两次：此时引擎还没记下有效 TCB，mrs 存根必须原样
    //    返回现场值（本进程里是 macOS libSystem 的槽位小值，实测 0x1006/0x1007），
    //    既不能抹成 0，也不能编一个高地址。
    //    （v1.5 实测缺陷：cbz 分支跳到了「野值顶替」，未建立时把现场值抹成 0。
    //     本用例就是钉这条的。）
    mrs  x0, tpidr_el0
    mrs  x1, tpidr_el0
    cmp  x0, x1
    b.ne fail0               // 同一现场值两次读不一致
    cbz  x0, fail0b          // 现场值被抹成 0
    movz x9, #0x0000
    movk x9, #0x0100, lsl #16   // x9 = 0x0000000100000000 的下界：0x10000000
    cmp  x0, x9
    b.hs fail0c              // 读出的比 0x10000000 还大：存根编造了高地址

    // 1. 拼一个 0x0000000105bce000 一档的"有效 TCB"并写进 TPIDR_EL0
    movz x20, #0xe000
    movk x20, #0x05bc, lsl #16
    movk x20, #0x0001, lsl #32
    msr  tpidr_el0, x20

    // 2. 读回来必须等于刚写的值
    mrs  x0, tpidr_el0
    cmp  x0, x20
    b.ne fail2

    // 3. 写一个小值：模拟 macOS libSystem 把 TPIDR_EL0 占回去
    movz x21, #0x1006
    msr  tpidr_el0, x21

    // 4. 再读必须还是有效 TCB（野值被顶替），不是 0x1006
    mrs  x1, tpidr_el0
    cmp  x1, x20
    b.ne fail4
    movz x9, #0x1006
    cmp  x1, x9
    b.eq fail4b

    // 5. 换目标寄存器逐个读。x0/x1 存根本来就保存，x9/x10 是存根的工作寄存器，
    //    x19/x28/x30 是它完全不碰的——七种都必须拿到同一个有效 TCB。
    mrs  x9, tpidr_el0
    cmp  x9, x20
    b.ne fail5a
    mrs  x10, tpidr_el0
    cmp  x10, x20
    b.ne fail5b
    mrs  x19, tpidr_el0
    cmp  x19, x20
    b.ne fail5c
    mrs  x28, tpidr_el0
    cmp  x28, x20
    b.ne fail5d
    mrs  x30, tpidr_el0
    cmp  x30, x20
    b.ne fail5e

    // 6. 邻存寄存器不能被 mrs 存根踩掉：填哨兵后触发一次拦截，再逐一比对
    movz x11, #0x1234
    movk x11, #0x5678, lsl #16
    movz x12, #0x9abc
    movk x12, #0xdef0, lsl #16
    movz x13, #0x1111
    movk x13, #0x2222, lsl #16
    movz x14, #0x5555
    movk x14, #0x6666, lsl #16
    movz x15, #0x7777
    movk x15, #0x8888, lsl #16
    movz x22, #0xdead
    movk x22, #0xbeef, lsl #16
    movz x23, #0xcafe
    movk x23, #0xbabe, lsl #16
    movz x24, #0x0f0f
    movk x24, #0xf0f0, lsl #16
    movz x25, #0x1357
    movk x25, #0x9bdf, lsl #16
    mrs  x26, tpidr_el0          // 触发一次 mrs 拦截
    cmp  x26, x20
    b.ne fail6

    movz x9, #0x1234
    movk x9, #0x5678, lsl #16
    cmp  x11, x9
    b.ne fail6a
    movz x9, #0x9abc
    movk x9, #0xdef0, lsl #16
    cmp  x12, x9
    b.ne fail6b
    movz x9, #0x1111
    movk x9, #0x2222, lsl #16
    cmp  x13, x9
    b.ne fail6c
    movz x9, #0x5555
    movk x9, #0x6666, lsl #16
    cmp  x14, x9
    b.ne fail6d
    movz x9, #0x7777
    movk x9, #0x8888, lsl #16
    cmp  x15, x9
    b.ne fail6e
    movz x9, #0xdead
    movk x9, #0xbeef, lsl #16
    cmp  x22, x9
    b.ne fail6f
    movz x9, #0xcafe
    movk x9, #0xbabe, lsl #16
    cmp  x23, x9
    b.ne fail6g
    movz x9, #0x0f0f
    movk x9, #0xf0f0, lsl #16
    cmp  x24, x9
    b.ne fail6h
    movz x9, #0x1357
    movk x9, #0x9bdf, lsl #16
    cmp  x25, x9
    b.ne fail6i

    // 7. 跨一次系统调用之后再读，必须还是有效 TCB
    mov  x8, #172               // getpid
    svc  #0
    mrs  x27, tpidr_el0
    cmp  x27, x20
    b.ne fail7

    // 全过：exit_group(0)
    mov  x0, #0
    mov  x8, #94
    svc  #0
    b .

fail2:  mov x0, #2
    b out
fail0:  mov x0, #1
    b out
fail0b: mov x0, #11
    b out
fail0c: mov x0, #12
    b out
fail4:  mov x0, #4
    b out
fail4b: mov x0, #44
    b out
fail5a: mov x0, #51
    b out
fail5b: mov x0, #52
    b out
fail5c: mov x0, #53
    b out
fail5d: mov x0, #54
    b out
fail5e: mov x0, #55
    b out
fail6:  mov x0, #6
    b out
fail6a: mov x0, #61
    b out
fail6b: mov x0, #62
    b out
fail6c: mov x0, #63
    b out
fail6d: mov x0, #64
    b out
fail6e: mov x0, #65
    b out
fail6f: mov x0, #66
    b out
fail6g: mov x0, #67
    b out
fail6h: mov x0, #68
    b out
fail6i: mov x0, #69
    b out
fail7:  mov x0, #7
out:
    mov  x8, #94
    svc  #0
    b .
