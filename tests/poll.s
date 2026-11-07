// MLC 测试载荷：poll / ppoll 的 pollfd 布局与越界写（2026-11-07 审计追加）
//
// 为什么值得单列一个载荷：第七轮补 ppoll 时把客户机 struct pollfd 的跨距写成 12、
// revents 偏移写成 8，而两侧真实布局都是跨距 8、revents 在偏移 6
// （实测 sizeof(struct pollfd)==8、offsetof(revents)==6）。
// 后果有两个，此前没有任何测试覆盖，所以套件一直是绿的：
//   1. nfds>1 时从第 2 项起读到的 fd/events 全是错位垃圾；
//   2. revents 写在第 8 字节，正好落到下一个 pollfd 的 fd 字段上，
//      最后一项还会写出数组末端两字节。
//
// 判据设计成「旧代码必红、新代码必绿」，共 6 项，失败项按位累加进退出码：
//   bit0  poll  的就绪个数不是 2
//   bit1  ppoll 的就绪个数不是 2
//   bit2  pfds[0].revents 不是 POLLIN
//   bit3  pfds[1].revents 不是 POLLIN
//   bit4  pfds[1].fd 被踩坏（跨距错位时 revents[0] 正好写在这一格）
//   bit5  哨兵被改写（revents 越界写的直接证据）
// 用 /dev/zero 做被 poll 的 fd：它在引擎里是虚拟设备、恒就绪，
// revents 是确定值，不依赖 stdout 是管道还是终端这类环境因素。
    .text
    .globl _start
_start:
    // ---- openat(AT_FDCWD, "/dev/zero", O_RDONLY, 0) ----
    mov  x0, #-100
    adrp x1, zpath
    add  x1, x1, :lo12:zpath
    mov  x2, #0
    mov  x3, #0
    mov  x8, #56
    svc  #0
    mov  x19, x0             // 设备 fd，后面反复用

    // ---- 填 pfds[0] 与 pfds[1] ----
    adrp x20, pfds
    add  x20, x20, :lo12:pfds
    str  w19, [x20, #0]      // pfds[0].fd
    mov  w0, #1              // POLLIN
    strh w0, [x20, #4]       // pfds[0].events
    strh wzr, [x20, #6]      // pfds[0].revents
    str  w19, [x20, #8]      // pfds[1].fd
    strh w0, [x20, #12]      // pfds[1].events
    strh wzr, [x20, #14]     // pfds[1].revents

    // ---- poll(pfds, 2, 0)：第三参 0 表示不阻塞，绝不挂死 ----
    mov  x0, x20
    mov  x1, #2
    mov  x2, #0
    mov  x8, #7              // asm-generic 7 = poll
    svc  #0
    mov  x21, x0             // 就绪个数

    // ---- ppoll(pfds, 2, &ts0, NULL)：同一批 fd 再走一遍 73 号 ----
    // revents 先清零，否则读到的是上一轮的值，就测不出 73 号这条路径
    strh wzr, [x20, #6]
    strh wzr, [x20, #14]
    mov  x0, x20
    mov  x1, #2
    adrp x2, ts0
    add  x2, x2, :lo12:ts0
    mov  x3, #0
    mov  x8, #73             // asm-generic 73 = ppoll
    svc  #0
    mov  x22, x0

    // ---- 逐项判定，失败项按位累加进 x23 ----
    mov  x23, #0

    cmp  x21, #2             // bit0：poll 就绪个数
    b.eq 1f
    add  x23, x23, #1
1:
    cmp  x22, #2             // bit1：ppoll 就绪个数
    b.eq 2f
    add  x23, x23, #2
2:
    ldrh w0, [x20, #6]       // bit2：pfds[0].revents
    cmp  w0, #1
    b.eq 3f
    add  x23, x23, #4
3:
    ldrh w0, [x20, #14]      // bit3：pfds[1].revents
    cmp  w0, #1
    b.eq 4f
    add  x23, x23, #8
4:
    ldr  w0, [x20, #8]       // bit4：pfds[1].fd 没被踩坏
    cmp  w0, w19
    b.eq 5f
    add  x23, x23, #16
5:
    adrp x0, sentinel        // bit5：哨兵原样不动
    add  x0, x0, :lo12:sentinel
    ldr  x1, [x0]
    adrp x2, smagic
    add  x2, x2, :lo12:smagic
    ldr  x2, [x2]
    cmp  x1, x2
    b.eq 6f
    add  x23, x23, #32
6:
    // ---- 输出结果串，然后按 x23 退出（0 = 全过）----
    mov  x0, #1
    adrp x1, okmsg
    add  x1, x1, :lo12:okmsg
    mov  x2, #oklen
    mov  x8, #64
    svc  #0

    mov  x0, x23
    mov  x8, #94             // exit_group
    svc  #0

    .data
    .align 3
pfds:
    .zero 16                 // 两个 struct pollfd
sentinel:
    .quad 0x5A5ADEADBEEF1234 // poll 之后必须原样不动
smagic:
    .quad 0x5A5ADEADBEEF1234
ts0:                         // ppoll 的 timespec：0 秒 0 纳秒
    .quad 0
    .quad 0
zpath:
    .asciz "/dev/zero"
okmsg:
    .ascii "MLC: poll ok\n"
oklen = . - okmsg
