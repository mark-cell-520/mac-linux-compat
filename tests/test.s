// MLC v1 测试载荷 v2：全位置无关（PC 相对）的 aarch64 Linux 程序
// 参数顺序全部按 Linux ABI：x0-x5。编译成 .o 后由 mkelf.py 包成 ET_DYN ELF。
    .text
    .globl _start
_start:
    // ---- write(1, msg1, 12) ----
    mov  x0, #1
    adrp x1, msg1
    add  x1, x1, :lo12:msg1
    mov  x2, #12
    mov  x8, #64
    svc  #0

    // ---- uname(buf) 后打印 machine 字段 ----
    adrp x0, ubuf
    add  x0, x0, :lo12:ubuf
    mov  x8, #160
    svc  #0
    mov  x0, #1
    adrp x1, ubuf
    add  x1, x1, :lo12:ubuf
    add  x1, x1, #(65*4)     // machine 字段
    mov  x2, #7              // "aarch64"
    mov  x8, #64
    svc  #0

    // ---- openat(AT_FDCWD, fpath, O_RDONLY, 0) ----
    mov  x0, #-100
    adrp x1, fpath
    add  x1, x1, :lo12:fpath
    mov  x2, #0
    mov  x3, #0
    mov  x8, #56
    svc  #0
    mov  x19, x0             // fd

    // ---- read(fd, rbuf, 64) ----
    mov  x0, x19
    adrp x1, rbuf
    add  x1, x1, :lo12:rbuf
    mov  x2, #64
    mov  x8, #63
    svc  #0
    mov  x20, x0             // 读到的字节数

    // ---- write(1, rbuf, n) ----
    mov  x0, #1
    adrp x1, rbuf
    add  x1, x1, :lo12:rbuf
    mov  x2, x20
    mov  x8, #64
    svc  #0

    // ---- close(fd) ----
    mov  x0, x19
    mov  x8, #57
    svc  #0

    // ---- openat(AT_FDCWD, dpath, O_DIRECTORY, 0) 然后 getdents64 ----
    mov  x0, #-100
    adrp x1, dpath
    add  x1, x1, :lo12:dpath
    mov  x2, #0x10000        // O_DIRECTORY
    mov  x3, #0
    mov  x8, #56
    svc  #0
    mov  x19, x0
    mov  x0, x19
    adrp x1, dbuf
    add  x1, x1, :lo12:dbuf
    mov  x2, #2048
    mov  x8, #61             // getdents64
    svc  #0
    mov  x21, x0             // 总字节数
    adrp x22, dbuf
    add  x22, x22, :lo12:dbuf
    mov  x23, #0
dir_loop:
    cmp  x23, x21
    b.ge dir_done
    mov  x0, #1
    add  x1, x22, x23
    add  x1, x1, #19         // d_name
    mov  x2, #24             // 名字区长度（够大多数名字）
    mov  x8, #64
    svc  #0
    mov  x0, #1              // 换行
    adrp x1, nl
    add  x1, x1, :lo12:nl
    mov  x2, #1
    mov  x8, #64
    svc  #0
    add  x26, x22, x23
    ldrh w25, [x26, #16]     // d_reclen
    add  x23, x23, x25
    b    dir_loop
dir_done:
    // ---- brk(0) ----
    mov  x0, #0
    mov  x8, #214
    svc  #0

    // ---- M1 野指针 clock_gettime(0, 0xdead0000)：引擎若解引用即 SIGSEGV，
    //      校验后应返回 -EFAULT(-14) ----
    mov  x0, #0
    mov  x1, #0xdead0000
    mov  x8, #113
    svc  #0
    cmn  x0, #14              // x0 == -14 则 Z=1
    b.ne eguard_fail
    mov  x0, #1
    adrp x1, eok
    add  x1, x1, :lo12:eok
    mov  x2, #15
    mov  x8, #64
    svc  #0
    b    eguard_done
eguard_fail:
    mov  x0, #1
    adrp x1, ebad
    add  x1, x1, :lo12:ebad
    mov  x2, #17
    mov  x8, #64
    svc  #0
eguard_done:

    // ---- M1 mprotect(0xbeef0000, 16K, RW) 未注册区域：期望 -ENOMEM(-12) ----
    mov  x0, #0xbeef0000
    mov  x1, #0x4000
    mov  x2, #3
    mov  x8, #226
    svc  #0
    cmn  x0, #12
    b.ne mp_fail
    mov  x0, #1
    adrp x1, mpok
    add  x1, x1, :lo12:mpok
    mov  x2, #16
    mov  x8, #64
    svc  #0
    b    mp_done
mp_fail:
    mov  x0, #1
    adrp x1, mpbad
    add  x1, x1, :lo12:mpbad
    mov  x2, #18
    mov  x8, #64
    svc  #0
mp_done:

    // ---- M3 mmap 匿名页，写入读回比对，再 munmap 精确卸载 ----
    mov  x0, #0
    mov  x1, #0x8000
    mov  x2, #3               // PROT_READ|PROT_WRITE
    mov  x3, #0x22            // MAP_PRIVATE|MAP_ANONYMOUS
    mov  x4, #-1
    mov  x5, #0
    mov  x8, #222
    svc  #0
    mov  x19, x0              // 映射返回地址
    adrp x1, mmmsg
    add  x1, x1, :lo12:mmmsg
    ldr  x2, [x1]
    str  x2, [x19]            // 写入客户机映射
    ldr  x3, [x19]
    cmp  x2, x3
    b.ne mm_fail
    mov  x0, x19              // munmap(addr, 0x8000)
    mov  x1, #0x8000
    mov  x8, #215
    svc  #0
    cmn  x0, #0               // munmap 返回 0？
    b.ne mm_fail
    mov  x0, #1
    adrp x1, mmok
    add  x1, x1, :lo12:mmok
    mov  x2, #13
    mov  x8, #64
    svc  #0
    b    mm_done
mm_fail:
    mov  x0, #1
    adrp x1, mmbad
    add  x1, x1, :lo12:mmbad
    mov  x2, #14
    mov  x8, #64
    svc  #0
mm_done:

    // ---- exit_group(0) ----
    mov  x0, #0
    mov  x8, #94
    svc  #0
    b .

open_fail:
    mov  x0, #1
    adrp x1, oerr
    add  x1, x1, :lo12:oerr
    mov  x2, #12
    mov  x8, #64
    svc  #0
    mov  x0, #1
    mov  x8, #94
    svc  #0
    b .

    .data
msg1:  .ascii "MLC: hello!\n"
oerr:  .ascii "MLC: openerr\n"
eok:   .ascii "MLC: eguard ok\n"
ebad:  .ascii "MLC: eguard FAIL\n"
mpok:  .ascii "MLC: mpguard ok\n"
mpbad: .ascii "MLC: mpguard FAIL\n"
mmok:  .ascii "MLC: mmap ok\n"
mmbad: .ascii "MLC: mmap bad\n"
mmmsg: .ascii "MLC: mm\n"
    .balign 8
fpath: .asciz "/tmp/mlc-dent-test/mlc-test.txt"
dpath: .asciz "/tmp/mlc-dent-test"
nl:    .ascii "\n"
    .balign 8
ubuf:  .zero 390             // new_utsname: 6*65
rbuf:  .zero 64
dbuf:  .zero 2048
