#!/usr/bin/env python3
"""迷你链接器：把 aarch64 ELF 目标文件转成位置无关 ET_DYN 可执行 ELF（MLC v1 测试载荷生成器）
处理 R_AARCH64_ADR_PREL_LO21 / R_AARCH64_ADD_ABS_LO12 / R_AARCH64_PREL32/64 重定位。"""
import struct, subprocess, sys

R_AARCH64_ADR_PREL_LO21 = 0x113
R_AARCH64_ADD_ABS_LO12_NC = 0x115
R_AARCH64_PREL32        = 0x102
R_AARCH64_PREL64        = 0x104

def build(asm_path, out_path):
    obj = asm_path + ".o"
    subprocess.run(["clang", "-c", "-target", "aarch64-linux-gnu", "-o", obj, asm_path], check=True)
    d = open(obj, "rb").read()
    assert d[:4] == b"\x7fELF" and d[4] == 2
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3A)
    shs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", d, o)
        shs.append(dict(name=name, typ=typ, flags=flags, addr=addr, off=off, size=size,
                        link=link, info=info, align=align, entsize=entsize))
    str_off = shs[e_shstrndx]["off"]
    def nm(n):
        s = d[str_off + n:]
        return s[:s.index(b"\0")].decode()
    for s in shs: s["nm"] = nm(s["name"])
    S = {s["nm"]: s for s in shs}

    # 地址分配：text 在 0，data 4K 对齐后接
    text = bytearray(d[S[".text"]["off"]:S[".text"]["off"]+S[".text"]["size"]])
    text_addr = 0
    data_addr = (len(text) + 0x3FFF) & ~0x3FFF   # 16K 对齐：宿主 macOS 页粒度
    data = bytearray(d[S[".data"]["off"]:S[".data"]["off"]+S[".data"]["size"]]) if ".data" in S else bytearray()
    bss_size = S[".bss"]["size"] if ".bss" in S else 0
    sec_addr = {".text": text_addr, ".data": data_addr, ".bss": data_addr + len(data)}

    # 符号表
    syms = []
    if ".symtab" in S:
        st = S[".symtab"]
        cnt = st["size"] // 24
        for i in range(cnt):
            o = st["off"] + i * 24
            nameoff, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", d, o)
            nmstr = d[S[".strtab"]["off"] + nameoff:]
            nmstr = nmstr[:nmstr.index(b"\0")].decode()
            syms.append((nmstr, shndx, value))
    def sym_addr_idx(idx):
        # 按符号索引解析：节符号（无名，shndx 指向节）与普通符号都走这里
        if idx >= len(syms): return 0
        n, shndx, value = syms[idx]
        if shndx == 0: return value
        sh = shs[shndx]
        return sec_addr.get(sh["nm"], sh["addr"]) + value

    # 应用 .text 重定位
    applied = 0
    if ".rela.text" in S:
        rt = S[".rela.text"]
        for i in range(rt["size"] // 24):
            o = rt["off"] + i * 24
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, o)
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32
            target = sym_addr_idx(r_sym) + r_add
            if r_type == R_AARCH64_ADR_PREL_LO21:
                place = text_addr + r_off
                imm = ((target & ~0xFFF) - (place & ~0xFFF)) >> 12
                insn_off = r_off
                insn = struct.unpack_from("<I", text, insn_off)[0]
                immlo = imm & 3
                immhi = (imm >> 2) & 0x7FFFF
                insn = (insn & ~((3 << 29) | (0x7FFFF << 5))) | (immlo << 29) | (immhi << 5)
                struct.pack_into("<I", text, insn_off, insn)
                applied += 1
            elif r_type == R_AARCH64_ADD_ABS_LO12_NC:
                insn_off = r_off
                insn = struct.unpack_from("<I", text, insn_off)[0]
                imm = (target) & 0xFFF
                shift = 0
                if (insn >> 22) & 3: shift = 12     # 处理 lsl #12 变体
                insn = (insn & ~(0x3FF << 22)) | ((imm >> shift) << 22) if shift else (insn & ~(0xFFF << 10)) | (imm << 10)
                struct.pack_into("<I", text, insn_off, insn)
                applied += 1
            elif r_type in (R_AARCH64_PREL32, R_AARCH64_PREL64):
                place = text_addr + r_off
                val = target - place
                if r_type == R_AARCH64_PREL32:
                    struct.pack_into("<i", text, r_off, val)
                else:
                    struct.pack_into("<q", text, r_off, val)
                applied += 1

    ehsize, phentsize, phnum = 64, 56, 2
    text_off = ehsize + phentsize * phnum
    data_off = text_off + len(text)
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"; eh[4] = 2; eh[5] = 1; eh[6] = 1; eh[7] = 0
    struct.pack_into("<HHI", eh, 16, 3, 0xB7, 1)
    struct.pack_into("<QQQ", eh, 24, text_addr, 64, 0)
    struct.pack_into("<IHHHHHH", eh, 48, 0, ehsize, phentsize, phnum, 0, 0, 0)
    def phdr(ptype, flags, off, vaddr, filesz, memsz):
        return struct.pack("<IIQQQQQQ", ptype, flags, off, vaddr, vaddr, filesz, memsz, 0x1000)
    ph = phdr(1, 0x5, text_off, text_addr, len(text), len(text))
    ph += phdr(1, 0x6, data_off, data_addr, len(data) + bss_size, len(data) + bss_size)

    with open(out_path, "wb") as f:
        f.write(eh); f.write(ph); f.write(text); f.write(data)
    print(f"生成 {out_path}: text={len(text)}B@{text_addr:#x} data+bss={len(data)+bss_size}B@{data_addr:#x} 重定位应用 {applied} 处")

if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2])
