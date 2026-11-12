"""Synthetic fixture class A: a small, internally consistent TC38x-like build:
ELF32 (EM_TRICORE), Intel HEX + S19 (with post-build UCB BMHD and a CRC block),
HighTec/GNU map, TASKING map + LSL, and an A2L with deliberate defects.

Synthetic on purpose: no employer or customer artefacts. Ground truth comes from
this generator, not from rea-auto. Hardware values the shipped profiles leave
unknown are filled in a separate synthetic profile whose facts are all marked
verification="synthetic"; they are test data, not claims about real silicon.
The BMHD CRC is computed here independently of rea-auto with the method from
Infineon AP32381 V1.4 (CRC-32 IEEE, reflected, inverted, 32-bit words big-endian),
which equals zlib.crc32 over the word-swapped header.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "generated" / "synthetic"

# name, vma, lma, size, flags(W=1,A=2,X=4), nobits, obj
SECTIONS = [
    (".startup", 0x80000020, 0x80000020, 0x40, 6, False, "obj/Ifx_Ssw_Tc0.o"),
    (".traptab_cpu0", 0x80000100, 0x80000100, 0x100, 6, False, "obj/Ifx_Ssw_Tc0.o"),
    (".text", 0x80000200, 0x80000200, 0x400, 6, False, None),
    (".rodata", 0x80001000, 0x80001000, 0x100, 2, False, "obj/Cal_Data.o"),
    (".clear_sec", 0x80001200, 0x80001200, 0x10, 2, False, "linker"),
    (".copy_sec", 0x80001220, 0x80001220, 0x18, 2, False, "linker"),
    (".inttab_cpu0", 0x80002000, 0x80002000, 0x100, 6, False, "obj/Ifx_Ssw_Tc0.o"),
    (".data", 0x70000000, 0x80001300, 0x40, 3, False, None),
    (".bss", 0x70000100, 0x70000100, 0x80, 3, True, None),
    (".csa0", 0x70010000, 0x70010000, 0x2000, 3, True, "linker"),
    (".ustack0", 0x70012000, 0x70012000, 0x1000, 3, True, "linker"),
    (".csa1", 0x70014000, 0x70014000, 0x800, 3, True, "linker"),
    (".CPU1.bss", 0x60000000, 0x60000000, 0x20, 3, True, "obj/Rte_Core1.o"),
]
TEXT_INPUTS = [  # input sections of .text: name, size, obj
    (".text.main", 0x40, "obj/main.o"),
    (".text.NvM_MainFunction", 0x100, "libBsw.a(NvM.o)"),
    (".text.Can_17_McmCan_Write", 0xC0, "obj/Can_17_McmCan.o"),
    (".text.Com_MainFunctionRx", 0x100, "libBsw.a(Com.o)"),
    (".text.EcuM_Init", 0x100, "obj/EcuM.o"),
]
# name, addr, size, type(1 obj, 2 func), section
SYMS = [
    ("_START", 0x80000020, 0x40, 2, ".startup"),
    ("main", 0x80000200, 0x40, 2, ".text"),
    ("NvM_MainFunction", 0x80000240, 0x100, 2, ".text"),
    ("Can_17_McmCan_Write", 0x80000340, 0xC0, 2, ".text"),
    ("Com_MainFunctionRx", 0x80000400, 0x100, 2, ".text"),
    ("EcuM_Init", 0x80000500, 0x100, 2, ".text"),
    ("Cal_IdleSpeed", 0x80001000, 2, 1, ".rodata"),
    ("Cal_Gain", 0x80001004, 4, 1, ".rodata"),
    ("Cal_Curve", 0x80001010, 16, 1, ".rodata"),
    ("Cal_Limit", 0x80001020, 1, 1, ".rodata"),
    ("Cal_Table", 0x80001028, 16, 1, ".rodata"),
    ("Cal_Offset", 0x80001040, 2, 1, ".rodata"),
    ("NvM_RamBlock", 0x70000000, 0x10, 1, ".data"),
    ("Com_RxBuf", 0x70000010, 0x20, 1, ".data"),
    ("Dem_EventStatus", 0x70000100, 0x40, 1, ".bss"),
    ("Can_State", 0x70000140, 0x8, 1, ".bss"),
    ("Rte_Core1_Buffer", 0x60000000, 0x20, 1, ".CPU1.bss"),
    ("__TRAPTAB_CPU0", 0x80000100, 0, 0, ".traptab_cpu0"),
    ("__INTTAB_CPU0", 0x80002000, 0, 0, ".inttab_cpu0"),
    ("__clear_table", 0x80001200, 0, 0, ".clear_sec"),
    ("__copy_table", 0x80001220, 0, 0, ".copy_sec"),
    ("__CSA0", 0x70010000, 0, 0, ".csa0"),
    ("__CSA0_END", 0x70012000, 0, 0, ".csa0"),
    ("__USTACK0_END", 0x70012000, 0, 0, ".ustack0"),
    ("__USTACK0", 0x70013000, 0, 0, ".ustack0"),
    ("__CSA1", 0x70014000, 0, 0, ".csa1"),
    ("__CSA1_END", 0x70014800, 0, 0, ".csa1"),
]
REGIONS = [("pfls0", 0x80000000, 0x300000, "xr"), ("dsram0", 0x70000000, 0x3C000, "w!xp"),
           ("dsram1", 0x60000000, 0x3C000, "w!xp")]

EXPECTED = {
    "uncovered_ram": ".CPU1.bss",
    "csa_small_core": 1,
    "a2l_out_of_limits": "Cal_Limit",
    "a2l_addr_mismatch": "Cal_Offset",
    "a2l_by_address": "Cal_Stale",
    "a2l_unresolved": "Ghost_Signal",
    "orphan_crc_block": 0x80100000,
}


def section_bytes(name: str, size: int) -> bytes:
    if name == ".rodata":
        b = bytearray(size)
        struct.pack_into("<H", b, 0x00, 800)  # Cal_IdleSpeed
        struct.pack_into("<f", b, 0x04, 1.25)  # Cal_Gain
        struct.pack_into("<4H4H", b, 0x10, 0, 1000, 2000, 3000, 10, 20, 30, 40)  # Cal_Curve
        b[0x20] = 250  # Cal_Limit (A2L upper limit 200 -> out of limits)
        struct.pack_into("<8H", b, 0x28, *range(8))  # Cal_Table
        struct.pack_into("<H", b, 0x40, 7)  # Cal_Offset
        return bytes(b)
    if name == ".clear_sec":
        return struct.pack("<4I", 0x70000100, 0x80, 0xFFFFFFFF, 0xFFFFFFFF)
    if name == ".copy_sec":
        return struct.pack("<6I", 0x80001300, 0x70000000, 0x40, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    if name == ".data":
        return bytes(range(0x40))
    # code-ish filler: TriCore NOP (0x0000) is erased-looking, use a recognisable pattern instead
    return bytes((0x91 + i * 7) & 0xFF for i in range(size))


# ---------------------------------------------------------------------------
def write_elf(path: Path) -> None:
    shstr = bytearray(b"\0")
    strtab = bytearray(b"\0")

    def add(tab: bytearray, s: str) -> int:
        off = len(tab)
        tab.extend(s.encode() + b"\0")
        return off

    body = bytearray()
    ehsize, phentsize, shentsize = 52, 32, 40
    phnum = len(SECTIONS)
    data_off = ehsize + phnum * phentsize
    sec_entries = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    offsets = {}
    for name, vma, lma, size, flags, nobits, _ in SECTIONS:
        off = data_off + len(body)
        offsets[name] = off
        if not nobits:
            body.extend(section_bytes(name, size))
        sec_entries.append((add(shstr, name), 8 if nobits else 1, flags, vma, off, size, 0, 0, 4, 0))
    sym = bytearray(16)
    sec_index = {s[0]: i + 1 for i, s in enumerate(SECTIONS)}
    for name, addr, size, typ, sec in SYMS:
        sym.extend(struct.pack("<IIIBBH", add(strtab, name), addr, size, (1 << 4) | typ, 0, sec_index[sec]))
    symtab_off = data_off + len(body)
    body.extend(sym)
    strtab_off = data_off + len(body)
    body.extend(strtab)
    n_sec = len(sec_entries)
    sec_entries.append((add(shstr, ".symtab"), 2, 0, 0, symtab_off, len(sym), n_sec + 1, 1, 4, 16))
    sec_entries.append((add(shstr, ".strtab"), 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0))
    shstr_name = add(shstr, ".shstrtab")
    shstr_off = data_off + len(body)
    body.extend(shstr)
    sec_entries.append((shstr_name, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0))
    while len(body) % 4:
        body.append(0)
    shoff = data_off + len(body)
    eh = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
    eh += struct.pack("<HHIIIIIHHHHHH", 2, 44, 1, 0x80000020, ehsize, shoff, 0, ehsize, phentsize, phnum,
                      shentsize, len(sec_entries), len(sec_entries) - 1)
    ph = bytearray()
    for name, vma, lma, size, flags, nobits, _ in SECTIONS:
        ph.extend(struct.pack("<IIIIIIII", 1, offsets[name], vma, lma, 0 if nobits else size, size,
                              (4 if flags & 2 else 0) | (2 if flags & 1 else 0) | (1 if flags & 4 else 0), 4))
    sh = b"".join(struct.pack("<IIIIIIIIII", *e) for e in sec_entries)
    path.write_bytes(eh + ph + body + sh)


# TASKING build: same image, but the HighTec clear/copy tables are replaced by a
# TASKING copy table at _lc_cp in the documented copy(src,dst,len) / clear(dst,len,0)
# form. .CPU1.bss is deliberately left out so the RAM-coverage check must flag it.
TASKING_TABLE_ADDR = 0x80001220
TASKING_TABLE = struct.pack("<9I", 0x80001300, 0x70000000, 0x40, 0x70000100, 0x80, 0, 0, 0, 0)


def flash_bytes(tasking: bool = False) -> dict[int, bytes]:
    out = {}
    for name, vma, lma, size, flags, nobits, _ in SECTIONS:
        if tasking and name in (".clear_sec", ".copy_sec"):
            continue
        if not nobits:
            out[lma] = section_bytes(name, size)
    if tasking:
        out[TASKING_TABLE_ADDR] = TASKING_TABLE
    # post-build: UCB_BMHD0 (STAD in non-cached alias) + a CRC block outside any section
    head = struct.pack("<HHI", 0x00FE, 0xB359, 0xA0000020)
    crc = zlib.crc32(b"".join(head[i:i + 4][::-1] for i in range(0, 8, 4))) & 0xFFFFFFFF
    bmhd = bytearray(head + struct.pack("<II", crc, ~crc & 0xFFFFFFFF)) + bytes(0x1F0 - 16)
    bmhd += struct.pack("<I", 0x43211234)
    out[0xAF400000] = bytes(bmhd)
    out[0x80100000] = struct.pack("<II", 0xDEADBEEF, 0x12345678)
    return out


def write_ihex(path: Path) -> None:
    lines, upper = [], None
    for base, data in sorted(flash_bytes().items()):
        for i in range(0, len(data), 16):
            a = base + i
            if a >> 16 != upper:
                upper = a >> 16
                rec = bytes([2, 0, 0, 4]) + upper.to_bytes(2, "big")
                lines.append(":" + (rec + bytes([(-sum(rec)) & 0xFF])).hex().upper())
            chunk = data[i : i + 16]
            rec = bytes([len(chunk), (a >> 8) & 0xFF, a & 0xFF, 0]) + chunk
            lines.append(":" + (rec + bytes([(-sum(rec)) & 0xFF])).hex().upper())
    lines.append(":00000001FF")
    path.write_text("\n".join(lines) + "\n")


def write_srec(path: Path, tasking: bool = False) -> None:
    lines = []
    for base, data in sorted(flash_bytes(tasking).items()):
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            rec = bytes([len(chunk) + 5]) + (base + i).to_bytes(4, "big") + chunk
            lines.append("S3" + (rec + bytes([~sum(rec) & 0xFF])).hex().upper())
    rec = bytes([5]) + (0x80000020).to_bytes(4, "big")
    lines.append("S7" + (rec + bytes([~sum(rec) & 0xFF])).hex().upper())
    path.write_text("\n".join(lines) + "\n")


def write_gnu_map(path: Path) -> None:
    o = ["Archive member included to satisfy reference by file (symbol)", "",
         "libBsw.a(NvM.o)              obj/EcuM.o (NvM_Init)", "",
         "Discarded input sections", "",
         " .text.unused   0x00000000       0x20 obj/main.o", "",
         "Memory Configuration", "", "Name             Origin             Length             Attributes"]
    for n, a, l, at in REGIONS:
        o.append(f"{n:<16} 0x{a:08x}         0x{l:08x}         {at}")
    o += ["*default*        0x00000000         0xffffffff", "", "Linker script and memory map", "",
          "LOAD obj/main.o", "LOAD libBsw.a", ""]
    syms_by_sec: dict[str, list] = {}
    for s in SYMS:
        syms_by_sec.setdefault(s[4], []).append(s)
    for name, vma, lma, size, flags, nobits, obj in SECTIONS:
        load = f" load address 0x{lma:08x}" if lma != vma else ""
        if len(name) > 14:
            o.append(name)
            o.append(f"                0x{vma:08x}     0x{size:x}{load}")
        else:
            o.append(f"{name:<16}0x{vma:08x}     0x{size:x}{load}")
        if name == ".text":
            o.append(" *(.text .text.*)")
            a = vma
            for iname, isz, iobj in TEXT_INPUTS:
                o.append(f" {iname}")  # long names wrap in real maps
                o.append(f"                0x{a:08x}     0x{isz:x} {iobj}")
                for s in syms_by_sec[".text"]:
                    if s[1] == a:
                        o.append(f"                0x{a:08x}                {s[0]}")
                a += isz
            continue
        iobj = obj or ("obj/NvM.o" if name == ".data" else "obj/Dem.o")
        o.append(f" *({name})")
        o.append(f" {name:<15}0x{vma:08x}     0x{size:x} {iobj}")
        for s in syms_by_sec.get(name, []):
            if s[0].startswith("__"):
                o.append(f"                0x{s[1]:08x}                {s[0]} = .")
            else:
                o.append(f"                0x{s[1]:08x}                {s[0]}")
        o.append("")
    o += ["OUTPUT(build/app.elf elf32-tricore)"]
    path.write_text("\n".join(o) + "\n")


def write_tasking(map_path: Path, lsl_path: Path) -> None:
    chip = {0x8: ("mpe:pfls0", 0x80000000), 0x7: ("mpe:dspr0", 0x70000000), 0x6: ("mpe:dspr1", 0x60000000)}
    o = ["TASKING VX-toolset for TriCore: object linker (ltc) v6.3r1 Build 19092611", "",
         "*********************************  Link Result  *********************************", "",
         "+--------------------------------------------------------------------------------------------+",
         "| [in] File        | [in] Section          | [in] Size (MAU) | [out] Offset | [out] Section          | [out] Size (MAU) |",
         "|============================================================================================|"]
    for name, vma, lma, size, flags, nobits, obj in SECTIONS:
        if name == ".text":
            for iname, isz, iobj in TEXT_INPUTS:
                o.append(f"| {iobj:<16} | {iname:<21} | 0x{isz:08x} | 0x00000000 | {iname} (1) | 0x{isz:08x} |")
        else:
            f = obj or ("NvM.o" if name == ".data" else "Dem.o")
            o.append(f"| {f:<16} | {name:<21} | 0x{size:08x} | 0x00000000 | {name} (2) | 0x{size:08x} |")
    o += ["+--------------------------------------------------------------------------------------------+", "",
          "*********************************  Locate Result  *********************************", "",
          "+ Space mpe:vtc:linear (MAU = 8bit)",
          "+---------------------------------------------------------------------------------------+",
          "| Chip      | Group | Section                  | Size (MAU) | Space addr | Chip addr  | Alignment  |",
          "|=======================================================================================|"]
    for name, vma, lma, size, flags, nobits, obj in SECTIONS:
        if name == ".clear_sec":
            continue
        if name == ".copy_sec":
            o.append(f"| mpe:pfls0 |       | table (4) | 0x{len(TASKING_TABLE):08x} | 0x{TASKING_TABLE_ADDR:08x} | "
                     f"0x{TASKING_TABLE_ADDR - 0x80000000:08x} | 0x00000004 |")
            continue
        if name == ".text":
            a = vma
            for iname, isz, iobj in TEXT_INPUTS:
                o.append(f"| mpe:pfls0 |       | {iname} (1) | 0x{isz:08x} | 0x{a:08x} | 0x{a - 0x80000000:08x} | 0x00000002 |")
                a += isz
            continue
        c, base = chip[vma >> 28]
        o.append(f"| {c} |       | {name} (2) | 0x{size:08x} | 0x{vma:08x} | 0x{vma - base:08x} | 0x00000004 |")
        if lma != vma:
            o.append(f"| mpe:pfls0 |       | [{name}] (3) | 0x{size:08x} | 0x{lma:08x} | 0x{lma - 0x80000000:08x} | 0x00000004 |")
    o += ["+---------------------------------------------------------------------------------------+", "",
          "* Symbols (sorted on name)", "",
          "+ Space mpe:vtc:linear (MAU = 8bit)",
          "+-------------------------------------------------------------+",
          "| Name                  | Space addr | Chip addr  | Chip      |",
          "|=============================================================|"]
    ren = {"__CSA0": "_lc_ub_csa_tc0", "__CSA0_END": "_lc_ue_csa_tc0", "__CSA1": "_lc_ub_csa_tc1",
           "__CSA1_END": "_lc_ue_csa_tc1", "__USTACK0_END": "_lc_ub_ustack_tc0", "__USTACK0": "_lc_ue_ustack_tc0",
           "__TRAPTAB_CPU0": "_lc_u_trap_tab_tc0", "__INTTAB_CPU0": "_lc_u_int_tab_tc0"}
    for name, addr, size, typ, sec in sorted(SYMS):
        if name == "__clear_table":
            continue
        if name == "__copy_table":
            name = "_lc_cp"
        c, base = chip[addr >> 28]
        o.append(f"| {ren.get(name, name):<21} | 0x{addr:08x} | 0x{addr - base:08x} | {c} |")
        if name == "Rte_Core1_Buffer":  # wrapped long section names exercise the parser
            pass
    o += ["+-------------------------------------------------------------+", "",
          "* Memory usage in bytes", "",
          "+------------------------------------------------------------------+",
          "| Memory      | Code     | Data     | Reserved | Free     | Total    |",
          "|==================================================================|",
          "| mpe:pfls0   | 0x000600 | 0x000190 | 0x000000 | 0x2ff870 | 0x300000 |",
          "| mpe:dspr0   | 0x000000 | 0x0038c0 | 0x000000 | 0x038740 | 0x03c000 |",
          "| mpe:dspr1   | 0x000000 | 0x000020 | 0x000000 | 0x03bfe0 | 0x03c000 |",
          "|------------------------------------------------------------------|",
          "| Total       | 0x000600 | 0x003a70 | 0x000000 |          |          |",
          "+------------------------------------------------------------------+"]
    map_path.write_text("\n".join(o) + "\n")
    lsl_path.write_text("""// synthetic TC38x LSL fragment
#define LCF_PFLASH0_SIZE 3M
memory pfls0 // Program flash 0
{
    mau = 8;
    size = LCF_PFLASH0_SIZE;
    type = rom;
    map cached (dest=bus:sri, dest_offset=0x80000000, size=3M);
    map not_cached (dest=bus:sri, dest_offset=0xa0000000, reserved, size=3M);
}
memory dspr0
{
    mau = 8;
    size = 240k;
    type = ram;
    map (dest=bus:sri, dest_offset=0x70000000, size=240k);
}
memory lmuram
{
    mau = 8;
    size = 64k;
    type = ram;
    map cached (dest=bus:sri, dest_offset=0x90040000, size=64k);
    map not_cached (dest=bus:sri, dest_offset=0xb0040000, size=64k);
}
section_layout ::linear
{
    group CPU0_BSS (ordered, run_addr=mem:dspr0) { select ".bss.*"; select ".zbss.*"; }
}
""")


A2L = r'''ASAP2_VERSION 1 71
/begin PROJECT Synthetic "rea-auto fixture"
 /begin MODULE ECU "synthetic TC38x"
  /begin MOD_COMMON "" BYTE_ORDER MSB_LAST ALIGNMENT_BYTE 1 /end MOD_COMMON
  /begin MOD_PAR ""
   /begin MEMORY_SEGMENT CalData "calibration" DATA FLASH INTERN 0x80001000 0x100 -1 -1 -1 -1 -1 /end MEMORY_SEGMENT
   /begin MEMORY_SEGMENT Ram0 "cpu0 dspr" VARIABLES RAM INTERN 0x70000000 0x3C000 -1 -1 -1 -1 -1 /end MEMORY_SEGMENT
  /end MOD_PAR
  /begin COMPU_METHOD CM_rpm "" LINEAR "%6.1" "rpm" COEFFS_LINEAR 1 0 /end COMPU_METHOD
  /begin COMPU_METHOD CM_ident "" IDENTICAL "%6.3" "" /end COMPU_METHOD
  /begin COMPU_METHOD CM_pct "" RAT_FUNC "%5.1" "%" COEFFS 0 2 0 0 0 1 /end COMPU_METHOD
  /begin RECORD_LAYOUT RL_UWORD FNC_VALUES 1 UWORD ROW_DIR DIRECT /end RECORD_LAYOUT
  /begin RECORD_LAYOUT RL_UBYTE FNC_VALUES 1 UBYTE ROW_DIR DIRECT /end RECORD_LAYOUT
  /begin RECORD_LAYOUT RL_FLOAT FNC_VALUES 1 FLOAT32_IEEE ROW_DIR DIRECT /end RECORD_LAYOUT
  /begin RECORD_LAYOUT RL_CURVE_UW AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT FNC_VALUES 2 UWORD COLUMN_DIR DIRECT /end RECORD_LAYOUT
  /* calibration */
  /begin CHARACTERISTIC Cal_IdleSpeed "idle speed" VALUE 0x80001000 RL_UWORD 0 CM_rpm 0 2000 /end CHARACTERISTIC
  /begin CHARACTERISTIC Cal_Gain "gain, non-cached alias" VALUE 0xA0001004 RL_FLOAT 0 CM_ident 0 10 /end CHARACTERISTIC
  /begin CHARACTERISTIC Cal_Curve "curve" CURVE 0x80001010 RL_CURVE_UW 0 CM_ident 0 100
   /begin AXIS_DESCR STD_AXIS NO_INPUT_QUANTITY CM_rpm 4 0 6000 /end AXIS_DESCR
  /end CHARACTERISTIC
  /begin CHARACTERISTIC Cal_Limit "limit" VALUE 0x80001020 RL_UBYTE 0 CM_pct 0 100 /end CHARACTERISTIC
  /begin CHARACTERISTIC Cal_Stale "renamed in code" VALUE 0x8000102A RL_UWORD 0 CM_ident 0 100 /end CHARACTERISTIC
  /begin CHARACTERISTIC Cal_Offset "stale address" VALUE 0x80001044 RL_UWORD 0 CM_ident 0 100 /end CHARACTERISTIC
  /begin CHARACTERISTIC Cal_NotFilled "address never updated" VALUE 0x0 RL_UWORD 0 CM_ident 0 100 /end CHARACTERISTIC
  /* measurement */
  /begin MEASUREMENT NvM_RamBlock "" UBYTE CM_ident 0 0 0 255 ECU_ADDRESS 0x70000000 ARRAY_SIZE 16 /end MEASUREMENT
  /begin MEASUREMENT Com_RxBuf.byte3 "" UBYTE CM_ident 0 0 0 255 ECU_ADDRESS 0x70000013 /end MEASUREMENT
  /begin MEASUREMENT Dem_EventStatus "" UBYTE CM_ident 0 0 0 255 ECU_ADDRESS 0x70000100 ARRAY_SIZE 64 /end MEASUREMENT
  /begin MEASUREMENT Ghost_Signal "" UWORD CM_ident 0 0 0 65535 ECU_ADDRESS 0x70000300 /end MEASUREMENT
 /end MODULE
/end PROJECT
'''


def write_synthetic_profile(path: Path) -> None:
    """Shipped TC38x profile with every unknown (null) fact filled by a synthetic value."""
    import json
    root = Path(__file__).resolve().parents[2]
    prof = json.loads((root / "reauto/silicon/infineon/aurix/targets/tc38x.json").read_text())
    prof["id"] += ".synthetic"
    prof["sources"]["SYNTHETIC"] = {"vendor": "rea-auto tests", "document": "synthetic fixture values", "tier": "synthetic"}
    syn = lambda v, ref: {"value": v, "source": "SYNTHETIC", "ref": ref, "verification": "synthetic"}
    for c, base in zip(prof["cpus"], (0x70000000, 0x60000000, 0x50000000, 0x40000000)):
        c["dspr"]["base"] = c["dspr"]["base"] or syn(base, "test DSPR base")
        c["pspr"]["base"] = c["pspr"]["base"] or syn(base + 0x100000, "test PSPR base")
        c["local_alias"]["pspr"] = c["local_alias"]["pspr"] or syn(0xC0000000, "test PSPR local alias")
    prof["flash"]["pflash"]["base"] = syn(0x80000000, "test PFLASH base")
    prof["flash"]["dflash0"]["base"] = syn(0xAF000000, "test DFLASH0 base")
    prof["bus_alias"] = syn([{"cached": 0x80000000, "noncached": 0xA0000000, "size": 10 << 20}], "test bus alias")
    path.write_text(json.dumps(prof, indent=1))


def write_manifest(path: Path) -> None:
    """Ground truth for the synthetic build, in the same format a real fixture uses."""
    import json
    sym = {n: a for n, a, *_ in SYMS}
    m = {
        "name": "synthetic-tc38x-gnu", "fixture_class": "synthetic", "device": "profile_synthetic_tc38x.json",
        "toolchain": "gnu", "experimental": True,
        "artifacts": {"image": "app.hex", "elf": "app.elf", "map": "app_gnu.map", "a2l": "app.a2l"},
        "provenance": {"source": "generated by fixtures/synthetic/make_fixtures.py"},
        "expect": {
            "L0": {"regions": [{"name": n, "origin": hex(a), "length": hex(l)} for n, a, l, _ in REGIONS],
                   "sections": [{"name": n, "vma": hex(v), "lma": hex(l), "size": hex(z)}
                                for n, v, l, z, *_ in SECTIONS],
                   "symbols": [{"name": n, "addr": hex(sym[n])} for n in
                               ("NvM_MainFunction", "Cal_Gain", "Com_RxBuf", "__CSA0")]},
            "L1": {"entry": "0x80000020",
                   "bmhd": [{"addr": "0xAF400000", "stad": "0xA0000020", "crc_status": "match"}],
                   "csa": [{"core": 0, "start": "0x70010000", "size": "0x2000"},
                           {"core": 1, "start": "0x70014000", "size": "0x800"}],
                   "stacks": [{"core": 0, "kind": "user", "bottom": "0x70012000", "top": "0x70013000"}],
                   "vectors": [{"core": 0, "kind": "trap", "addr": "0x80000100"},
                               {"core": 0, "kind": "interrupt", "addr": "0x80002000"}],
                   "init": {"copy": [{"src": "0x80001300", "dst": "0x70000000", "size": "0x40"}],
                            "clear": [{"addr": "0x70000100", "size": "0x80"}]}},
            "L2": {"a2l": [{"name": "Cal_IdleSpeed", "symbol_addr": "0x80001000", "phys": 800.0},
                           {"name": "Cal_Gain", "symbol_addr": "0x80001004", "phys": 1.25}],
                   "modules": [{"module": "NvM", "class": "text", "bytes": "0x100"},
                               {"module": "Dem", "class": "bss", "bytes": "0x80"}]},
        },
        "allowed_findings": ["Cal_Offset", "A2L correlation:", "synthetic"],
    }
    path.write_text(json.dumps(m, indent=1))


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write_elf(OUT / "app.elf")
    write_ihex(OUT / "app.hex")
    write_srec(OUT / "app.s19")
    write_srec(OUT / "app_tasking.s19", tasking=True)
    write_gnu_map(OUT / "app_gnu.map")
    write_tasking(OUT / "app_tasking.map", OUT / "app.lsl")
    (OUT / "app.a2l").write_text(A2L)
    write_synthetic_profile(OUT / "profile_synthetic_tc38x.json")
    write_manifest(OUT / "manifest.json")
    print(f"fixtures written to {OUT}")


if __name__ == "__main__":
    main()
