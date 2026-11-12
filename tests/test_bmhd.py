"""Synthetic class: BMHD and CRC modes (L1)."""
import json
import struct

import pytest

from conftest import find, has
from reauto.analyze import open_project, run_all
from reauto.silicon.infineon.aurix.crc import ALGORITHMS, DISCOVERY_CANDIDATES, crc32


def test_crc_check_values():
    assert crc32(b"123456789", reflected=True) == 0xCBF43926
    assert crc32(b"123456789", reflected=False) == 0xFC891918


def test_documented_algorithm_matches_public_vector():
    # HighTec public tc39x BMHD example: BMI 0x00FE, BMHDID 0xB359, STAD 0xA0000000 -> 0x31795570 / 0xCE86AA8F
    head = struct.pack("<HHI", 0x00FE, 0xB359, 0xA0000000)
    assert ALGORITHMS["aurix_tc3xx_bmhd"].compute(head) == 0x31795570
    assert ~0x31795570 & 0xFFFFFFFF == 0xCE86AA8F
    assert [c.name for c in DISCOVERY_CANDIDATES if c.compute(head) == 0x31795570] == ["refl/32-bit words, MSB first"]


def _patched(gen, tmp_path, crc_fn, pair=True):
    from reauto.formats.hexrec import load_ihex
    from reauto.formats.image import MemoryImage
    img = load_ihex(gen / "app.hex", "x", MemoryImage())
    seg = img.find(0xAF400000)
    c = crc_fn(bytes(seg.data[0:8]))
    seg.data[8:16] = struct.pack("<II", c, (~c & 0xFFFFFFFF) if pair else c)
    lines, upper = [], None
    for s in img.segments:
        for i in range(0, len(s.data), 16):
            a = s.start + i
            if a >> 16 != upper:
                upper = a >> 16
                r = bytes([2, 0, 0, 4]) + upper.to_bytes(2, "big")
                lines.append(":" + (r + bytes([(-sum(r)) & 0xFF])).hex())
            ch = bytes(s.data[i:i + 16])
            r = bytes([len(ch), (a >> 8) & 0xFF, a & 0xFF, 0]) + ch
            lines.append(":" + (r + bytes([(-sum(r)) & 0xFF])).hex())
    out = tmp_path / "p.hex"
    out.write_text("\n".join(lines + [":00000001FF"]) + "\n")
    return out


def test_profile_mode_match(gen):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf")
    run_all(p)
    f = find(p, r"CRCBMHD matches documented algorithm aurix_tc3xx_bmhd", topic="startup")
    assert f.kind == "derived"


def test_profile_mode_mismatch_is_error(gen, tmp_path):
    hx = _patched(gen, tmp_path, lambda h: crc32(h))  # plain CRC-32, wrong byte order
    p = open_project(image=hx, elf=gen / "app.elf")
    run_all(p)
    f = find(p, r"does NOT match documented algorithm", topic="startup")
    assert f.severity == "error"


def test_discover_mode_is_inferred_and_logs_all_candidates(gen, tmp_path):
    hx = _patched(gen, tmp_path, lambda h: crc32(h, reflected=False))
    p = open_project(image=hx, elf=gen / "app.elf", bmhd_crc_mode="discover")
    run_all(p)
    f = find(p, r"CRC discovery tested 8 candidates", topic="startup")
    assert f.kind == "inferred" and len(f.data["candidates"]) == 8
    assert sum(c["result"] == "MATCH" for c in f.data["candidates"]) >= 1


def test_strict_mode_without_algorithm_is_error(gen, tmp_path):
    prof = json.loads(open(gen / "profile_synthetic_tc38x.json").read())
    prof["bmhd"]["crc"]["algorithm"] = None
    pf = tmp_path / "noalg.json"
    pf.write_text(json.dumps(prof))
    p = open_project(image=gen / "app.hex", device=str(pf), bmhd_crc_mode="strict")
    run_all(p)
    assert find(p, r"no documented CRC algorithm", topic="startup").severity == "error"
    p2 = open_project(image=gen / "app.hex", device=str(pf), bmhd_crc_mode="profile")
    run_all(p2)
    assert find(p2, r"no documented CRC algorithm", topic="startup").kind == "unknown"


def test_broken_pair(gen, tmp_path):
    hx = _patched(gen, tmp_path, lambda h: 0x1234, pair=False)
    p = open_project(image=hx)
    run_all(p)
    assert has(p, r"CRCBMHD_N is not the bitwise inverse", topic="startup", min_severity="error")


def test_bmi_decode_and_stad_relation(gen, syn_profile):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf")
    run_all(p)
    assert has(p, r"HWCFG=111 -> internal start from flash", topic="startup")
    assert find(p, r"STAD 0xa0000020 vs ELF entry", topic="startup").kind == "unknown"  # no documented alias
    q = open_project(image=gen / "app.hex", elf=gen / "app.elf", device=syn_profile)
    run_all(q)
    assert has(q, r"STAD 0xa0000020 and ELF entry 0x80000020 are the same location", topic="startup")
