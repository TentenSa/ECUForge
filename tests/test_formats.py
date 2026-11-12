"""Synthetic class: formats and malformed inputs (L0)."""
import pytest

from ecuforge.analyze import open_project
from ecuforge.formats.hexrec import RecordError, load_ihex, load_srec


def test_hex_and_srec_decode_identically(gen):
    a = open_project(image=gen / "app.hex")
    b = open_project(image=gen / "app.s19")
    assert a.image.regions()[0][:2] == b.image.regions()[0][:2]
    assert a.image.read(0x80001000, 2) == b.image.read(0x80001000, 2) == (800).to_bytes(2, "little")
    assert b.image.entry == 0x80000020


@pytest.mark.parametrize("text,loader", [(":0400000001020304F0\n:00000001FF\n", load_ihex),
                                         (":0400000001020304\n", load_ihex),
                                         ("S1070000010203FF\n", load_srec)])
def test_malformed_records_rejected(tmp_path, text, loader):
    f = tmp_path / "bad"
    f.write_text(text)
    with pytest.raises((RecordError, ValueError)):
        loader(f, "x")


def test_elf_tricore(gen):
    p = open_project(elf=gen / "app.elf")
    assert p.elf.machine == 44 and p.elf.entry == 0x80000020
    assert p.symbols()["NvM_MainFunction"].size == 0x100


def test_sources_carry_type_digest_parser(gen):
    p = open_project(image=gen / "app.hex", elf=gen / "app.elf", map_=gen / "app_gnu.map")
    f = next(f for f in p.store.findings if f.claim.startswith("HEX image"))
    s = f.sources[0]
    assert s.type == "HEX" and len(s.sha256) == 64 and s.parser.startswith("formats.hexrec.hex@")
    assert next(f for f in p.store.findings if "gnu map" in f.claim).sources[0].type == "MAP"
