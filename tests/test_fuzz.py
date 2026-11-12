"""Fuzz class: property-based invariants for every parser.

For arbitrary or mutated input a parser must
  - return a model, or raise its documented rejection (RecordError / ElfFormatError) only
    when the input is not that format at all;
  - never raise any other exception;
  - never fabricate: every name and address it reports appears in the input;
  - never lose input silently: (HEX/S19) every non-blank line is an accepted record or a ParseEvent.
"""

import os

from hypothesis import HealthCheck, given, settings, strategies as st

from conftest import ROOT
from reauto.formats.a2l.parser import parse_a2l
from reauto.formats.elf import ElfFormatError, load_elf
from reauto.formats.hexrec import RecordError, load_ihex, load_srec
from reauto.toolchains.gnu.map import parse_gnu_map
from reauto.toolchains.tasking.map import parse_lsl, parse_tasking_map

SEEDS = ROOT / "fixtures/fuzz/seeds"
CFG = settings(max_examples=int(os.environ.get("REA_FUZZ_EXAMPLES", "150")), deadline=None,
               suppress_health_check=[HealthCheck.function_scoped_fixture])


def mutate(text: str):
    lines = text.splitlines()
    return st.lists(st.tuples(st.integers(0, 3), st.integers(0, max(len(lines) - 1, 0)), st.text(max_size=12)),
                    max_size=6).map(lambda ops: _apply(lines, ops))


def _apply(lines, ops):
    out = list(lines)
    for op, i, s in ops:
        if not out:
            break
        i %= len(out)
        if op == 0:
            del out[i]
        elif op == 1:
            out.insert(i, out[i])
        elif op == 2:
            out[i] = out[i][: len(out[i]) // 2] + s + out[i][len(out[i]) // 2:]
        else:
            out[i] = s
    return "\n".join(out) + "\n"


def _write(tmp_path, name, text):
    f = tmp_path / name
    f.write_text(text, errors="replace") if isinstance(text, str) else f.write_bytes(text)
    return f


@CFG
@given(text=mutate((SEEDS / "minimal.hex").read_text()))
def test_ihex(tmp_path, text):
    f = _write(tmp_path, "x.hex", text)
    events = []
    try:
        img = load_ihex(f, "x", None, events)
    except RecordError:
        return
    nonblank = sum(1 for l in text.splitlines() if l.strip())
    assert img.stats["accepted_records"] + len(events) == nonblank  # nothing lost silently


@CFG
@given(text=mutate((SEEDS / "minimal.s19").read_text()))
def test_srec(tmp_path, text):
    f = _write(tmp_path, "x.s19", text)
    events = []
    try:
        img = load_srec(f, "x", None, events)
    except RecordError:
        return
    nonblank = sum(1 for l in text.splitlines() if l.strip())
    assert img.stats["accepted_records"] + len(events) == nonblank


def _no_fabrication(text, names, addrs):
    for n in names:
        assert n in text, n
    low = text.lower()
    for a in addrs:
        assert f"{a:x}" in low, hex(a)


@CFG
@given(text=mutate((SEEDS / "minimal_gnu.map").read_text()) | st.text(max_size=400))
def test_gnu_map(tmp_path, text):
    lm = parse_gnu_map(_write(tmp_path, "x.map", text), "x")
    _no_fabrication(text, [s.name for s in lm.sections] + [s.name for s in lm.symbols] + [r.name for r in lm.regions],
                    [s.addr for s in lm.sections] + [s.addr for s in lm.symbols] + [r.origin for r in lm.regions])
    assert all(1 <= e.line <= max(1, len(text.splitlines())) for e in lm.events)


@CFG
@given(text=mutate((SEEDS / "minimal_tasking.map").read_text()) | st.text(max_size=400))
def test_tasking_map(tmp_path, text):
    lm = parse_tasking_map(_write(tmp_path, "x.map", text), "x")
    _no_fabrication(text, [s.name for s in lm.sections] + [s.name for s in lm.symbols],
                    [s.addr for s in lm.sections] + [s.addr for s in lm.symbols])


@CFG
@given(text=mutate((SEEDS / "minimal.lsl").read_text()) | st.text(max_size=300))
def test_lsl(tmp_path, text):
    lsl = parse_lsl(_write(tmp_path, "x.lsl", text))
    _no_fabrication(text, [m["name"] for m in lsl["memories"]], [])


@CFG
@given(text=mutate((SEEDS / "minimal.a2l").read_text()) | st.text(max_size=300))
def test_a2l(tmp_path, text):
    a = parse_a2l(_write(tmp_path, "x.a2l", text))
    _no_fabrication(text, [o.name for o in a.objects()], [])


@CFG
@given(data=st.binary(max_size=600))
def test_elf(tmp_path, data):
    f = _write(tmp_path, "x.elf", b"\x7fELF\x01\x01\x01\x00" + data)
    try:
        elf = load_elf(f)
    except ElfFormatError:
        return
    raw = f.read_bytes()
    for s in elf.symbols:  # names come from the file's string table
        assert s.name.encode(errors="replace") in raw or "�" in s.name
