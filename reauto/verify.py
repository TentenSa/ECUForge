"""Score rea-auto against a fixture manifest of independently known facts.

Every expected fact ends in exactly one category:
  correct           rea-auto reports the expected value
  expected_unknown  rea-auto reports no value, and the manifest lists this fact under
                    verification.expected_unknowns with an id and a reason
  unknown           rea-auto reports no value, not listed as expected
  conflict          rea-auto reports contradictory evidence about this item
  false_claim       rea-auto confidently reports a different value  (most serious)

The manifest's expected values must come from a source independent of rea-auto:
the reference firmware's own source and linker script, a vendor dump tool, or
the generator of a synthetic fixture. Errors or conflicts rea-auto raises that
the manifest does not list in `allowed_findings` are reported as unexplained.

Policy (manifest `verification` block):
  allow_unexpected_unknown: bool  default true; release gates set false
  expected_unknowns: [{id, what, reason}]  each unknown accepted individually

PASS requires zero false claims, zero conflicts, zero unexplained findings and,
when allow_unexpected_unknown is false, zero unexpected unknowns. There is no
blanket switch: the old `allow_unknown` key is rejected.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .analyze import open_project, run_all

CATEGORIES = ("correct", "expected_unknown", "unknown", "conflict", "false_claim")


def _n(v):
    return int(v, 0) if isinstance(v, str) else v


def load_manifest(path) -> dict:
    path = Path(path)
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as e:
            raise SystemExit("YAML manifests need PyYAML (pip install pyyaml); or use JSON") from e
        return yaml.safe_load(path.read_text())
    return json.loads(path.read_text())


@dataclass
class Check:
    level: str
    subject: str
    what: str
    expected: object
    actual: object
    category: str = ""


@dataclass
class VerifyResult:
    checks: list[Check] = field(default_factory=list)
    unexplained: list[str] = field(default_factory=list)
    allow_unexpected_unknown: bool = True
    expected_unknowns_recovered: list[str] = field(default_factory=list)

    def score(self) -> dict:
        out = {"expected_facts": len(self.checks), **{c: 0 for c in CATEGORIES}, "by_level": {}}
        for c in self.checks:
            out[c.category] += 1
            lv = out["by_level"].setdefault(c.level, {k: 0 for k in CATEGORIES})
            lv[c.category] += 1
        out["unexplained"] = len(self.unexplained)
        return out

    @property
    def ok(self) -> bool:
        s = self.score()
        if s["false_claim"] or s["conflict"] or s["unexplained"]:
            return False
        return self.allow_unexpected_unknown or s["unknown"] == 0


def verify(manifest_path):
    mpath = Path(manifest_path)
    m = load_manifest(mpath)
    base = mpath.parent
    if "allow_unknown" in m:
        raise SystemExit(f"{mpath}: 'allow_unknown' is not supported; use verification.allow_unexpected_unknown "
                         "and list each accepted unknown in verification.expected_unknowns")
    pol = m.get("verification") or {}
    expected_unknown = {e["what"]: e for e in pol.get("expected_unknowns", [])}
    for e in expected_unknown.values():
        if not (e.get("id") and e.get("reason")):
            raise SystemExit(f"{mpath}: every expected unknown needs an id and a reason: {e}")
    art = {k: str(base / v) for k, v in (m.get("artifacts") or {}).items() if v}
    p = open_project(art.get("image"), art.get("elf"), art.get("map"), art.get("lsl"), art.get("a2l"),
                     str(base / m["device"]) if str(m.get("device", "")).endswith(".json") else m.get("device", "tc38x"),
                     m.get("toolchain"), m.get("bmhd_crc_mode"), bool(m.get("experimental")))
    res = run_all(p)
    vr = VerifyResult(allow_unexpected_unknown=bool(pol.get("allow_unexpected_unknown", True)))
    conflicts = [f.claim for f in p.store.query(kind="conflict")]
    add = lambda lv, subj, what, e, a: vr.checks.append(Check(lv, subj, what, e, a))
    exp = m.get("expect", {})

    # L0 artifact facts
    L0 = exp.get("L0", {})
    regions = {r.name: r for r in (p.map.regions if p.map else [])}
    for r in L0.get("regions", []):
        g = regions.get(r["name"])
        add("L0", r["name"], f"region {r['name']}", (_n(r["origin"]), _n(r["length"])), (g.origin, g.length) if g else None)
    secs = {s.name: s for s in res["layout"].sections}
    for s in L0.get("sections", []):
        g = secs.get(s["name"])
        keys = [k for k in ("vma", "lma", "size") if k in s]
        add("L0", s["name"], f"section {s['name']}", tuple(_n(s[k]) for k in keys),
            tuple(getattr(g, k) for k in keys) if g else None)
    syms = p.symbols()
    for s in L0.get("symbols", []):
        g = syms.get(s["name"])
        add("L0", s["name"], f"symbol {s['name']}", _n(s["addr"]), g.addr if g else None)

    for r in L0.get("image", []):  # address range expected fully present in the programmed image
        a, n = _n(r["addr"]), _n(r["size"])
        add("L0", f"image {r['addr']}", f"image {r['addr']}+{r['size']}", n, p.image.coverage(a, n) or None)

    # L1 structural recovery
    L1 = exp.get("L1", {})
    stc = res["startup"]
    if "entry" in L1:
        add("L1", "entry", "ELF entry", _n(L1["entry"]), p.elf.entry if p.elf else None)
    bm = {b["addr"]: b for b in stc["bmhd"]}
    for b in L1.get("bmhd", []):
        g = bm.get(_n(b["addr"]))
        add("L1", g["slot"] if g else str(b["addr"]), f"BMHD {b['addr']}",
            (_n(b["stad"]), b.get("crc_status", "match")), (g["stad"], g["crc_status"]) if g else None)
    for c in L1.get("csa", []):
        g = stc["csa_stacks"]["csa"].get(c["core"])
        add("L1", f"CPU{c['core']} CSA", f"CSA CPU{c['core']}", (_n(c["start"]), _n(c["size"])),
            (g["start"], g["size"]) if g else None)
    for s in L1.get("stacks", []):
        g = stc["csa_stacks"]["stacks"].get(f"{s['kind']}{s['core']}")
        add("L1", f"CPU{s['core']} {s['kind']} stack", f"{s['kind']} stack CPU{s['core']}",
            (_n(s["bottom"]), _n(s["top"])), (g["bottom"], g["top"]) if g else None)
    vec = {(v["core"], v["kind"]): v["addr"] for v in stc["vectors"]}
    for v in L1.get("vectors", []):
        add("L1", f"CPU{v['core']} {v['kind']}", f"{v['kind']} table CPU{v['core']}", _n(v["addr"]),
            vec.get((v["core"], v["kind"])))
    tables = [t for t in stc["init"]["tables"] if t["kind"] == "derived"]
    copies = [(e["src"], e["dst"], e["size"]) for t in tables for e in t["copy"]]
    clears = [(e["addr"], e["size"]) for t in tables for e in t["clear"]]
    for c in (L1.get("init") or {}).get("copy", []):
        e = (_n(c["src"]), _n(c["dst"]), _n(c["size"]))
        add("L1", "init table", f"copy {c['src']}->{c['dst']}", e, e if e in copies else (None if not tables else "absent"))
    for c in (L1.get("init") or {}).get("clear", []):
        e = (_n(c["addr"]), _n(c["size"]))
        add("L1", "init table", f"clear {c['addr']}", e, e if e in clears else (None if not tables else "absent"))

    # L2 semantic recovery
    L2 = exp.get("L2", {})
    if L2.get("a2l"):
        values = {f.claim.split(" = ")[0]: f.data for f in p.store.query(topic="a2l") if "raw" in f.data}
        for o in L2["a2l"]:
            if "symbol_addr" in o:
                g = syms.get(o.get("symbol", o["name"]))
                add("L2", o["name"], f"A2L {o['name']} symbol", _n(o["symbol_addr"]), g.addr if g else None)
            if "phys" in o:
                v = values.get(o["name"], {}).get("phys")
                add("L2", o["name"], f"A2L {o['name']} value", o["phys"], None if v is None else round(v, 6))
    for mm in L2.get("modules", []):
        add("L2", mm["module"], f"module {mm['module']} {mm['class']}", _n(mm["bytes"]),
            res["modules"].get(mm["module"], {}).get(mm["class"]))

    for c in vr.checks:
        if c.actual == c.expected:
            c.category = "correct"
            if c.what in expected_unknown:
                vr.expected_unknowns_recovered.append(expected_unknown[c.what]["id"])
        elif any(c.subject in x for x in conflicts):
            c.category = "conflict"
        elif c.actual is None:
            c.category = "expected_unknown" if c.what in expected_unknown else "unknown"
        else:
            c.category = "false_claim"

    allowed = [re.compile(a) for a in m.get("allowed_findings", [])]
    for f in p.store.findings:
        if f.severity == "error" or f.kind == "conflict":
            line = f"{f.id} [{f.kind}/{f.severity}] {f.claim}"
            if not any(a.search(line) for a in allowed):
                vr.unexplained.append(line)

    record = res["run"] | {"manifest": {"name": m.get("name"), "sha256": hashlib.sha256(mpath.read_bytes()).hexdigest(),
                                        "fixture_class": m.get("fixture_class")},
                           "policy": {"allow_unexpected_unknown": vr.allow_unexpected_unknown,
                                      "expected_unknowns": list(expected_unknown.values())},
                           "expected_unknowns_recovered": vr.expected_unknowns_recovered,
                           "score": vr.score(), "result": "PASS" if vr.ok else "FAIL",
                           "failures": [{"level": c.level, "what": c.what, "category": c.category,
                                         "expected": _fmt(c.expected), "actual": _fmt(c.actual)}
                                        for c in vr.checks if c.category != "correct"],
                           "unexplained": vr.unexplained}
    return vr, record


def render(vr: VerifyResult, name) -> str:
    s = vr.score()
    o = [f"# verify: {name}", "",
         f"{s['expected_facts']} expected facts: {s['correct']} correct, {s['expected_unknown']} expected unknown, "
         f"{s['unknown']} unexpected unknown, {s['conflict']} conflict, {s['false_claim']} false claims; "
         f"{s['unexplained']} unexplained findings",
         f"policy: allow_unexpected_unknown={vr.allow_unexpected_unknown}", ""]
    for lv, d in sorted(s["by_level"].items()):
        o.append(f"{lv}: " + ", ".join(f"{k} {v}" for k, v in d.items()))
    o.append("")
    for c in sorted(vr.checks, key=lambda c: CATEGORIES.index(c.category), reverse=True):
        if c.category != "correct":
            o.append(f"{c.category.upper():12} {c.level} {c.what}: expected {_fmt(c.expected)}, rea-auto {_fmt(c.actual)}")
    for u in vr.unexplained:
        o.append(f"UNEXPLAINED  {u}")
    for i in vr.expected_unknowns_recovered:
        o.append(f"NOTE         expected unknown {i} was recovered; consider removing it from expected_unknowns")
    o += ["", "RESULT: " + ("PASS" if vr.ok else "FAIL")]
    return "\n".join(o)


def _fmt(v):
    if isinstance(v, bool) or v is None:
        return repr(v)
    if isinstance(v, int):
        return hex(v)
    if isinstance(v, tuple):
        return "(" + ", ".join(_fmt(x) for x in v) + ")"
    return repr(v)
