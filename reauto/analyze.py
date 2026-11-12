"""Pipeline, report and run record."""
from __future__ import annotations

from .architecture.tricore.startup import recover_csa_stacks, recover_entries, recover_vectors
from .core.layout import linker_draft, recover_layout
from .core.project import Options, Project
from .core.raminit import recover_init
from .core.symbols import correlate_symbols
from .silicon.infineon.aurix.bmhd import recover_bmhd


def open_project(image=None, elf=None, map_=None, lsl=None, a2l=None, device="tc38x", toolchain=None,
                 bmhd_crc_mode=None, experimental=False) -> Project:
    p = Project(device, Options(bmhd_crc_mode=bmhd_crc_mode, experimental=experimental, toolchain=toolchain))
    if image:
        p.add_image(str(image))
    if elf and str(elf) != str(image):
        p.add_elf(str(elf))
    if map_:
        p.add_map(str(map_), toolchain)
    if lsl:
        p.add_lsl(str(lsl))
    if a2l:
        p.add_a2l(str(a2l))
    return p


def run_all(p: Project) -> dict:
    lay = recover_layout(p)
    bmhds = recover_bmhd(p)
    res = {
        "layout": lay,
        "symbols": correlate_symbols(p),
        "startup": {"bmhd": bmhds, "entries": recover_entries(p, bmhds), "csa_stacks": recover_csa_stacks(p),
                    "vectors": recover_vectors(p), "init": recover_init(p)},
        "a2l": {}, "modules": {},
        "linker_draft": linker_draft(p, lay) if lay.regions else None,
    }
    if p.options.experimental:
        from .semantics.a2l import correlate_a2l
        from .semantics.autosar import module_footprint
        res["a2l"] = correlate_a2l(p)
        res["modules"] = module_footprint(p)
    elif p.a2l is not None:
        p.store.add("a2l", "unknown", "note", "A2L loaded but L2 semantics are experimental in 0.1.x; "
                    "run with --experimental to correlate it", [], level="L2")
    res["run"] = p.run_record()
    return res


def _h(v):
    return f"0x{v:08X}" if isinstance(v, int) else (v if v is not None else "-")


def render_markdown(p: Project, res: dict, max_rows: int = 200) -> str:
    st, s = p.store, p.store.summary()
    run = res["run"]
    o = ["# rea-auto analysis report", "",
         f"rea-auto {run['tool']['version']} | target {run['target']['architecture']} / {run['target']['silicon']} "
         f"(profile v{run['profile']['version']}, sha256 {run['profile']['sha256'][:12]}, "
         f"{run['profile']['unknown_facts']} facts unknown) | options {run['analysis']['options']}", "",
         "## Inputs", "| Type | File | SHA-256 | Parser |", "|---|---|---|---|"]
    for a in run["artifacts"]:
        o.append(f"| {a['type']} | {a['path']} | `{a['sha256'][:16]}` | {a['parser']} |")
    o += ["", f"**Findings:** {s['total']} | kind: " + ", ".join(f"{k} {v}" for k, v in s["by_kind"].items())
          + " | severity: " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items())
          + " | level: " + ", ".join(f"{k} {v}" for k, v in sorted(s["by_level"].items())), ""]
    conflicts = st.query(kind="conflict")
    if conflicts:
        o += [f"## Conflicts ({len(conflicts)})", "Contradictory sources. Every claim is kept; none is preferred.", ""]
        for f in conflicts[:max_rows]:
            o.append(f"- `{f.id}` [{f.level}/{f.severity}] {f.claim}")
            for c in f.data["claims"]:
                o.append(f"  - {c['value']} per {c['type']}: {c['source']}")
        o.append("")
    issues = [f for f in st.query(min_severity="warning") if f.kind != "conflict"]
    o.append(f"## Other issues ({len(issues)})")
    if issues:
        o += ["| ID | Level | Sev | Kind | Claim |", "|---|---|---|---|---|"]
        for f in sorted(issues, key=lambda f: (f.level, f.severity != "error", f.id))[:max_rows]:
            o.append(f"| {f.id} | {f.level} | {f.severity} | {f.kind} | {f.claim.replace('|', '/')} |")
    else:
        o.append("None.")
    lay = res["layout"]
    if lay.regions:
        o += ["", "## Linker regions vs physical memory", "| Linker region | Origin | Length | Used | Physical relation | Core | Evidence |",
              "|---|---|---|---|---|---|---|"]
        for r in lay.regions:
            o.append(f"| {r.name} | {_h(r.origin)} | 0x{r.length:X} | 0x{r.used:X} | {r.physical_relation} "
                     f"{r.physical or ''} | {'' if r.core is None else r.core} | {r.finding} |")
    o += ["", "## Sections", "| Section | Run | Load | Size | Class | Init | In image | Region | Physical | Evidence |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for x in sorted(lay.sections, key=lambda x: p.profile.canonical(x.vma))[:max_rows]:
        img = "-" if x.in_image is None else f"{x.in_image}/{x.size}"
        o.append(f"| {x.name} | {_h(x.vma)} | {_h(x.lma)} | 0x{x.size:X} | {x.cls} ({x.cls_kind}) | {x.init} | {img} | "
                 f"{x.region or '?'} | {x.physical or 'UNKNOWN'} | {x.finding} |")
    o += ["", "## Startup (L1)"]
    for f in st.query(topic="startup"):
        o.append(f"- `{f.id}` [{f.kind}/{f.severity}] {f.claim}")
    o += ["", "## Map / ELF correlation"]
    for f in st.query(topic="symbols"):
        if f.kind != "conflict":
            o.append(f"- `{f.id}` [{f.kind}/{f.severity}] {f.claim}")
    if p.options.experimental:
        o += ["", "## L2 semantics (experimental)"]
        for f in st.query(level="L2"):
            if f.severity in ("info", "note") and f.kind != "conflict":
                o.append(f"- `{f.id}` [{f.kind}] {f.claim}")
    if res.get("linker_draft"):
        o += ["", "## Linker layout draft", "```ld", res["linker_draft"], "```"]
    o += ["", "_Kinds: observed, derived, inferred, unknown, conflict. Levels: L0 artifact facts, L1 structural "
          "recovery, L2 semantic recovery._"]
    return "\n".join(o)
