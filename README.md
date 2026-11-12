# rea-auto

Evidence-first analysis of automotive embedded firmware builds. First target: TriCore / Infineon AURIX TC3xx with GNU (HighTec, tricore-gcc) and TASKING toolchains.

Status: **0.1.1a1, alpha.** Scored on synthetic fixtures; a reference-firmware fixture is written but not yet built.

## Project rule

rea-auto must be reproducible from publicly accessible specifications, openly usable or testable artifacts, synthetic fixtures, or artifacts contributed by their owner. No employer- or customer-derived implementation knowledge is accepted as product evidence. Details in [CONTRIBUTING.md](CONTRIBUTING.md).

## What 0.1.x covers

| Area | Scope |
|---|---|
| Artifacts (L0) | Intel HEX, S-record, ELF32 (TriCore), GNU/HighTec map, TASKING map + LSL; each identified by SHA-256 |
| Address spaces (L1) | Physical (documented MCU facts), linker (map/LSL/ELF), image (HEX/S19/ELF load) kept separate and related: CONTAINED, ALIASED, OVERLAPS, OUTSIDE, UNKNOWN |
| Layout (L1) | Section run/load addresses, init strategy, image coverage, region usage, unexplained image bytes, linker layout draft |
| Startup (L1) | BMHD with documented CRC, BMI decode, entry points, CSA areas, stacks, trap/interrupt tables, init tables (GNU/iLLD and TASKING) with one shared RAM-coverage check |
| Correlation (L1) | Map vs ELF by name and address |
| Semantics (L2) | A2L correlation and AUTOSAR attribution, experimental (`--experimental`), planned for 0.4.x / 0.5.x |

## Evidence

```
observed   read directly from an artifact
derived    computed from observed facts and documented rules
inferred   heuristic, naming convention or candidate search
unknown    the inputs or documented facts cannot answer it
conflict   sources contradict; every claim kept, none preferred
```

Each source records its type (ELF, HEX, S19, MAP, LSL, A2L, MCU_PROFILE, ARCH_SPEC, DISASSEMBLY, USER), the artifact SHA-256 and the parser version. Levels: **L0** artifact facts, **L1** structural recovery, **L2** semantic recovery.

## Target descriptions

* `reauto/silicon/infineon/aurix/targets/tc37x|tc38x|tc39x.json`: every value is cited (vendor, document, revision, date, URL, table or section) or `null`. Current sources: Infineon AP32381 V1.4 (BMHD slots, layout, BMI, CRC method), Infineon TC3x C4C variants addendum v1.0 (DSPR/PSPR sizes per CPU, flash sizes), TASKING KB 564 (CPU0/CPU1 DSPR SRI base, core-local DSPR alias). Flash bases, CPU2+ DSPR bases, PSPR bases and cached/non-cached aliasing are `null` until a public document is checked.
* `reauto/architecture/tricore/tricore.json`: CSA size and alignment, trap classes, trap vector spacing. BTV/BIV/stack alignment are `null`, so those checks report unknown.

A `null` fact never becomes a default. Analyses that need it say so.

## BMHD CRC modes

| Mode | Behaviour |
|---|---|
| `profile` (default) | runs only the profile's documented algorithm; mismatch is an error; no algorithm configured is unknown |
| `strict` | as `profile`, but no algorithm configured is an error |
| `discover` | computes 8 candidate orderings / bit orders, logs each result; a match is inferred, never derived |

The documented algorithm reproduces HighTec's public tc39x BMHD example (CRC 0x31795570), and no other candidate does.

## Install

```
pip install -e .            # core: Python stdlib only
pip install -e ".[mcp]"     # MCP server (SDK 1.x or 2.x)
pip install -e ".[yaml]"    # YAML manifests
pip install -e ".[dev]"     # pytest
```

The core is dependency-light, not dependency-free by rule. DWARF, demangling and disassembly will come from established libraries or engines behind the artifact model.

## CLI

```
rea-auto analyze --image app.hex --elf app.elf --map app.map --device tc38x -o out/
rea-auto analyze --image app.s19 --map app.map --lsl app.lsl --toolchain tasking -o out/
rea-auto findings ... [--topic startup] [--level L1] [--kind conflict] [--json]
rea-auto linker-draft ...
rea-auto lookup 0x70008000 ...
rea-auto verify manifest.json [-o run.json]
rea-auto profiles
```

`analyze` writes `report.md`, `evidence.json`, `run.json` (tool version, target, profile id/version/SHA-256, artifact SHA-256s, options) and `linker_draft.ld`. It exits non-zero when any error finding exists.

## MCP server

```
claude mcp add rea-auto -- python -m reauto.mcp_server
```

Tools: `open_build`, `analyze`, `get_findings`, `get_evidence`, `lookup`, `read_memory`, `linker_draft`, `report`, `verify_manifest`, `list_profiles`.

## Fixtures and scoring

Three fixture classes: synthetic (A), public vendor examples (B, license permitting), reference firmware (C). `rea-auto verify` scores every expected fact as correct, unknown, conflict or false claim. A false claim is the most serious result. See [docs/fixtures.md](docs/fixtures.md).

## Layout

```
reauto/
  core/          evidence, project, views, layout, raminit, symbols
  formats/       elf, hexrec, image, map/model, a2l/parser
  architecture/  tricore/ (spec facts, startup structures)
  silicon/       infineon/aurix/ (profile, targets, bmhd, crc)
  toolchains/    gnu/ (map, iLLD conventions, init tables), tasking/ (map, LSL, conventions, copy table)
  semantics/     a2l, autosar (experimental)
  analyze.py, verify.py, cli.py, mcp_server.py
fixtures/reference/tricore/   reference firmware source, linker script, manifest
tests/                        synthetic generator and tests by fixture class
```

## Roadmap

| Version | Focus |
|---|---|
| 0.1.x | trustworthy firmware structure (this release line); exit: reference firmware built and scored |
| 0.2.x | TriCore/AURIX structural recovery depth (ABM headers once documented, more derivatives, TC2xx/TC4xx) |
| 0.3.x | map + DWARF symbol reconstruction |
| 0.4.x | ASAM MCD-2 MC (A2L) |
| 0.5.x | AUTOSAR structural recognition from public specifications |
| 0.6.x | diagnostics (UDS, XCP) |
| 0.7.x | security, boot and FOTA analysis |
| 1.0 | architecture-independent automotive binary-analysis framework (ARM, RH850, ...) |
