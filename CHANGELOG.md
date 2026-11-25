# Changelog

## Unreleased (0.2 development)
- Project workspace: `init`, `add`, `analyze`, `show`; content-addressed artifact store with separate roles; reproducible, path-free analysis runs.
- Semantic finding keys (`<rule>@<subject>`) on every finding.
- Consumer-neutral export model (`ecuforge.export.model`): stable ids anchored to the program image hash, physical regions with one canonical view and explicit alias views, sections, symbols and findings.
- Release gate: synthetic TASKING-format fixture (S19, TASKING map, LSL) verified with the same strict rules as the reference builds. Region names follow the TASKING map (`mpe:pfls0`).
- `ecuforge export ghidra`: Ghidra export file (model, section permissions from ELF flags, BMHD structure type and instances, one bookmark per addressed finding, program notes for the rest). Applying it in Ghidra is a separate step.
- `ecuforge ghidra apply` (PyGhidra): plans changes in plain Python, refuses a program whose image hash differs, never modifies blocks, symbols or data it did not create, maps alias views onto whichever view holds the loaded bytes, merges findings that share an address and category into one bookmark, and is idempotent. Written against the Ghidra 12.3 API; not yet run against a real Ghidra.
- `ecuforge doctor ghidra`: PyGhidra, Java, Ghidra version, TriCore module and languages, and which TriCore 1.6.2 instructions the SLEIGH spec does not name.

## 0.1.1 (2026-11-12)
ECUForge 0.1.1 establishes the reproducible evidence and artifact-reconstruction baseline for TriCore/AURIX analysis. Reference firmware built with a real TriCore toolchain is verified against preregistered expectations, with separate BMHD validation and explicit handling of unknown, conflicting and unsupported evidence.

This is a baseline, not a production-ready or broadly validated release.

Name: developed as rea-auto and renamed to ECUForge before first publication (Python package and CLI: `ecuforge`).

Origin: ECUForge is an independent Python implementation derived from the evidence-first design of REA (https://github.com/morluto/rea, MIT): the separation of observed, derived, inferred and unknown evidence, and one analysis core exposed through CLI and MCP. It shares no code or history with REA and is not affiliated with its maintainers.

Release gate:
- `fixtures/reference/tricore`: 19/19 expected facts; 0 unexpected unknowns, conflicts, false claims or unexplained findings.
- `fixtures/reference/aurix-bmhd`: 9/9 expected facts; same zero counts.
- Both reference builds reproducible: byte-identical ELF, HEX, MAP and readelf output across build directories, no host paths in the ELF. Toolchain: tricore-elf-gcc 13.4.1 / binutils 2.40 built from pinned sources (`fixtures/reference/tricore/TOOLCHAIN.md`).
- BMHD CRC expectations computed independently of ECUForge (`bmhd_crc.py`, AP32381 method, self-checked against a public vector).
- 78 tests, repository guard clean.

Known limitation: expected BMHD values and source hashes were recorded before the first build; pre-registration was not independently committed to Git before generated artifacts were produced.

Changes since 0.1.1a2:
- Reference fixture corrected to build with a real TriCore GCC (freestanding, `-nostdlib`, `-mcpu` at link, `.previous`, explicit input-section names, real vector tables) and made reproducible.
- GNU map parser: output-section headers recognised by syntax, including the two-line `memory region -> NAME` form; linker data statements and relaxation lines recognised.
- Parse health: findings derived from announced versus recovered structures (`<TYPE>_STRUCTURE_NOT_RECOVERED`), not from parser state; parse events are telemetry only.
- Layout: sections the ELF marks not allocated are excluded from memory placement.
- verify: `allow_unexpected_unknown` and `expected_unknowns` (id, what, reason) replace the blanket `allow_unknown`; PASS also requires zero conflicts; image coverage expectations.
- New reference fixture `aurix-bmhd`.

## 0.1.1a2 (unreleased)
- Parse events: parsers keep everything they do not model as `ParseEvent`s (file, line, raw text, context). All are written to `evidence.json`; only events that can change a result become UNKNOWN findings, plus one summary note per artifact.
- HEX/S19: lines after the end-of-file record are kept as events; loaders account for every non-blank line.
- ELF: malformed input raises `ElfFormatError` only.
- Typed address-space views: `PhysicalMemoryRegion`, `LinkerMemoryRegion`, `LinkerSection`, `ImageMemoryRegion`; relation helpers reject mixed or physical-as-complete comparisons.
- Fixture tree `fixtures/{synthetic,generated,public,reference,fuzz}` with `provenance.yaml` (schema v1, per-file SHA-256).
- `scripts/check_repo.py`: provenance validation, build artifacts only in approved fixture directories, 5 MiB size cap.
- Fuzz: Hypothesis property tests for HEX, S19, ELF, GNU map, TASKING map, LSL and A2L parsers.
- Policy: provenance boundary in README; prohibited content, knowledge sources, security scope and contributor declaration in CONTRIBUTING; PR checklist; CI (tests, ruff, repository guard, gitleaks).

## 0.1.1a1
Project boundary: ECUForge is built only from public specifications, open artifacts, synthetic fixtures and owner-contributed artifacts (CONTRIBUTING.md).

- Layered packages: core, formats, architecture/tricore, silicon/infineon/aurix, toolchains/{gnu,tasking}, semantics.
- Provenance: every source carries type (ELF, HEX, S19, MAP, LSL, A2L, MCU_PROFILE, ARCH_SPEC, ...), artifact SHA-256 and parser version.
- Levels redefined: L0 artifact facts, L1 structural recovery, L2 semantic recovery.
- MCU profiles: estimated values removed. Facts are cited (Infineon AP32381 V1.4, Infineon TC3x C4C variants addendum v1.0, TASKING KB 564) or null. PFLASH/DFLASH bases, CPU2+ DSPR bases, PSPR bases and bus aliasing are unknown until documented.
- TriCore architecture facts in their own cited spec (CSA 16 words, 8 trap classes, 32-byte trap spacing). BTV/BIV/stack alignment are null, so those checks report unknown.
- Physical / linker / image address views with CONTAINED, ALIASED, OVERLAPS, OUTSIDE, UNKNOWN relations. Boundary disagreements are conflicts with both claims kept; no view overrides another.
- BMHD: documented algorithm `aurix_tc3xx_bmhd` checked against HighTec's public tc39x example vector. CRC modes discover / profile / strict; discovery results are inferred and log every candidate. BMI decoded per AP32381. Confirmation word reported without interpretation.
- Init tables: GNU/iLLD and TASKING decoders feed one validator and one RAM-coverage check. Every TASKING candidate keeps its rejection reason.
- Removed undocumented heuristics: minimum CSA frame warning, CSA-in-own-DSPR warning, UCB "unlocked" interpretation, section-name core heuristic.
- A2L and AUTOSAR attribution moved to `semantics/`, behind `--experimental` (planned 0.4.x / 0.5.x). AUTOSAR vendor infix generalised to any vendor id.
- `verify` scores correct / unknown / conflict / false_claim and writes a run record. Internal-build fixture procedure removed; fixture classes A (synthetic) and C (reference firmware) added, B (public vendor examples) documented.
- Linker draft command renamed to `linker-draft`.

## 0.1.1a0
Conflict kind, L0/L1/L2, BMHD CRC candidates, per-CPU profiles, TASKING `_lc_cp` decode, verify harness (superseded by 0.1.1a1).

## 0.1.0a0
Initial framework.
