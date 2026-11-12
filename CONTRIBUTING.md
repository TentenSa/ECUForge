# Contributing to rea-auto

## Provenance boundary

rea-auto is developed from publicly available specifications, redistributable public artifacts, synthetic test fixtures, and artifacts contributed by their owners with appropriate rights. Proprietary employer, customer or third-party firmware, configuration, symbols, documentation and implementation details must not be used as repository source material.

### Do not submit

- proprietary firmware or binaries, in any form (ELF, HEX, S-record, raw images)
- confidential source code, linker scripts or build configuration
- non-public map, ELF, A2L, ARXML or LSL files, including "sanitized" ones
- confidential memory maps or production addresses known only from non-public projects
- calibration datasets
- security material: keys, certificates, seeds, passwords, HSM configuration
- internal specifications, register databases, documentation, screenshots or anything under NDA
- symbols, identifiers or test cases extracted from proprietary products
- implementation knowledge you are not entitled to disclose

Renaming symbols or removing a customer name does not make an artifact publishable. A sanitized map or A2L still exposes layout, feature composition and calibration structure.

### Where knowledge may come from

| Acceptable | Not acceptable |
|---|---|
| A public document states that X is at Y (cite it in a profile or spec fact). | "Several programs I worked on put X at Y, so rea-auto assumes Y." |
| Y is discovered at runtime from an ELF or map the user supplies. | A constant learned only from a non-public build. |
| A defect seen on a non-public build is reproduced with an invented synthetic fixture. | Committing the non-public build, or a reduced copy of it. |

Engineering experience may guide what problems to solve and how to design algorithms. It must not become an implicit database of non-public facts.

### Security scope

rea-auto reports evidence for authorized analysis, research, interoperability and defensive assessment (for example: "this region participates in boot authentication"). It does not ship mechanisms to defeat vehicle security, such as key extraction, signature bypass or immobilizer defeat.

## Technical rules

- **Hardware and architecture facts** live in `reauto/silicon/**/targets/*.json` and `reauto/architecture/**/*.json` as fact objects with `source`, `ref` and `verification`; the source names vendor, document, revision, date and a public URL. Unknown is `null`, never an estimate. Analysis code holds no unexplained hardware constants (`tests/test_rules.py`).
- **Parsers never manufacture certainty.** Anything not understood becomes a `ParseEvent` with file and line; nothing is dropped silently. Severity never depends on parser state alone: parsers report `ParseHealth` (announced vs recovered structures), and findings are derived from it. When two sources disagree the result is a `CONFLICT` with both claims, never whichever parser ran last.
- **Normalise below the analyzers.** Toolchain differences are translated by the toolchain plug-in into the common model. Analyzers in `core/`, `architecture/`, `silicon/` and `semantics/` never branch on a toolchain name (`tests/test_rules.py`).
- **Physical, linker and image memory are separate views.** None overrides another.
- **Fixtures** follow [fixtures/README.md](fixtures/README.md). Every fixture directory has a `provenance.yaml` listing each file with its SHA-256. Binary or build-artifact files anywhere else fail CI (`scripts/check_repo.py`). If redistribution rights are unclear, do not add the file.

## Layering

```
reauto/core/            evidence, views, layout, RAM-init analysis
reauto/formats/         ELF, HEX, S-record, map model, A2L, parse events
reauto/architecture/    CPU architecture facts and structures
reauto/silicon/         device facts and boot structures
reauto/toolchains/      map/LSL parsers, linker-generated tables, symbol conventions
reauto/semantics/       L2 recovery (experimental in 0.1.x)
```

## Contributor declaration

By opening a pull request you confirm that:

1. you have the right to submit the code and data;
2. it contains no confidential, NDA-covered, employer or customer material;
3. fixtures are synthetic, authored for this project, or demonstrably redistributable;
4. hardware facts have a public source;
5. reverse-engineered observations are distinguished from specifications;
6. it contains no secrets or production credentials.

## Pull requests

Maintainer review is required for every merge into `main`. CI must pass: tests (including fuzz properties), lint, repository guard, secret scan.
