# Contributing to rea-auto

## Project rule (hard)

rea-auto must be reproducible from publicly accessible specifications, openly usable or testable artifacts, synthetic fixtures, or artifacts contributed by their owner. No employer- or customer-derived implementation knowledge is accepted as product evidence.

In practice:

* No employer or customer binaries, maps, A2Ls, ARXMLs, linker scripts, memory layouts, configurations, naming conventions or heuristics derived from them, in code, fixtures, tests, docs or commit history.
* Every hardware or architecture value in `reauto/silicon/**/targets/*.json` and `reauto/architecture/**/*.json` is a fact object with `source`, `ref` and `verification`, and its source entry names vendor, document, revision, date and a public URL. Unknown values are `null`. Estimated or "typical" values are not accepted, even when flagged.
* `verification` is `documented` (silicon vendor) or `documented-secondary` (toolchain vendor). `synthetic` is allowed only in test fixtures and is rejected for shipped profiles by `tests/test_profiles.py`.
* Naming conventions used to find symbols (toolchain or BSP) must be publicly documented and live in `reauto/toolchains/<toolchain>/`.
* Fixtures are synthetic (class A), public vendor examples whose license allows it (class B), or reference firmware written for this project (class C). Expected values in a fixture manifest come from a source independent of rea-auto.

## Layering

```
reauto/core/            evidence, views, layout, RAM-init analysis (architecture and toolchain neutral)
reauto/formats/         ELF, HEX, S-record, map model, A2L
reauto/architecture/    CPU architecture facts and structures (tricore/)
reauto/silicon/         device facts and boot structures (infineon/aurix/)
reauto/toolchains/      map/LSL parsers, linker-generated tables, symbol conventions (gnu/, tasking/)
reauto/semantics/       L2 recovery: A2L, AUTOSAR (experimental in 0.1.x)
```

Dependencies point inward: toolchains and silicon may use core and formats; core never imports a toolchain or silicon module except through the registries in `reauto/toolchains/__init__.py`.

## Commits

Author is the repository owner. No AI co-author or attribution trailers.
