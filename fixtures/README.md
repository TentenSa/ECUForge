# Fixtures

| Directory | Class | Committed content | Provenance |
|---|---|---|---|
| `synthetic/` | A, synthetic | generator script only | `provenance.yaml` (origin: generated) |
| `generated/` | output | nothing (ignored by git) | n/a |
| `public/<name>/` | B, public | redistributable third-party example artifacts | `provenance.yaml` with source URL, license, redistribution right |
| `reference/<name>/` | C, reference firmware | source, linker script, manifest | `provenance.yaml` (origin: authored) |
| `fuzz/` | fuzz | small hand-written seed inputs | `provenance.yaml` (origin: authored) |

Every file in a fixture directory is listed in its `provenance.yaml` with its SHA-256. `python scripts/check_repo.py` enforces this and blocks binary or build-artifact files anywhere else. Print the hash list for a directory with `python scripts/check_repo.py --hashes fixtures/<dir>`.

A behaviour found while analysing a non-public build is reproduced here with invented addresses, symbols and data. The non-public build itself never enters the repository.
