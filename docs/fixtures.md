# Fixture classes

| Class | Where | Ground truth comes from | Use |
|---|---|---|---|
| A. Synthetic | `fixtures/synthetic/` (output in `fixtures/generated/`) | the generator script | unit behaviour: formats, malformed input, BMHD/CRC modes, copy tables, RAM init, conflicting evidence |
| B. Public | `fixtures/public/<name>/` (empty so far) | the example's own source and project files | realistic toolchain output; add only where the license permits redistribution or local rebuild |
| C. Reference firmware | `fixtures/reference/tricore/` | its source and linker script | exact ground truth for real compiler and linker output |

Each fixture has a manifest scored by `ecuforge verify`. Every expected fact ends as **correct**, **unknown**, **conflict** or **false claim**. A false claim (ECUForge confidently reports a wrong value) is the most serious result. `verify -o run.json` writes the run record: tool version, target, profile id/version/SHA-256, artifact SHA-256s with parser versions, analysis options, score.

Synthetic hardware values live in a separate synthetic profile (`profile_synthetic_tc38x.json`, generated) whose facts are all `verification: synthetic`. They are test data, never device claims.
| Fuzz | `fixtures/fuzz/` | hand-written seeds; mutations generated at test time | property invariants: no uncaught exception, no fabricated names or addresses, no silent input loss |
