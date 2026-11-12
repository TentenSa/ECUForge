# Reference firmware: TriCore (fixture class C)

Small firmware whose every structure is known from its own source and linker script:
initialised data (copy-init), zeroed data (clear), constants, an IRQ handler, a trap and
an interrupt table placeholder, one CSA area and one user stack, all at fixed addresses
in `link_gnu.ld`.

Status: built with the toolchain in [TOOLCHAIN.md](TOOLCHAIN.md); outputs committed in `out/` and reproducible.

1. Build with a TriCore GCC: `TC_PREFIX=tricore-elf- ./build_gnu.sh`; check with `./check_reproducible.sh`.
2. Run `ecuforge verify manifest.json`. Expected values in the manifest come only from
   `link_gnu.ld`. `allow_unknown` is true because the shipped profile leaves PFLASH
   undocumented; false claims and unexplained errors still fail the run.
3. Add size-dependent facts (copy/clear table records) from the toolchain's own
   `readelf` output, not from ECUForge.
4. Commit built binaries only if the toolchain license allows redistribution.

A TASKING variant (LSL instead of `link_gnu.ld`) follows the same pattern.
