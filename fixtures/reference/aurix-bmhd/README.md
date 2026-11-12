# Reference fixture: AURIX BMHD (class C)

One UCB_BMHD0_ORIG block (BMI 0x00FE, BMHDID 0xB359, STAD 0x80000020, CRC from `bmhd_crc.py`, confirmation word) and a reset entry `_START` at the STAD address. Gate facts: regions, sections, symbols, image coverage of the 512-byte header, ELF entry, BMHD STAD and documented-CRC match.

Build: `TC_PREFIX=tricore-elf- ./build_gnu.sh` (toolchain in `../tricore/TOOLCHAIN.md`); reproducibility: `./check_reproducible.sh`.

The manifest and sources were hashed before the first build and checked unchanged after it (SHA-256 in provenance.yaml, `prebuild_sha256`).
