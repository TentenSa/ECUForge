# Toolchain used for the committed outputs in out/

Built from source (no prebuilt binaries):

| Component | Repository | Commit |
|---|---|---|
| toolchain meta-repo | https://github.com/NoMore201/tricore-gcc-toolchain | eb167cf281d95e220546aff2c4ecb99a2f91b90c |
| GCC (`tricore-elf-gcc 13.4.1 20260422`) | https://github.com/NoMore201/tricore-gcc | 59834f272d9c0d051329195c867341238b0c6a86 |
| binutils 2.40 | https://github.com/NoMore201/tricore-binutils-gdb | 78ccc076bc8cad0f9e08c81ca1c89b5e89dfb8f3 |

Configuration: flags from the meta-repo `Makefile.in` (`stamps/build-binutils-tc`, `stamps/build-gcc-stage1`), with host GMP/MPFR/MPC, `--enable-languages=c`, `--without-headers`, `make all-gcc`. No newlib and no libgcc are needed: the fixture builds with `-ffreestanding` and links with `-nostdlib`.

Licensing: GCC and binutils are GPLv3 (GCC with the GCC Runtime Library Exception). Neither is redistributed here. The outputs link no toolchain library code (`-nostdlib`), so they contain only this fixture's MIT-licensed code and linker-generated tables.

Reproducibility: `./check_reproducible.sh` builds in two directories and requires identical ELF, HEX, MAP and readelf output and no host paths in the ELF.
