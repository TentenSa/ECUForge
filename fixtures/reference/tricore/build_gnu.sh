#!/usr/bin/env sh
# Build the reference firmware with a TriCore GCC (tested: NoMore201/tricore-gcc-toolchain,
# tricore-elf-gcc 13.4.1, binutils 2.40; see TOOLCHAIN.md). Usage:
#   TC_PREFIX=tricore-elf- ./build_gnu.sh
# Bare-metal, freestanding: no C library and no libgcc are linked, so the outputs
# contain only this fixture's code. Build and toolchain paths are mapped to fixed
# names so the outputs do not depend on where they were built.
set -eu
P=${TC_PREFIX:-tricore-elf-}
HERE=$(cd "$(dirname "$0")" && pwd)
TC_ROOT=$(cd "$(dirname "$(command -v "${P}gcc")")/.." && pwd)
MAP="-ffile-prefix-map=$HERE=/usr/src/rea-auto-fixture -fdebug-prefix-map=$HERE=/usr/src/rea-auto-fixture \
 -ffile-prefix-map=$TC_ROOT=/usr/lib/tricore-toolchain -fdebug-prefix-map=$TC_ROOT=/usr/lib/tricore-toolchain"
CFLAGS="-O1 -g -mcpu=tc39xx -ffreestanding -ffunction-sections -fdata-sections -fno-common $MAP"
cd "$HERE"
mkdir -p out
${P}gcc $CFLAGS -c src/main.c -o out/main.o
${P}gcc $CFLAGS -c src/start.c -o out/start.o
${P}gcc -mcpu=tc39xx -nostdlib -T link_gnu.ld -Wl,-Map=out/reference.map out/start.o out/main.o -o out/reference.elf
${P}objcopy -O ihex out/reference.elf out/reference.hex
${P}readelf -S -s -W out/reference.elf > out/reference.readelf.txt
rm -f out/main.o out/start.o
echo "built: out/reference.elf out/reference.hex out/reference.map"
