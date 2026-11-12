#!/usr/bin/env sh
# Build the reference firmware with a TriCore GCC (HighTec or an open-source tricore-gcc).
# Usage: TC_PREFIX=tricore-elf- ./build_gnu.sh
# Check each toolchain's license terms before committing produced binaries.
set -eu
P=${TC_PREFIX:-tricore-elf-}
mkdir -p out
${P}gcc -O1 -g -mcpu=tc39xx -ffunction-sections -fdata-sections -fno-common -c src/main.c -o out/main.o
${P}gcc -O1 -g -mcpu=tc39xx -c src/start.c -o out/start.o
${P}gcc -nostartfiles -T link_gnu.ld -Wl,-Map=out/reference.map out/start.o out/main.o -o out/reference.elf
${P}objcopy -O ihex out/reference.elf out/reference.hex
${P}readelf -S -s out/reference.elf > out/reference.readelf.txt
echo "built: out/reference.elf out/reference.hex out/reference.map"
