#!/usr/bin/env sh
# Build the aurix-bmhd reference fixture (toolchain: ../tricore/TOOLCHAIN.md).
#   TC_PREFIX=tricore-elf- ./build_gnu.sh
set -eu
P=${TC_PREFIX:-tricore-elf-}
HERE=$(cd "$(dirname "$0")" && pwd)
TC_ROOT=$(cd "$(dirname "$(command -v "${P}gcc")")/.." && pwd)
python3 "$HERE/bmhd_crc.py" 0x00FE 0xB359 0x80000020 | grep -q "CRC_BMHD=0xAA25DA86 CRC_BMHD_N=0x55DA2579" \
  || { echo "bmhd.c CRC constants disagree with bmhd_crc.py" >&2; exit 1; }
MAP="-ffile-prefix-map=$HERE=/usr/src/ecuforge-fixture -fdebug-prefix-map=$HERE=/usr/src/ecuforge-fixture \
 -ffile-prefix-map=$TC_ROOT=/usr/lib/tricore-toolchain -fdebug-prefix-map=$TC_ROOT=/usr/lib/tricore-toolchain"
cd "$HERE"
mkdir -p out
${P}gcc -O1 -g -mcpu=tc39xx -ffreestanding -fno-common $MAP -c src/bmhd.c -o out/bmhd.o
${P}gcc -mcpu=tc39xx -nostdlib -T link_gnu.ld -Wl,-Map=out/reference.map out/bmhd.o -o out/reference.elf
${P}objcopy -O ihex out/reference.elf out/reference.hex
${P}readelf -S -s -W out/reference.elf > out/reference.readelf.txt
rm -f out/bmhd.o
echo "built: out/reference.elf out/reference.hex out/reference.map"
