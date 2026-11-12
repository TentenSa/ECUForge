#!/usr/bin/env sh
# Build in two different directories and compare outputs byte for byte.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
A=$(mktemp -d)/build-a; B=$(mktemp -d)/elsewhere/build-b
mkdir -p "$A" "$B"
for d in "$A" "$B"; do
  cp -r "$HERE/src" "$HERE/link_gnu.ld" "$HERE/build_gnu.sh" "$d/"
  (cd "$d" && ./build_gnu.sh >/dev/null)
done
rc=0
for f in reference.elf reference.hex reference.map reference.readelf.txt; do
  if cmp -s "$A/out/$f" "$B/out/$f"; then echo "identical  $f"; else echo "DIFFERENT  $f"; rc=1; fi
done
if strings "$A/out/reference.elf" | grep -qE "$A|$B|/tmp/|/home/|/opt/"; then echo "host path in ELF"; rc=1; fi
exit $rc
