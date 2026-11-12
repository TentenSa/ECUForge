#!/usr/bin/env python3
"""Compute CRC_BMHD / CRC_BMHD_N for this fixture, independently of ECUForge.

Method (Infineon AP32381 V1.4, CRC algorithm): CRC-32 with the IEEE 802.3
polynomial, bit-reflected and inverted, over 2 words (BMI|BMHDID, STAD), each
32-bit word fed most-significant byte first. That is zlib.crc32 over the two
words byte-swapped. Self-check: HighTec's public tc39x example
(BMI 0x00FE, BMHDID 0xB359, STAD 0xA0000000 -> CRC 0x31795570).
"""
import struct
import sys
import zlib


def crc_bmhd(bmi: int, bmhdid: int, stad: int) -> int:
    words = struct.pack("<HHI", bmi, bmhdid, stad)
    return zlib.crc32(words[0:4][::-1] + words[4:8][::-1]) & 0xFFFFFFFF


assert crc_bmhd(0x00FE, 0xB359, 0xA0000000) == 0x31795570, "self-check against public vector failed"

if __name__ == "__main__":
    bmi, bmhdid, stad = (int(x, 0) for x in sys.argv[1:4])
    c = crc_bmhd(bmi, bmhdid, stad)
    print(f"CRC_BMHD=0x{c:08X} CRC_BMHD_N=0x{~c & 0xFFFFFFFF:08X}")
