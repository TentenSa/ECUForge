"""CRC-32 engine and BMHD header-CRC candidates.

Documented method (IFX-AP32381 V1.4, "CRC algorithm"): CRC-32 with the IEEE
802.3 polynomial 0x04C11DB7, bit-reflected and inverted; memory is little-endian
but each 32-bit word is fed as big-endian; the BMHD check covers 2 words
(BMI, BMHDID, STAD). That is ALGORITHMS["aurix_tc3xx_bmhd"]. Regression vector:
HighTec public tc39x BMHD example (BMI 0x00FE, BMHDID 0xB359, STAD 0xA0000000
-> CRC 0x31795570), see tests.

DISCOVERY_CANDIDATES are only used in `discover` mode; a match there is
inferred, never observed or derived.
"""
from __future__ import annotations

from dataclasses import dataclass


def _reflect(v: int, bits: int) -> int:
    r = 0
    for _ in range(bits):
        r = (r << 1) | (v & 1)
        v >>= 1
    return r


def crc32(data: bytes, poly: int = 0x04C11DB7, init: int = 0xFFFFFFFF, xorout: int = 0xFFFFFFFF,
          reflected: bool = True) -> int:
    crc = init
    if reflected:
        rp = _reflect(poly, 32)
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ (rp if crc & 1 else 0)
    else:
        for b in data:
            crc ^= b << 24
            for _ in range(8):
                crc = ((crc << 1) ^ poly if crc & 0x80000000 else crc << 1) & 0xFFFFFFFF
    return (crc ^ xorout) & 0xFFFFFFFF


def _be_words(b: bytes) -> bytes:
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def _swap_first_halfwords(b: bytes) -> bytes:
    return b[2:4] + b[0:2] + b[4:]


ORDERINGS = {
    "bytes as stored": lambda b: b,
    "32-bit words, MSB first": _be_words,
    "BMI/BMHDID halfwords swapped": _swap_first_halfwords,
    "halfwords swapped, words MSB first": lambda b: _be_words(_swap_first_halfwords(b)),
}


@dataclass(frozen=True)
class CrcCandidate:
    name: str
    ordering: str
    reflected: bool

    def compute(self, header: bytes) -> int:
        return crc32(ORDERINGS[self.ordering](header), reflected=self.reflected)


DISCOVERY_CANDIDATES = [CrcCandidate(f"{'refl' if r else 'msb'}/{o}", o, r)
                        for o in ORDERINGS for r in (True, False)]
ALGORITHMS = {"aurix_tc3xx_bmhd": CrcCandidate("aurix_tc3xx_bmhd", "32-bit words, MSB first", True)}
