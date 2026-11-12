/* rea-auto reference fixture: AURIX TC3xx boot mode header (UCB_BMHD0_ORIG).
 * Field layout from Infineon AP32381 V1.4 (BMHD field layout table); values are this
 * fixture's own. CRC values come from ../bmhd_crc.py (documented method, self-checked
 * against a public vector), not from rea-auto. */
#include <stdint.h>

struct bmhd {
    uint16_t bmi;            /* 0x000 */
    uint16_t bmhdid;         /* 0x002 */
    uint32_t stad;           /* 0x004 */
    uint32_t crc;            /* 0x008 */
    uint32_t crc_n;          /* 0x00C */
    uint8_t  reserved[0x1F0 - 0x10];
    uint32_t confirmation;   /* 0x1F0 */
    uint8_t  pad[0x200 - 0x1F4];
};

_Static_assert(sizeof(struct bmhd) == 0x200, "UCB_BMHD block is 512 bytes");

const struct bmhd bmhd_0_orig __attribute__((section(".bmhd_0_orig"), used)) = {
    .bmi = 0x00FEu,              /* PINDIS=0, HWCFG=111b internal start from flash, LSENA0-3=1 */
    .bmhdid = 0xB359u,
    .stad = 0x80000020u,         /* = _START in link_gnu.ld */
    .crc = 0xAA25DA86u,          /* bmhd_crc.py 0x00FE 0xB359 0x80000020 */
    .crc_n = 0x55DA2579u,
    .confirmation = 0x43211234u,
};

/* Reset entry: an endless loop is enough for a header fixture. */
__asm__(".section .startup, \"ax\"\n"
        ".global _START\n"
        "_START: j _START\n"
        ".previous\n");
