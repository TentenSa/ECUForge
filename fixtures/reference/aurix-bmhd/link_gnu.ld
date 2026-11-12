/* aurix-bmhd reference fixture layout (fixture's own choice, not a device claim except
 * UCB_BMHD0_ORIG at 0xAF400000, 512 bytes, documented in Infineon AP32381 V1.4). */
ENTRY(_START)

MEMORY
{
  pfls0     (rx) : ORIGIN = 0x80000000, LENGTH = 0x00010000
  ucb_bmhd0 (r)  : ORIGIN = 0xAF400000, LENGTH = 0x00000200
}

SECTIONS
{
  .startup      0x80000020 : { KEEP(*(.startup)) } > pfls0
  .bmhd_0_orig  0xAF400000 : { KEEP(*(.bmhd_0_orig)) } > ucb_bmhd0
  /DISCARD/ : { *(.data .data.* .bss .bss.* .text .text.* .rodata .rodata.*) }
}
