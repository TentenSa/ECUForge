/* Reference firmware layout. These addresses are this fixture's own choice
 * (ground truth for the manifest), NOT claims about any device.
 * CPU0 DSPR at 0x70000000 matches the documented mapping (TASKING KB 564);
 * the flash origin 0x80000000 is chosen here and is not taken from a profile. */
ENTRY(_START)

MEMORY
{
  pfls0  (rx)  : ORIGIN = 0x80000000, LENGTH = 0x00100000
  dsram0 (w!x) : ORIGIN = 0x70000000, LENGTH = 0x00010000
}

SECTIONS
{
  .startup      0x80000020 : { KEEP(*(.startup)) } > pfls0
  .traptab_cpu0 0x80000100 : { __TRAPTAB_CPU0 = .; KEEP(*(.traptab*)); . = 0x100; } > pfls0
  .text         0x80000200 : { *(.text .text.*) } > pfls0
  .rodata       0x80004000 : { *(.rodata) *(.rodata.*) } > pfls0
  .inttab_cpu0  0x80006000 : { __INTTAB_CPU0 = .; KEEP(*(.inttab*)); . = 0x100; } > pfls0

  .data         0x70000000 : AT(0x80008000) { *(.data) *(.data.*) } > dsram0
  .bss          0x70001000 (NOLOAD) : { *(.bss) *(.bss.*) *(COMMON) } > dsram0

  .clear_sec    0x80007000 : { PROVIDE(__clear_table = .);
                  LONG(ADDR(.bss)); LONG(SIZEOF(.bss));
                  LONG(-1); LONG(-1); } > pfls0
  .copy_sec     0x80007100 : { PROVIDE(__copy_table = .);
                  LONG(LOADADDR(.data)); LONG(ADDR(.data)); LONG(SIZEOF(.data));
                  LONG(-1); LONG(-1); LONG(-1); } > pfls0

  .csa0         0x70008000 (NOLOAD) : { __CSA0 = .; . = 0x2000; __CSA0_END = .; } > dsram0
  .ustack0      0x7000A000 (NOLOAD) : { __USTACK0_END = .; . = 0x1000; __USTACK0 = .; } > dsram0
}
