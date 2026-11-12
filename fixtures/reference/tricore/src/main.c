/* ECUForge reference firmware (fixture class C).
 * Every object here exists to produce one known structure in the image.
 * Placement is fixed by ../link_gnu.ld, so the expected facts come from this
 * source and that linker script, not from ECUForge. */
#include <stdint.h>

/* Explicit input-section names: placement must not depend on how a particular
 * compiler names -fdata-sections output. The linker script keeps the standard
 * *(.data .data.*) / *(.bss .bss.*) / *(.rodata .rodata.*) selectors. */
#define IN(s) __attribute__((section(s)))

uint32_t initialized IN(".data.initialized") = 0x12345678u;          /* copy-init record */
uint32_t initialized_array[4] IN(".data.initialized_array") = {1, 2, 3, 4};
uint32_t zeroed IN(".bss.zeroed");                                    /* clear record     */
uint8_t  zeroed_buffer[64] IN(".bss.zeroed_buffer");
const uint16_t calib_value IN(".rodata.calib_value") = 800u;         /* decodable constant */
const uint16_t calib_curve[8] IN(".rodata.calib_curve") = {0, 1000, 2000, 3000, 10, 20, 30, 40};

volatile uint32_t irq_count IN(".bss.irq_count");

void irq_handler(void) { irq_count++; }

void init(void)
{
    zeroed = initialized;
    for (unsigned i = 0; i < sizeof zeroed_buffer; i++) {
        zeroed_buffer[i] = (uint8_t)calib_curve[i & 7u];
    }
}

int main(void)
{
    init();
    for (;;) {
        if (irq_count > calib_value) {
            irq_count = 0;
        }
    }
}
