/* rea-auto reference firmware (fixture class C).
 * Every object here exists to produce one known structure in the image.
 * Placement is fixed by ../link_gnu.ld, so the expected facts come from this
 * source and that linker script, not from rea-auto. */
#include <stdint.h>

uint32_t initialized = 0x12345678u;          /* .data : copy-init record          */
uint32_t initialized_array[4] = {1, 2, 3, 4}; /* .data                             */
uint32_t zeroed;                              /* .bss  : clear record              */
uint8_t  zeroed_buffer[64];                   /* .bss                              */
const uint16_t calib_value = 800u;            /* .rodata : decodable constant      */
const uint16_t calib_curve[8] = {0, 1000, 2000, 3000, 10, 20, 30, 40};

volatile uint32_t irq_count;

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
