/* Minimal startup for the reference firmware. Walks the iLLD-convention
 * __clear_table / __copy_table emitted by link_gnu.ld, then calls main().
 * Static-analysis fixture: not validated on silicon. */
#include <stdint.h>

extern const uint32_t __clear_table[];
extern const uint32_t __copy_table[];
extern int main(void);

void _c_init(void)
{
    for (const uint32_t *t = __clear_table; t[0] != 0xFFFFFFFFu; t += 2) {
        uint8_t *d = (uint8_t *)t[0];
        for (uint32_t n = 0; n < t[1]; n++) d[n] = 0;
    }
    for (const uint32_t *t = __copy_table; t[0] != 0xFFFFFFFFu; t += 3) {
        const uint8_t *s = (const uint8_t *)t[0];
        uint8_t *d = (uint8_t *)t[1];
        for (uint32_t n = 0; n < t[2]; n++) d[n] = s[n];
    }
    (void)main();
    for (;;) { }
}

/* Reset entry: set the user stack pointer, then enter C. `.previous` returns the
 * assembler to the compiler's section so later debug expressions stay valid. */
__asm__(".section .startup, \"ax\"\n"
        ".global _START\n"
        "_START:\n"
        "  movh.a %sp, hi:__USTACK0\n"
        "  lea    %sp, [%sp]lo:__USTACK0\n"
        "  j      _c_init\n"
        ".previous\n");

/* Trap table: 8 classes, 32 bytes apart, each a jump to a stop loop.
 * Interrupt table: two 32-byte entries (priority 0 unused, priority 1 -> irq_handler). */
__asm__(".section .traptab_cpu0, \"ax\"\n"
        ".global _trap_stop\n"
        "_trap0: j _trap_stop\n .balign 32\n"
        "_trap1: j _trap_stop\n .balign 32\n"
        "_trap2: j _trap_stop\n .balign 32\n"
        "_trap3: j _trap_stop\n .balign 32\n"
        "_trap4: j _trap_stop\n .balign 32\n"
        "_trap5: j _trap_stop\n .balign 32\n"
        "_trap6: j _trap_stop\n .balign 32\n"
        "_trap7: j _trap_stop\n .balign 32\n"
        ".previous\n"
        ".section .inttab_cpu0, \"ax\"\n"
        "_int0: j _trap_stop\n .balign 32\n"
        "_int1: j irq_handler\n .balign 32\n"
        ".previous\n"
        ".text\n"
        "_trap_stop: j _trap_stop\n"
        ".previous\n");
