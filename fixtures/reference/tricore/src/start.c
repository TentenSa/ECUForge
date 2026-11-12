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

/* Reset entry: set the user stack pointer, then enter C. */
__asm__(".section .startup, \"ax\"\n"
        ".global _START\n"
        "_START:\n"
        "  movh.a %sp, hi:__USTACK0\n"
        "  lea    %sp, [%sp]lo:__USTACK0\n"
        "  j      _c_init\n");
