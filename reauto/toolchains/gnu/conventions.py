"""Startup-symbol naming used by Infineon iLLD linker scripts for GNU-based toolchains
(HighTec, tricore-gcc). These are public BSP conventions, matched by name only, so
every match is `inferred` until the address is validated against the image."""
import re

from ..model import Conventions

GNU_ILLD = Conventions(
    name="gnu/iLLD",
    csa=[(re.compile(r"^__CSA(\d)$"), "__CSA{c}_END")],
    stacks=[(re.compile(r"^__USTACK(\d)$"), "__USTACK{c}_END", "user"),
            (re.compile(r"^__ISTACK(\d)$"), "__ISTACK{c}_END", "interrupt")],
    vectors=[(re.compile(r"^__TRAPTAB_CPU(\d)$"), "trap"), (re.compile(r"^__INTTAB_CPU(\d)$"), "interrupt")],
    entries=[(re.compile(r"^_START$|^_start$"), "reset entry"), (re.compile(r"^__START(\d)$"), "core start"),
             (re.compile(r"^_?core(\d)_main$", re.I), "core main")],
)
