"""TASKING linker-defined symbol names (public TASKING linker documentation:
_lc_ub_<name> / _lc_ue_<name> mark begin / end of a reserved area)."""
import re

from ..model import Conventions

TASKING = Conventions(
    name="tasking",
    csa=[(re.compile(r"^_lc_ub_csa_tc(\d)$"), "_lc_ue_csa_tc{c}")],
    stacks=[(re.compile(r"^_lc_ub_ustack_tc(\d)$"), "_lc_ue_ustack_tc{c}", "user"),
            (re.compile(r"^_lc_ub_istack_tc(\d)$"), "_lc_ue_istack_tc{c}", "interrupt")],
    vectors=[(re.compile(r"^_lc_u_trap_tab_tc(\d)$"), "trap"), (re.compile(r"^_lc_u_int_tab_tc(\d)$"), "interrupt")],
    entries=[(re.compile(r"^_START$|^_start$"), "reset entry")],
)
