"""AUTOSAR module attribution (L2, experimental in 0.1.x).

Attribution uses only the public AUTOSAR naming rules: the standardised module
abbreviations and the vendor API infix <Ma>_<vendorId>_<vendorApiInfix>_ from the
AUTOSAR BSW General specification. No project or supplier naming is assumed.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import PurePath

from ..core.evidence import Source
from ..core.layout import classify_section

BSW_MODULES = set("""
Adc BswM Can CanIf CanNm CanSM CanTp CanTrcv Com ComM Crc CryIf Crypto Csm Dcm Dem Det Dio Dlt DoIP Dma
Ea Eep EcuM E2E Fee FiM Fls Fr FrIf FrNm FrSM FrTp Gpt Icu IoHwAb IpduM IdsM KeyM Lin LinIf LinSM LinTp
MemIf Mcu Nm NvM Ocu Os PduR Port Pwm Rte SecOC SoAd Spi StbM TcpIp Tm Wdg WdgIf WdgM Xcp Smu Stm Irq
Uart Dsadc Mcal Sent Iom Eth EthIf EthSM EthTrcv LdCom J1939Tp J1939Nm Sd SomeIpXf Tls FlsLoader Csm
""".split())
RE_MCAL = re.compile(r"^([A-Z][A-Za-z0-9]{1,15}?)(?:_\d+_[A-Za-z0-9]+)?_")
RE_IFX = re.compile(r"^(Ifx[A-Z][a-z]+|IfxCpu|IfxScu)")


def module_of(name: str, obj: str | None = None) -> tuple[str | None, str]:
    """Return (module, how). how in {'symbol-prefix','object-name','ifx'}."""
    m = RE_MCAL.match(name)
    if m and m.group(1) in BSW_MODULES:
        return m.group(1), "symbol-prefix"
    if obj:
        stem = PurePath(re.sub(r"\(.*\)$", "", obj)).stem
        member = re.search(r"\(([^)]+)\)$", obj)
        if member:
            stem = PurePath(member.group(1)).stem
        base = re.split(r"_\d+_|_Cfg|_PBcfg|_Lcfg|_Irq|_Callout|_MemMap", stem)[0]
        if base in BSW_MODULES:
            return base, "object-name"
    if RE_IFX.match(name) or (obj and RE_IFX.match(PurePath(re.sub(r"\(.*\)$", "", obj)).stem)):
        return "iLLD", "ifx"
    return None, ""


def module_footprint(p) -> dict:
    """Per-AUTOSAR-module footprint by memory class. Attribution is inferred."""
    st = p.store
    fp: dict = defaultdict(lambda: defaultdict(int))
    how_count: dict = defaultdict(int)
    if p.map and any(s.inputs for s in p.map.sections):
        elf_secs = {s.name: s for s in p.elf.sections} if p.elf else {}
        for os_ in p.map.sections:
            es = elf_secs.get(os_.name)
            cls, _ = classify_section(os_.name, es.perms if es else None, es.nobits if es else None)
            for ins in os_.inputs:
                mod, how = module_of(ins.name.split(".")[-1], ins.obj)
                if not mod:
                    mod, how = module_of("", ins.obj)
                fp[mod or "(unattributed)"][cls] += ins.size
                how_count[how or "none"] += 1
        basis = "map input sections"
    else:
        for s in p.symbols().values():
            if not s.size:
                continue
            mod, how = module_of(s.name, s.obj)
            w = p.profile.classify(s.addr)
            cls = "flash" if w and w.kind in ("pflash", "dflash") else "ram" if w else "other"
            fp[mod or "(unattributed)"][cls] += s.size
            how_count[how or "none"] += 1
        basis = "symbol sizes"
    table = {m: dict(v) for m, v in sorted(fp.items(), key=lambda kv: -sum(kv[1].values()))}
    if table:
        st.add("autosar", "inferred", "info",
               f"AUTOSAR module footprint for {len(table)} modules (basis: {basis}; attribution by "
               + ", ".join(f"{k}={v}" for k, v in how_count.items()) + ")",
               [Source(p.map.artifact if p.map else p.elf_art.short, basis)], {"modules": table}, level="L2",
               key="autosar.footprint")
    return table
