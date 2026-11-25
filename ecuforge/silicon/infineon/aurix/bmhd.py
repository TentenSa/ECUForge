"""AURIX TC3xx Boot Mode Header (BMHD) recovery, driven only by documented profile facts.

CRC handling has three explicit modes (profile `bmhd.crc.mode`, or Options.bmhd_crc_mode):

  discover  every candidate in DISCOVERY_CANDIDATES is computed and logged; a match
            is INFERRED (a CRC agreeing is not proof of the method)
  profile   only the profile's documented algorithm runs; match -> derived,
            mismatch -> error; no algorithm in the profile -> unknown
  strict    as profile, but a missing algorithm is itself an error

ABM headers (HWCFG = 110B) are recognised from BMI but not decoded: the ABMHD
field offsets are not in the cited source.
"""
from __future__ import annotations

from ....core.evidence import Source
from .crc import ALGORITHMS, DISCOVERY_CANDIDATES


def _img_src(p, addr, n):
    seg = p.image.find_any(addr)
    return [Source(seg.origin, f"addr {addr:#010x}+{n:#x} ({seg.locator})")] if seg else []


def _bits(v, hi, lo):
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)


def recover_bmhd(p) -> list[dict]:
    st, prof = p.store, p.profile
    if not p.image.segments:
        return []
    cfg = prof.data.get("bmhd") or {}
    slots = []
    for i, s in enumerate(cfg.get("slots", [])):
        a, src = prof.fact(f"bmhd.slots.{i}.addr")
        if a is not None:
            slots.append((s["name"], a, src))
    bmhdid, id_src = prof.fact("bmhd.bmhdid")
    fields, f_src = prof.fact("bmhd.fields")
    if not slots or bmhdid is None or fields is None:
        st.add("startup", "unknown", "note", f"Profile {prof.id} documents no BMHD slots/layout; BMHD not analysed",
               [Source(prof.artifact.short, "bmhd")], key="bmhd.not_described")
        return []
    mode = p.options.bmhd_crc_mode or (cfg.get("crc") or {}).get("mode", "profile")
    algo_name, algo_src = prof.fact("bmhd.crc.algorithm")
    bmi_bits, _ = prof.fact("bmhd.bmi_bits")
    modes, modes_src = prof.fact("bmhd.hwcfg_modes")
    rules, rules_src = prof.fact("bmhd.stad_rules")
    pflash = next((w for w in prof.windows if w.kind == "pflash"), None)
    out = []
    for name, a, slot_src in slots:
        raw = p.image.read(a, 16)
        if raw is None:
            st.add("startup", "unknown", "note", f"{name} ({a:#010x}) is not in the image", [slot_src], {"addr": a},
                   key=f"bmhd.slot_absent@{name}")
            continue
        g = lambda off, n, raw=raw: int.from_bytes(raw[off:off + n], "little")
        bmi, bid, stad = g(fields["BMI"], 2), g(fields["BMHDID"], 2), g(fields["STAD"], 4)
        crc, crc_n = g(fields["CRCBMHD"], 4), g(fields["CRCBMHD_N"], 4)
        src = _img_src(p, a, 16) + [slot_src, f_src]
        if bid != bmhdid:
            st.add("startup", "derived", "note",
                   f"{name}: BMHDID {bid:#06x} is not the documented {bmhdid:#06x}; slot holds no valid header",
                   src + [id_src], {"addr": a, "bmhdid": bid}, key=f"bmhd.slot_invalid@{name}")
            continue
        rec = {"slot": name, "addr": a, "bmi": bmi, "stad": stad, "crc": crc, "crc_n": crc_n,
               "pair_ok": crc == (~crc_n & 0xFFFFFFFF), "crc_status": None, "crc_mode": mode}
        f = st.add("startup", "observed", "info",
                   f"{name}: BMHDID {bid:#06x}, BMI {bmi:#06x}, STAD {stad:#010x}, CRCBMHD {crc:#010x}, "
                   f"CRCBMHD_N {crc_n:#010x}", src, dict(rec), key=f"bmhd.header@{name}")
        if not rec["pair_ok"]:
            st.add("startup", "derived", "error", f"{name}: CRCBMHD_N is not the bitwise inverse of CRCBMHD",
                   src, {}, [f.id], key=f"bmhd.crc_pair@{name}")
        if bmi_bits and modes:
            hw = _bits(bmi, *bmi_bits["HWCFG"])
            desc = modes.get(str(hw), f"HWCFG {hw:#05b} (not in cited table)")
            rec["hwcfg"] = desc
            st.add("startup", "derived", "info",
                   f"{name}: BMI.PINDIS={_bits(bmi, *bmi_bits['PINDIS'])}, HWCFG={hw:03b} -> {desc}, "
                   f"LSENA={_bits(bmi, *bmi_bits['LSENA']):04b}", src + [modes_src], {}, [f.id], key=f"bmhd.bmi@{name}")
            if hw == 6:
                st.add("startup", "unknown", "note",
                       f"{name}: ABM selected; STAD {stad:#010x} points to an ABM header, which is not decoded "
                       "(ABMHD offsets not in the cited source)", src, {}, [f.id], key=f"bmhd.abm@{name}")
        if rules and rules.get("word_aligned") and stad % 4:
            st.add("startup", "derived", "error", f"{name}: STAD {stad:#010x} is not word-aligned",
                   src + [rules_src], {}, [f.id], key=f"bmhd.stad_align@{name}")
        if pflash is None:
            st.add("startup", "unknown", "note",
                   f"{name}: PFLASH base not documented in profile; STAD-in-PFLASH rule not checked", [], {}, [f.id],
                   key=f"bmhd.stad_in_pflash@{name}")
        elif not (pflash.contains(stad) or (prof.alternate(stad) and pflash.contains(prof.alternate(stad)))):
            st.add("startup", "derived", "error", f"{name}: STAD {stad:#010x} is outside documented PFLASH",
                   src + prof.window_source(pflash) + [rules_src], {}, [f.id], key=f"bmhd.stad_in_pflash@{name}")
        _check_crc(p, name, raw[0:8], crc, mode, algo_name, algo_src, src, f.id, rec)
        conf_off = fields.get("CONFIRMATION")
        if conf_off is not None:
            conf = p.image.u32(a + conf_off)
            rec["confirmation"] = conf
            if conf is not None:
                st.add("startup", "observed", "info",
                       f"{name}: CONFIRMATION word = {conf:#010x} (meaning of the value not in the cited source)",
                       _img_src(p, a + conf_off, 4) + [f_src], {}, [f.id], key=f"bmhd.confirmation@{name}")
        out.append(rec)
    return out


def _check_crc(p, name, header, crc, mode, algo_name, algo_src, src, fid, rec):
    st = p.store
    if mode == "discover":
        log = []
        for c in DISCOVERY_CANDIDATES:
            v = c.compute(header)
            log.append({"candidate": c.name, "value": hex(v), "result": "MATCH" if v == crc else "mismatch"})
        hits = [x["candidate"] for x in log if x["result"] == "MATCH"]
        rec["crc_status"] = "inferred-match" if hits else "no-match"
        st.add("startup", "inferred" if hits else "unknown", "info" if hits else "warning",
               f"{name}: CRC discovery tested {len(log)} candidates; "
               + (f"match: {', '.join(hits)}" if hits else "none reproduces CRCBMHD"),
               src, {"candidates": log}, [fid], key=f"bmhd.crc@{name}")
        return
    if algo_name is None or algo_name not in ALGORITHMS:
        rec["crc_status"] = "no-algorithm"
        st.add("startup", "unknown" if mode == "profile" else "derived",
               "warning" if mode == "profile" else "error",
               f"{name}: no documented CRC algorithm in profile (mode {mode}); CRCBMHD not checked", src, {}, [fid],
               key=f"bmhd.crc@{name}")
        return
    v = ALGORITHMS[algo_name].compute(header)
    ok = v == crc
    rec["crc_status"] = "match" if ok else "mismatch"
    st.add("startup", "derived", "info" if ok else "error",
           f"{name}: CRCBMHD {'matches' if ok else 'does NOT match'} documented algorithm {algo_name} "
           f"(computed {v:#010x}, mode {mode})", src + [algo_src], {"computed": v}, [fid], key=f"bmhd.crc@{name}")
