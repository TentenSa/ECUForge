"""Shipped MCU profiles must contain only cited, documented facts."""
import json

import pytest

from ecuforge.silicon.infineon.aurix.profile import DeviceProfile, TARGET_DIR

SHIPPED = DeviceProfile.available()


@pytest.mark.parametrize("name", SHIPPED)
def test_no_synthetic_and_every_fact_cited(name):
    prof = DeviceProfile.load(name)
    assert prof.synthetic_facts() == []

    def walk(node):
        if isinstance(node, dict):
            if "value" in node:
                assert node["source"] in prof.sources, node
                assert node["verification"] in ("documented", "documented-secondary"), node
                assert prof.sources[node["source"]].get("url"), node["source"]
                assert node.get("ref"), node
            for k, v in node.items():
                if k != "sources":
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(json.loads((TARGET_DIR / f"{name}.json").read_text()))


def test_cpu_memory_from_addendum():
    p = DeviceProfile.load("tc38x")
    assert p.cores == 4
    sizes = [p.fact(f"cpus.{i}.dspr.size")[0] for i in range(4)]
    assert sizes == [240 * 1024, 240 * 1024, 96 * 1024, 96 * 1024]  # "240 in CPU0&1; 96 other"
    assert p.fact("cpus.2.dspr.base") == (None, None)  # not documented -> unknown, never guessed
    assert p.cpu_window(2, "dspr") is None and p.cpu_window(0, "dspr").start == 0x70000000
    assert p.canonical(0xA0000020) == 0xA0000020  # no documented bus alias -> no aliasing
    assert "flash.pflash.base" in p.facts_unknown()


def test_bmhd_facts_documented():
    p = DeviceProfile.load("tc39x")
    v, src = p.fact("bmhd.slots.0.addr")
    assert v == 0xAF400000 and "AP32381" in src.excerpt
    assert p.fact("bmhd.crc.algorithm")[0] == "aurix_tc3xx_bmhd"
