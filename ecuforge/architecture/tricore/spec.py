"""TriCore architecture facts (core-level, silicon independent), each with a citation.

Null facts are UNKNOWN: checks that depend on them report `unknown` instead of
assuming a value.
"""
from __future__ import annotations

import json
from pathlib import Path

from ...core.evidence import Artifact, Source

SPEC_PATH = Path(__file__).parent / "tricore.json"


class TriCoreSpec:
    def __init__(self, path: Path = SPEC_PATH):
        self.path = path
        self.data = json.loads(path.read_text())
        self.artifact = Artifact.from_path(path, "arch_spec", "architecture.tricore.spec")

    def fact(self, key: str):
        node = self.data.get(key)
        if not node:
            return None, None
        doc = self.data["sources"].get(node["source"], {})
        excerpt = " ".join(str(x) for x in (doc.get("vendor"), doc.get("document"), doc.get("revision"),
                                             doc.get("date")) if x)
        return node["value"], Source(self.artifact.short, f"fact {key} [{node['verification']}]",
                                     f"{excerpt}; {node.get('ref', '')}")
