import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def gen(tmp_path_factory):
    out = tmp_path_factory.mktemp("synthetic")
    subprocess.run([sys.executable, str(ROOT / "fixtures/synthetic/make_fixtures.py"), str(out)], check=True,
                   capture_output=True)
    return out


@pytest.fixture(scope="session")
def syn_profile(gen):
    return str(gen / "profile_synthetic_tc38x.json")


def has(p, pattern, **kw):
    return any(re.search(pattern, f.claim) for f in p.store.query(**kw))


def find(p, pattern, **kw):
    return next(f for f in p.store.query(**kw) if re.search(pattern, f.claim))
