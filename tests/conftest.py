from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERMES_SRC = os.environ.get("HERMES_AGENT_SRC")
if not HERMES_SRC:
    raise RuntimeError("Set HERMES_AGENT_SRC to a Hermes Agent source checkout")
HERMES = Path(HERMES_SRC)
if not HERMES.is_dir():
    raise RuntimeError("Set HERMES_AGENT_SRC to a Hermes Agent source checkout")
sys.path.insert(0, str(HERMES))
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def plugin_module():
    path = ROOT / "proton-pass" / "__init__.py"
    spec = importlib.util.spec_from_file_location("hermes_proton_pass_plugin", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
