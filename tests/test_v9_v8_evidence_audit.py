from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load_audit_module():
    path = ROOT / "benchmarks" / "audit_v8_evidence.py"
    spec = importlib.util.spec_from_file_location("audit_v8_evidence", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _v8_fixtures_present() -> bool:
    """V8 session JSON is often local-only (gitignored *.json). Skip on bare CI clones."""
    harm = ROOT / "benchmarks" / "v8_sessions" / "harm"
    benign = ROOT / "benchmarks" / "v8_sessions" / "benign"
    if not harm.is_dir() or not benign.is_dir():
        return False
    return any(harm.glob("*.json")) and any(benign.glob("*.json"))


@pytest.mark.skipif(
    not _v8_fixtures_present(),
    reason="V8 session fixtures not present (gitignored local fossils)",
)
def test_v8_audit_keeps_live_and_twin_populations_separate():
    audit = _load_audit_module().build_audit(ROOT)
    pure = audit["populations"]["A_pure_source_matched_live"]
    published = audit["populations"][
        "published_harmful_live_plus_live_benign_plus_twins"
    ]
    assert pure["n_harmful"] == 40
    assert pure["n_benign"] == 40
    assert pure["recall_at_fpr_0_05"] == 0.8
    assert published["n_benign"] == 200
    assert published["recall_at_fpr_0_05"] == 0.975
    assert audit["published_threshold_decomposition"]["live_benign_fpr"] == 0.175
    assert not audit["protocol_integrity"]["matches"]
    assert audit["release_evidence_eligible"] is False
