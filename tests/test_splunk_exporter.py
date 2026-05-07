"""Tests for Splunk SPL exporter."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from ddr.models.record import DDRRecord

_VALID_HASH = "sha256:" + "a" * 64
_NOW = datetime(2025, 1, 15, 9, 0, 0, tzinfo=UTC)
_FUTURE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=UTC)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

_sigma_to_spl_available = True
try:
    import sigma_to_spl  # noqa: F401
except ImportError:
    _sigma_to_spl_available = False

requires_sigma_to_spl = pytest.mark.skipif(
    not _sigma_to_spl_available, reason="sigma-to-spl not installed"
)


def _suppress_record_data(condition: str = "not known_fp") -> dict:
    return {
        "ddr_version": "0.1",
        "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "title": "Test FP Suppression",
        "description": "Test.",
        "target": {
            "kind": "sigma",
            "rule_ref": {
                "rule_id": "d7a95147-145f-4678-b555-b7a3c9b16830",
                "content_hash": _VALID_HASH,
                "source": "sigmahq",
                "path_or_url": "https://example.com/rule.yml",
            },
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Known FP.",
            "tuning": {
                "filter_title": "Test FP Filter",
                "logsource": {"category": "process_creation", "product": "windows"},
                "selections": {"known_fp": {"ParentImage|endswith": ["\\ccmexec.exe"]}},
                "condition": condition,
            },
        },
        "lifecycle": {
            "status": "active",
            "created_on": _NOW.isoformat(),
            "activated_on": _NOW.isoformat(),
            "expires_on": _FUTURE.isoformat(),
        },
        "provenance": {"author": "alice@example.com"},
    }


# ── _strip_not (always run) ───────────────────────────────────────────────────


def test_strip_not_simple():
    from ddr.exporters.splunk import _strip_not

    inner, had_not = _strip_not("not known_fp")
    assert inner == "known_fp"
    assert had_not is True


def test_strip_not_parens():
    from ddr.exporters.splunk import _strip_not

    inner, had_not = _strip_not("not (known_fp_1 or known_fp_2)")
    assert inner == "known_fp_1 or known_fp_2"
    assert had_not is True


def test_strip_not_uppercase():
    from ddr.exporters.splunk import _strip_not

    inner, had_not = _strip_not("NOT known_fp")
    assert inner == "known_fp"
    assert had_not is True


def test_strip_not_no_not():
    from ddr.exporters.splunk import _strip_not

    inner, had_not = _strip_not("known_fp")
    assert inner == "known_fp"
    assert had_not is False


# ── Non-suppress raises (no sigma-to-spl needed) ─────────────────────────────


def test_build_splunk_suppression_non_suppress_raises():
    from ddr.exporters.splunk import build_splunk_suppression

    data = _suppress_record_data()
    data["decision"] = {"kind": "accept-risk", "rationale": "Accepted."}
    record = DDRRecord.model_validate(data)
    with pytest.raises(ValueError, match="suppress"):
        build_splunk_suppression(record)


# ── Missing sigma-to-spl error ────────────────────────────────────────────────


def test_missing_sigma_to_spl_raises_runtime_error():
    """RuntimeError with install instructions when sigma_to_spl is not importable."""
    from ddr.exporters.splunk import _require_sigma_to_spl

    with (
        patch.dict(sys.modules, {"sigma_to_spl": None}),
        pytest.raises(RuntimeError, match="sigma-to-spl"),
    ):
        _require_sigma_to_spl()


# ── Unit tests (require sigma-to-spl) ────────────────────────────────────────


@requires_sigma_to_spl
def test_build_splunk_suppression_returns_not_clause():
    from ddr.exporters.splunk import build_splunk_suppression

    record = DDRRecord.model_validate(_suppress_record_data())
    result = build_splunk_suppression(record)
    assert result.startswith("NOT (")
    assert result.endswith(")")
    assert "ccmexec.exe" in result.lower() or "ParentImage" in result


@requires_sigma_to_spl
def test_build_splunk_suppression_no_not_warns():
    from ddr.exporters.splunk import build_splunk_suppression

    record = DDRRecord.model_validate(_suppress_record_data(condition="known_fp"))
    with pytest.warns(UserWarning, match="does not start with 'not'"):
        result = build_splunk_suppression(record)
    assert result.startswith("(")
    assert not result.startswith("NOT (")


@requires_sigma_to_spl
def test_export_to_spl_savedsearches_format():
    from ddr.exporters.splunk import export_to_spl

    record = DDRRecord.model_validate(_suppress_record_data())
    result = export_to_spl(record, fmt="savedsearches")
    assert "[test_fp_filter]" in result
    assert "search = NOT" in result
    assert "dispatch.earliest_time" in result


@requires_sigma_to_spl
def test_export_to_spl_writes_file(tmp_path):
    from ddr.exporters.splunk import export_to_spl

    record = DDRRecord.model_validate(_suppress_record_data())
    out = tmp_path / "fragment.spl"
    result = export_to_spl(record, output=out)
    assert out.exists()
    assert out.read_text(encoding="utf-8") == result
    assert "NOT (" in result


# ── v0.3: _normalize_splunk_filter ───────────────────────────────────────────


def test_normalize_splunk_filter_plain():
    from ddr.exporters.splunk import _normalize_splunk_filter

    assert _normalize_splunk_filter("src_ip=10.0.0.1") == "src_ip=10.0.0.1"


def test_normalize_splunk_filter_strips_outer_not():
    from ddr.exporters.splunk import _normalize_splunk_filter

    assert _normalize_splunk_filter("NOT (src_ip=10.0.0.1)") == "src_ip=10.0.0.1"


def test_normalize_splunk_filter_compound():
    from ddr.exporters.splunk import _normalize_splunk_filter

    result = _normalize_splunk_filter('NOT (src_ip="10.0.0.0/8" OR user=svc_foo)')
    assert result == 'src_ip="10.0.0.0/8" OR user=svc_foo'


# ── v0.3: Splunk-native build_splunk_suppression (no sigma-to-spl) ───────────


def _splunk_native_record_data(splunk_filter: str = 'src_ip="10.20.30.0/24"') -> dict:
    return {
        "ddr_version": "0.3",
        "id": "7c3e9a2f-b841-4d12-9f6e-1a5c8d047b3e",
        "title": "Suppress: Excessive Failed Logins",
        "description": "FP suppression for vuln scanner.",
        "target": {
            "kind": "splunk",
            "query_ref": {"name": "Excessive Failed Logins", "app": "DA-ESS-AccessProtection"},
        },
        "decision": {
            "kind": "suppress",
            "rationale": "Authorized scanner.",
            "tuning": {
                "kind": "splunk",
                "splunk_filter": splunk_filter,
            },
        },
        "lifecycle": {
            "status": "active",
            "created_on": _NOW.isoformat(),
            "activated_on": _NOW.isoformat(),
            "expires_on": _FUTURE.isoformat(),
        },
        "provenance": {"author": "cray44@example.com"},
    }


def test_build_splunk_suppression_native_returns_not_clause():
    from ddr.exporters.splunk import build_splunk_suppression

    record = DDRRecord.model_validate(_splunk_native_record_data())
    result = build_splunk_suppression(record)
    assert result == 'NOT (src_ip="10.20.30.0/24")'


def test_build_splunk_suppression_native_strips_outer_not():
    from ddr.exporters.splunk import build_splunk_suppression

    record = DDRRecord.model_validate(_splunk_native_record_data('NOT (src_ip="10.20.30.0/24")'))
    result = build_splunk_suppression(record)
    assert result == 'NOT (src_ip="10.20.30.0/24")'


def test_build_splunk_suppression_native_no_sigma_to_spl_needed(monkeypatch):
    """Splunk-native export must not import sigma_to_spl."""
    import sys

    from ddr.exporters.splunk import build_splunk_suppression

    record = DDRRecord.model_validate(_splunk_native_record_data())

    # Simulate sigma-to-spl absent
    original = sys.modules.get("sigma_to_spl")
    sys.modules["sigma_to_spl"] = None  # type: ignore[assignment]
    try:
        result = build_splunk_suppression(record)
        assert result.startswith("NOT (")
    finally:
        if original is None:
            sys.modules.pop("sigma_to_spl", None)
        else:
            sys.modules["sigma_to_spl"] = original


def test_export_to_spl_native_fragment():
    from ddr.exporters.splunk import export_to_spl

    record = DDRRecord.model_validate(_splunk_native_record_data())
    result = export_to_spl(record, fmt="fragment")
    assert result == 'NOT (src_ip="10.20.30.0/24")'


def test_export_to_spl_native_savedsearches():
    from ddr.exporters.splunk import export_to_spl

    record = DDRRecord.model_validate(_splunk_native_record_data())
    result = export_to_spl(record, fmt="savedsearches")
    assert "excessive_failed_logins" in result
    assert 'search = NOT (src_ip="10.20.30.0/24")' in result
    assert "dispatch.earliest_time" in result


# ── Integration: example 06 (no sigma-to-spl) ────────────────────────────────


def test_example_06_validates():
    from ruamel.yaml import YAML

    ddr_path = EXAMPLES_DIR / "06-splunk-native-savedsearch" / "ddr.yml"
    y = YAML(typ="safe")
    with open(ddr_path, encoding="utf-8") as fh:
        data = y.load(fh)
    record = DDRRecord.model_validate(data)
    assert record.target.kind == "splunk"


def test_example_06_export_fragment(monkeypatch):
    import sys

    from ruamel.yaml import YAML

    from ddr.exporters.splunk import build_splunk_suppression

    ddr_path = EXAMPLES_DIR / "06-splunk-native-savedsearch" / "ddr.yml"
    y = YAML(typ="safe")
    with open(ddr_path, encoding="utf-8") as fh:
        data = y.load(fh)
    record = DDRRecord.model_validate(data)

    # Prove it works without sigma-to-spl installed
    original = sys.modules.get("sigma_to_spl")
    sys.modules["sigma_to_spl"] = None  # type: ignore[assignment]
    try:
        result = build_splunk_suppression(record)
        assert result.startswith("NOT (")
        assert "10.20.30.0/24" in result
    finally:
        if original is None:
            sys.modules.pop("sigma_to_spl", None)
        else:
            sys.modules["sigma_to_spl"] = original


# ── Integration: real suppress examples ──────────────────────────────────────


@requires_sigma_to_spl
@pytest.mark.parametrize(
    "example_dir,expected_in_spl",
    [
        ("01-psexec-admin-suppression", "ParentImage"),
        ("02-nessus-network-scanner", "id.orig_h"),
        ("03-scheduled-task-vendor-noise", "ParentImage"),
    ],
)
def test_export_splunk_suppress_examples(example_dir, expected_in_spl):
    from ruamel.yaml import YAML

    from ddr.exporters.splunk import build_splunk_suppression

    ddr_path = EXAMPLES_DIR / example_dir / "ddr.yml"
    y = YAML(typ="safe")
    with open(ddr_path, encoding="utf-8") as fh:
        data = y.load(fh)
    record = DDRRecord.model_validate(data)

    result = build_splunk_suppression(record)
    assert result.startswith("NOT ("), f"Expected NOT (...), got: {result[:80]}"
    assert result.endswith(")")
    assert expected_in_spl in result, f"Expected '{expected_in_spl}' in: {result}"
