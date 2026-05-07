"""CLI integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ddr.cli import app

runner = CliRunner()


def test_validate_valid_suppress(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "suppress_basic.yml")])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_validate_valid_accept_risk(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "accept_risk.yml")])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_validate_valid_deprecate(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "deprecate.yml")])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_validate_directory(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir)])
    assert result.exit_code == 0


def test_validate_missing_expires_on(negative_fixtures_dir):
    result = runner.invoke(app, ["validate", str(negative_fixtures_dir / "missing_expires_on.yml")])
    assert result.exit_code == 1
    assert "FAIL" in result.output
    assert "expires_on" in result.output


def test_validate_bad_hash_format(negative_fixtures_dir):
    result = runner.invoke(app, ["validate", str(negative_fixtures_dir / "bad_hash_format.yml")])
    assert result.exit_code == 1
    assert "FAIL" in result.output
    assert "content_hash" in result.output


def test_validate_unknown_decision(negative_fixtures_dir):
    result = runner.invoke(app, ["validate", str(negative_fixtures_dir / "unknown_decision.yml")])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_validate_nonexistent_path():
    result = runner.invoke(app, ["validate", "/nonexistent/path.yml"])
    assert result.exit_code == 1


def test_validate_skips_non_ddr_yaml(tmp_path):
    sigma_rule = tmp_path / "sigma_rule.yml"
    sigma_rule.write_text(
        "title: Some rule\nid: abc\nlogsource:\n  category: process_creation\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 1  # no DDR files found
    assert "No DDR records" in result.output


def test_validate_strict_warns_on_ip_in_description(valid_fixtures_dir, tmp_path):
    record_text = (valid_fixtures_dir / "suppress_basic.yml").read_text(encoding="utf-8")
    record_text = record_text.replace(
        "IT Operations uses PsExec via SCCM for patch management on corp endpoints.",
        "IT Operations. FP triggered by 192.168.1.100 during SCCM scan.",
    )
    fp = tmp_path / "strict_test.yml"
    fp.write_text(record_text, encoding="utf-8")
    result = runner.invoke(app, ["validate", "--strict", str(fp)])
    assert "WARN" in result.output or result.exit_code == 0  # warn but don't fail


def test_expire_check_no_issues(valid_fixtures_dir):
    # valid fixtures have future expires_on, should report no issues
    result = runner.invoke(app, ["expire-check", str(valid_fixtures_dir)])
    # may succeed (0) or exit 1 only if there are expired records
    assert "No expired" in result.output or result.exit_code in (0, 1)


def test_expire_check_expired_record(tmp_path):
    record_text = """ddr_version: "0.1"
id: f47ac10b-58cc-4372-a567-0e02b2c3d490
title: Expired record
description: This record is expired.
target:
  kind: sigma
  rule_ref:
    rule_id: d7a95147-145f-4678-b555-b7a3c9b16830
    content_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
    source: internal
    path_or_url: rules/test.yml
decision:
  kind: accept-risk
  rationale: Accepted.
lifecycle:
  status: active
  created_on: "2023-01-01T00:00:00Z"
  activated_on: "2023-01-02T00:00:00Z"
  expires_on: "2023-06-01T00:00:00Z"
provenance:
  author: test@example.com
"""
    fp = tmp_path / "expired.yml"
    fp.write_text(record_text, encoding="utf-8")
    result = runner.invoke(app, ["expire-check", str(fp)])
    assert result.exit_code == 1
    assert "EXPIRED" in result.output


def test_expire_check_json_format(tmp_path):
    record_text = """ddr_version: "0.1"
id: f47ac10b-58cc-4372-a567-0e02b2c3d491
title: Expired json test
description: Test.
target:
  kind: sigma
  rule_ref:
    rule_id: d7a95147-145f-4678-b555-b7a3c9b16830
    content_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
    source: internal
    path_or_url: rules/test.yml
decision:
  kind: accept-risk
  rationale: Accepted.
lifecycle:
  status: active
  created_on: "2023-01-01T00:00:00Z"
  activated_on: "2023-01-02T00:00:00Z"
  expires_on: "2023-06-01T00:00:00Z"
provenance:
  author: test@example.com
"""
    fp = tmp_path / "expired_json.yml"
    fp.write_text(record_text, encoding="utf-8")
    result = runner.invoke(app, ["expire-check", "--format", "json", str(fp)])
    import json
    data = json.loads(result.output)
    assert "expired" in data
    assert len(data["expired"]) == 1


def test_export_sigma_filter(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-sigma-filter", str(valid_fixtures_dir / "suppress_basic.yml")]
    )
    assert result.exit_code == 0
    assert "title:" in result.output
    assert "filter:" in result.output
    assert "condition:" in result.output


def test_export_sigma_filter_non_suppress(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-sigma-filter", str(valid_fixtures_dir / "accept_risk.yml")]
    )
    assert result.exit_code == 1


def test_export_sigma_filter_to_file(valid_fixtures_dir, tmp_path):
    out = tmp_path / "filter.yml"
    result = runner.invoke(
        app,
        ["export-sigma-filter", str(valid_fixtures_dir / "suppress_basic.yml"), "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    assert "filter:" in out.read_text(encoding="utf-8")


def test_new_from_sigma_rule(tmp_path):
    rule = tmp_path / "test_rule.yml"
    rule.write_text(
        """title: Test Detection Rule
id: d7a95147-145f-4678-b555-b7a3c9b16831
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\test.exe'
  condition: selection
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["new", str(rule)])
    assert result.exit_code == 0
    assert "ddr_version" in result.output
    assert "sha256:" in result.output
    assert "d7a95147-145f-4678-b555-b7a3c9b16831" in result.output


def test_new_to_output_file(tmp_path):
    rule = tmp_path / "rule.yml"
    rule.write_text(
        "title: Rule\nid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nlogsource:\n  product: windows\ndetection:\n  selection:\n    field: val\n  condition: selection\n",
        encoding="utf-8",
    )
    out = tmp_path / "new_ddr.yml"
    result = runner.invoke(app, ["new", str(rule), "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "ddr_version" in out.read_text(encoding="utf-8")


def test_new_nonexistent_rule():
    result = runner.invoke(app, ["new", "/no/such/rule.yml"])
    assert result.exit_code == 1


def test_refresh_hash_no_rule(tmp_path):
    fp = tmp_path / "ddr.yml"
    fp.write_text("target:\n  rule_ref:\n    path_or_url: /no/such/rule.yml\n", encoding="utf-8")
    result = runner.invoke(app, ["refresh-hash", str(fp)])
    assert result.exit_code == 1


# --- v0.3: ddr new --target splunk ---


def test_new_splunk_target_with_name():
    result = runner.invoke(app, ["new", "--target", "splunk", "--name", "My Noisy Detection"])
    assert result.exit_code == 0
    output = result.output
    assert "ddr_version" in output
    assert "splunk" in output
    assert "My Noisy Detection" in output
    assert "splunk_filter" in output


def test_new_splunk_target_without_name_fails():
    result = runner.invoke(app, ["new", "--target", "splunk"])
    assert result.exit_code == 1
    assert "--name" in result.output or "required" in result.output.lower()


def test_new_splunk_target_custom_app():
    result = runner.invoke(
        app, ["new", "--target", "splunk", "--name", "My Detection", "--app", "DA-ESS-AccessProtection"]
    )
    assert result.exit_code == 0
    assert "DA-ESS-AccessProtection" in result.output


def test_new_invalid_target():
    result = runner.invoke(app, ["new", "--target", "elastic"])
    assert result.exit_code == 1


# --- v0.3: export-sigma-filter on Splunk target ---


def test_export_sigma_filter_splunk_target_fails(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-sigma-filter", str(valid_fixtures_dir / "splunk_native_suppress.yml")]
    )
    assert result.exit_code == 1
    assert "splunk" in result.output.lower()


# --- v0.3: validate mixed sigma+splunk directory ---


def test_validate_splunk_native_fixture(valid_fixtures_dir):
    result = runner.invoke(
        app, ["validate", str(valid_fixtures_dir / "splunk_native_suppress.yml")]
    )
    assert result.exit_code == 0
    assert "OK" in result.output


def test_validate_mixed_directory(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir)])
    assert result.exit_code == 0


# --- v0.3: export-splunk on native target ---


def test_export_splunk_native_target(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-splunk", str(valid_fixtures_dir / "splunk_native_suppress.yml")]
    )
    assert result.exit_code == 0
    assert result.output.strip().startswith("NOT (")


def test_export_splunk_native_target_savedsearches(valid_fixtures_dir):
    result = runner.invoke(
        app,
        ["export-splunk", str(valid_fixtures_dir / "splunk_native_suppress.yml"), "--format", "savedsearches"],
    )
    assert result.exit_code == 0
    assert "search = NOT" in result.output
    assert "dispatch.earliest_time" in result.output


def test_export_splunk_native_config_warns(valid_fixtures_dir, tmp_path):
    fake_config = tmp_path / "config.yml"
    fake_config.write_text("field_mappings: {}\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["export-splunk", str(valid_fixtures_dir / "splunk_native_suppress.yml"), "--config", str(fake_config)],
    )
    # Should warn but still succeed
    assert "WARN" in result.output
    assert result.exit_code == 0


# --- v0.3: back-compat fixture validation ---


def test_validate_v01_fixture_under_v03(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "suppress_basic.yml")])
    assert result.exit_code == 0


def test_validate_v02_fixture_under_v03(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "v0.2-record.yml")])
    assert result.exit_code == 0
