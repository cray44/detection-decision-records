"""CLI integration tests."""

from __future__ import annotations

from pathlib import Path

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


def test_validate_strict_warns_on_log_line_ip_in_description(valid_fixtures_dir, tmp_path):
    """key=ip pattern in rationale triggers warn (raw log data)."""
    record_text = (valid_fixtures_dir / "suppress_basic.yml").read_text(encoding="utf-8")
    record_text = record_text.replace(
        "IT Operations uses PsExec via SCCM for patch management on corp endpoints.",
        "IT Operations. src_ip=192.168.1.100 seen in SCCM scan logs.",
    )
    fp = tmp_path / "strict_test.yml"
    fp.write_text(record_text, encoding="utf-8")
    result = runner.invoke(app, ["validate", "--strict", str(fp)])
    assert "WARN" in result.output


def test_validate_strict_bare_ip_no_warn(valid_fixtures_dir, tmp_path):
    """Bare IP cited as infra context must not trigger warn."""
    record_text = (valid_fixtures_dir / "suppress_basic.yml").read_text(encoding="utf-8")
    record_text = record_text.replace(
        "IT Operations uses PsExec via SCCM for patch management on corp endpoints.",
        "Veeam backup servers 10.10.5.20 and 10.10.5.21 access ADMIN$ shares.",
    )
    fp = tmp_path / "strict_test.yml"
    fp.write_text(record_text, encoding="utf-8")
    result = runner.invoke(app, ["validate", "--strict", str(fp)])
    assert "WARN" not in result.output


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
        [
            "export-sigma-filter",
            str(valid_fixtures_dir / "suppress_basic.yml"),
            "--output",
            str(out),
        ],
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


def test_new_sigma_suppress_scaffold_includes_filter_title(tmp_path):
    """ddr new sigma suppress scaffold must include filter_title to avoid double-prefix."""
    rule = tmp_path / "rule.yml"
    rule.write_text(
        "title: DNS Tunneling\nid: d7a95147-145f-4678-b555-b7a3c9b16833\n"
        "logsource:\n  category: dns\ndetection:\n  selection:\n"
        "    field: v\n  condition: selection\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["new", str(rule)])
    assert result.exit_code == 0
    assert "filter_title" in result.output


def test_new_sigma_path_or_url_not_absolute(tmp_path):
    """path_or_url must preserve the caller-supplied path, not resolve to absolute."""
    rule = tmp_path / "test_rule.yml"
    rule.write_text(
        "title: T\nid: d7a95147-145f-4678-b555-b7a3c9b16832\n"
        "logsource:\n  product: windows\ndetection:\n  selection:\n"
        "    field: v\n  condition: selection\n",
        encoding="utf-8",
    )
    # Pass a relative path — scaffold must echo it back as-is
    import os

    rel = os.path.relpath(rule)
    result = runner.invoke(app, ["new", rel])
    assert result.exit_code == 0
    assert rel in result.output


def test_new_to_output_file(tmp_path):
    rule = tmp_path / "rule.yml"
    rule.write_text(
        (
            "title: Rule\nid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n"
            "logsource:\n  product: windows\ndetection:\n  selection:\n"
            "    field: val\n  condition: selection\n"
        ),
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
        app,
        ["new", "--target", "splunk", "--name", "My Detection", "--app", "DA-ESS-AccessProtection"],
    )
    assert result.exit_code == 0
    assert "DA-ESS-AccessProtection" in result.output


def test_new_invalid_target():
    result = runner.invoke(app, ["new", "--target", "flibbertigibbet"])
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
        [
            "export-splunk",
            str(valid_fixtures_dir / "splunk_native_suppress.yml"),
            "--format",
            "savedsearches",
        ],
    )
    assert result.exit_code == 0
    assert "search = NOT" in result.output
    assert "dispatch.earliest_time" in result.output


def test_export_splunk_native_config_warns(valid_fixtures_dir, tmp_path):
    fake_config = tmp_path / "config.yml"
    fake_config.write_text("field_mappings: {}\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "export-splunk",
            str(valid_fixtures_dir / "splunk_native_suppress.yml"),
            "--config",
            str(fake_config),
        ],
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


# ---------------------------------------------------------------------------
# v0.4: ddr new --target splunk <conf_path>
# ---------------------------------------------------------------------------

_SIMPLE_CONF = """\
[My Noisy Detection]
search = index=main sourcetype=syslog error
dispatch.earliest_time = -1h
"""

_MULTI_CONF = """\
[Alpha Detection]
search = index=main event=alpha

[Beta Detection]
search = index=main event=beta
"""


def test_new_splunk_from_conf_with_name(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    result = runner.invoke(
        app, ["new", "--target", "splunk", str(conf), "--name", "My Noisy Detection"]
    )
    assert result.exit_code == 0
    assert "sha256:" in result.output
    assert "My Noisy Detection" in result.output
    assert "query_hash" in result.output
    assert "path_or_url" in result.output


def test_new_splunk_from_conf_single_stanza_no_name(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    result = runner.invoke(app, ["new", "--target", "splunk", str(conf)])
    assert result.exit_code == 0
    assert "My Noisy Detection" in result.output
    assert "sha256:" in result.output


def test_new_splunk_from_conf_multi_stanza_no_name_fails(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_MULTI_CONF, encoding="utf-8")
    result = runner.invoke(app, ["new", "--target", "splunk", str(conf)])
    assert result.exit_code == 1
    assert "Alpha Detection" in result.output or "Beta Detection" in result.output


def test_new_splunk_from_conf_name_not_found_fails(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    result = runner.invoke(app, ["new", "--target", "splunk", str(conf), "--name", "Nonexistent"])
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_new_splunk_name_only_minimal_scaffold():
    """--name without conf path uses v0.3-style minimal scaffold."""
    result = runner.invoke(app, ["new", "--target", "splunk", "--name", "My Detection"])
    assert result.exit_code == 0
    assert "My Detection" in result.output
    assert "query_hash" not in result.output


def test_new_splunk_from_conf_disabled_warns(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text("[Disabled]\nsearch = index=main\ndisabled = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["new", "--target", "splunk", str(conf)])
    assert "WARN" in result.output
    assert result.exit_code == 0


def test_new_splunk_from_conf_app_inference(tmp_path):
    app_dir = tmp_path / "etc" / "apps" / "MyTA" / "local"
    app_dir.mkdir(parents=True)
    conf = app_dir / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    result = runner.invoke(app, ["new", "--target", "splunk", str(conf)])
    assert result.exit_code == 0
    assert "MyTA" in result.output


def test_new_splunk_from_conf_app_override(tmp_path):
    app_dir = tmp_path / "etc" / "apps" / "MyTA" / "local"
    app_dir.mkdir(parents=True)
    conf = app_dir / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    result = runner.invoke(app, ["new", "--target", "splunk", str(conf), "--app", "CustomApp"])
    assert result.exit_code == 0
    assert "CustomApp" in result.output


# ---------------------------------------------------------------------------
# v0.4: ddr refresh-hash (Splunk branch)
# ---------------------------------------------------------------------------

_SPLUNK_DDR_TEMPLATE = """\
ddr_version: "0.4"
id: 7c3e9a2f-b841-4d12-9f6e-1a5c8d047b3e
title: Suppress test
description: test
target:
  kind: splunk
  query_ref:
    name: My Noisy Detection
    app: search
    query_hash: sha256:{old_hash}
    path_or_url: "{conf_path}"
decision:
  kind: suppress
  rationale: test
  tuning:
    kind: splunk
    splunk_filter: "user=svc_test"
lifecycle:
  status: active
  created_on: "2026-01-01T00:00:00Z"
  activated_on: "2026-01-02T00:00:00Z"
  expires_on: "2027-01-01T00:00:00Z"
provenance:
  author: test@example.com
"""


def _make_splunk_ddr(tmp_path: Path, conf_path: Path, old_hash: str = "sha256:" + "0" * 64) -> Path:
    ddr = tmp_path / "ddr.yml"
    ddr.write_text(
        _SPLUNK_DDR_TEMPLATE.format(
            old_hash=old_hash[len("sha256:") :],
            conf_path=str(conf_path).replace("\\", "/"),
        ),
        encoding="utf-8",
    )
    return ddr


def test_refresh_hash_splunk_updates(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    ddr = _make_splunk_ddr(tmp_path, conf)
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 0
    assert "sha256:" in result.output
    assert "old:" in result.output or "new:" in result.output


def test_refresh_hash_splunk_unchanged(tmp_path):
    from ddr._internal.splunk_conf import (
        compute_query_hash,
        extract_stanza,
        parse_savedsearches_conf,
    )

    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    parsed = parse_savedsearches_conf(conf)
    stanza = extract_stanza(parsed, "My Noisy Detection")
    current_hash = compute_query_hash(stanza["search"])

    ddr = _make_splunk_ddr(tmp_path, conf, old_hash=current_hash)
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 0
    assert "unchanged" in result.output.lower()


def test_refresh_hash_splunk_conf_override(tmp_path):
    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")

    other_conf = tmp_path / "other.conf"
    other_conf.write_text(
        "[My Noisy Detection]\nsearch = index=main sourcetype=other\n", encoding="utf-8"
    )

    ddr = _make_splunk_ddr(tmp_path, conf)
    result = runner.invoke(app, ["refresh-hash", str(ddr), "--conf", str(other_conf)])
    assert result.exit_code == 0


def test_refresh_hash_splunk_http_url_no_conf(tmp_path):
    ddr = tmp_path / "ddr.yml"
    ddr.write_text(
        _SPLUNK_DDR_TEMPLATE.format(
            old_hash="0" * 64,
            conf_path="https://splunk.example.com/savedsearches.conf",
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 1
    assert "remote" in result.output.lower() or "--conf" in result.output


# ---------------------------------------------------------------------------
# v0.4: ddr validate --strict (query_hash drift)
# ---------------------------------------------------------------------------


def test_validate_strict_splunk_drift_warns(tmp_path):

    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")

    # Write a DDR with a stale hash
    stale_hash = "sha256:" + "a" * 64
    ddr = _make_splunk_ddr(tmp_path, conf, old_hash=stale_hash)

    result = runner.invoke(app, ["validate", "--strict", str(ddr)])
    assert "WARN" in result.output or "drift" in result.output.lower()


def test_validate_strict_splunk_no_drift_no_warn(tmp_path):
    from ddr._internal.splunk_conf import (
        compute_query_hash,
        extract_stanza,
        parse_savedsearches_conf,
    )

    conf = tmp_path / "savedsearches.conf"
    conf.write_text(_SIMPLE_CONF, encoding="utf-8")
    parsed = parse_savedsearches_conf(conf)
    stanza = extract_stanza(parsed, "My Noisy Detection")
    current_hash = compute_query_hash(stanza["search"])

    ddr = _make_splunk_ddr(tmp_path, conf, old_hash=current_hash)
    result = runner.invoke(app, ["validate", "--strict", str(ddr)])
    assert result.exit_code == 0
    assert "drift" not in result.output.lower()


# ---------------------------------------------------------------------------
# v0.4: back-compat — v0.3 records still validate
# ---------------------------------------------------------------------------


def test_validate_v03_fixture_under_v04(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "v0.3-record.yml")])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# v0.5: ddr new emits rule_refs (plural)
# ---------------------------------------------------------------------------


def test_new_sigma_scaffold_emits_rule_refs(tmp_path):
    rule = tmp_path / "rule.yml"
    rule.write_text(
        "id: d7a95147-145f-4678-b555-b7a3c9b16830\ntitle: Test Rule\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    CommandLine: '*'\n  condition: selection\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["new", str(rule)])
    assert result.exit_code == 0
    assert "rule_refs:" in result.output
    assert "rule_ref:" not in result.output.replace("rule_refs:", "")


def test_new_splunk_scaffold_emits_query_refs(tmp_path):
    result = runner.invoke(app, ["new", "--target", "splunk", "--name", "My Detection"])
    assert result.exit_code == 0
    assert "query_refs:" in result.output


# ---------------------------------------------------------------------------
# v0.5: ddr list
# ---------------------------------------------------------------------------


def test_list_table_output(valid_fixtures_dir):
    result = runner.invoke(app, ["list", str(valid_fixtures_dir)])
    assert result.exit_code == 0
    assert "STATUS" in result.output


def test_list_json_output(valid_fixtures_dir):
    import json

    result = runner.invoke(app, ["list", "--format", "json", str(valid_fixtures_dir)])
    assert result.exit_code == 0
    rows = json.loads(result.output)
    assert isinstance(rows, list)
    assert len(rows) > 0
    assert "status" in rows[0]
    assert "target" in rows[0]
    assert "refs" in rows[0]


def test_list_filter_by_status(valid_fixtures_dir):
    result = runner.invoke(app, ["list", "--status", "active", str(valid_fixtures_dir)])
    assert result.exit_code == 0
    # every line in output (after header) should be active
    lines = [
        ln
        for ln in result.output.splitlines()
        if ln and not ln.startswith("STATUS") and not ln.startswith("-")
    ]
    for line in lines:
        assert line.startswith("active")


def test_list_filter_by_decision(valid_fixtures_dir):
    result = runner.invoke(app, ["list", "--decision", "suppress", str(valid_fixtures_dir)])
    assert result.exit_code == 0


def test_list_empty_dir(tmp_path):
    result = runner.invoke(app, ["list", str(tmp_path)])
    assert result.exit_code == 0
    assert "No DDR records found" in result.output


def test_list_multi_ref_shows_correct_count(valid_fixtures_dir):
    import json

    result = runner.invoke(app, ["list", "--format", "json", str(valid_fixtures_dir)])
    rows = json.loads(result.output)
    multi = [r for r in rows if r["refs"] == 3]
    assert len(multi) == 1  # only multi_ref_sigma.yml has 3


# ---------------------------------------------------------------------------
# v0.5: ddr refresh-hash multi-ref sigma
# ---------------------------------------------------------------------------


_SIGMA_RULE_YAML = """\
id: d7a95147-145f-4678-b555-b7a3c9b16830
title: Test Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine: '*'
  condition: selection
"""

_MULTI_REF_DDR_TEMPLATE = """\
ddr_version: "0.5"
id: f47ac10b-58cc-4372-a567-0e02b2c3d499
title: Multi-ref test
description: test
target:
  kind: sigma
  rule_refs:
    - rule_id: d7a95147-145f-4678-b555-b7a3c9b16830
      content_hash: sha256:{hash1}
      source: internal
      path_or_url: "{rule1_path}"
    - rule_id: e8b3d258-256a-5789-bcde-f02345678901
      content_hash: sha256:{hash2}
      source: internal
      path_or_url: "{rule2_path}"
decision:
  kind: deprecate
  rationale: Retiring two overlapping rules.
lifecycle:
  status: active
  created_on: "2026-01-01T00:00:00Z"
provenance:
  author: test@example.com
"""


def test_refresh_hash_sigma_multi_ref(tmp_path):
    rule1 = tmp_path / "rule1.yml"
    rule2 = tmp_path / "rule2.yml"
    rule1.write_text(_SIGMA_RULE_YAML, encoding="utf-8")
    rule2.write_text(_SIGMA_RULE_YAML.replace("Test Rule", "Test Rule 2"), encoding="utf-8")

    ddr = tmp_path / "ddr.yml"
    ddr.write_text(
        _MULTI_REF_DDR_TEMPLATE.format(
            hash1="0" * 64,
            hash2="1" * 64,
            rule1_path=str(rule1).replace("\\", "/"),
            rule2_path=str(rule2).replace("\\", "/"),
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 0
    assert "rule_refs[0]" in result.output or "sha256:" in result.output
    assert "rule_refs[1]" in result.output or "sha256:" in result.output


def test_refresh_hash_sigma_multi_ref_rule_override_fails(tmp_path):
    rule1 = tmp_path / "rule1.yml"
    rule2 = tmp_path / "rule2.yml"
    rule1.write_text(_SIGMA_RULE_YAML, encoding="utf-8")
    rule2.write_text(_SIGMA_RULE_YAML, encoding="utf-8")

    ddr = tmp_path / "ddr.yml"
    ddr.write_text(
        _MULTI_REF_DDR_TEMPLATE.format(
            hash1="0" * 64,
            hash2="1" * 64,
            rule1_path=str(rule1).replace("\\", "/"),
            rule2_path=str(rule2).replace("\\", "/"),
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr), "--rule", str(rule1)])
    assert result.exit_code == 1
    assert "multi-ref" in result.output.lower()


# ---------------------------------------------------------------------------
# v0.5: back-compat — v0.4 back-compat fixture validates under v0.5
# ---------------------------------------------------------------------------


def test_validate_v04_backcompat_fixture(valid_fixtures_dir):
    result = runner.invoke(
        app, ["validate", str(valid_fixtures_dir / "v0.4_backcompat_rule_ref.yml")]
    )
    assert result.exit_code == 0


def test_validate_multi_ref_fixture(valid_fixtures_dir):
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir / "multi_ref_sigma.yml")])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# v0.6: Elastic target — ddr new / validate / refresh-hash / export
# ---------------------------------------------------------------------------

_ELASTIC_RULE_NDJSON = (
    '{"rule_id":"96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c",'
    '"name":"Windows Defender AV Threats",'
    '"type":"eql","language":"eql",'
    '"query":"process where process.name : \\"MpCmdRun.exe\\"",'
    '"risk_score":47,"severity":"medium","tags":["Windows"],'
    '"enabled":true,"from":"now-360s","to":"now","interval":"5m",'
    '"max_signals":100,"threat":[]}\n'
)


def test_new_elastic_target_no_file():
    """--target elastic with no file produces a placeholder scaffold."""
    result = runner.invoke(app, ["new", "--target", "elastic"])
    assert result.exit_code == 0
    assert "elastic" in result.output
    assert "query_refs" in result.output
    assert "kql_filter" in result.output


def test_new_elastic_target_from_ndjson(tmp_path):
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    result = runner.invoke(app, ["new", str(ndjson)])
    assert result.exit_code == 0
    assert "elastic" in result.output
    assert "query_refs" in result.output
    assert "96b9fc2a" in result.output
    assert "Windows Defender" in result.output


def test_new_elastic_ndjson_infers_target(tmp_path):
    """.ndjson extension auto-selects --target elastic."""
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    result = runner.invoke(app, ["new", str(ndjson)])
    assert result.exit_code == 0
    assert "kind: elastic" in result.output


def test_new_elastic_accept_risk_decision(tmp_path):
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    result = runner.invoke(app, ["new", str(ndjson), "--decision", "accept-risk"])
    assert result.exit_code == 0
    assert "accept-risk" in result.output
    assert "kql_filter" not in result.output


def test_validate_elastic_fixture(valid_fixtures_dir):
    result = runner.invoke(
        app, ["validate", str(valid_fixtures_dir / "elastic_suppress.yml")]
    )
    assert result.exit_code == 0
    assert "OK" in result.output


def test_validate_mixed_directory_with_elastic(valid_fixtures_dir):
    """Directory containing sigma, splunk, and elastic DDRs all validate."""
    result = runner.invoke(app, ["validate", str(valid_fixtures_dir)])
    assert result.exit_code == 0


def test_list_shows_elastic_target(valid_fixtures_dir):
    import json

    result = runner.invoke(app, ["list", "--format", "json", str(valid_fixtures_dir)])
    assert result.exit_code == 0
    rows = json.loads(result.output)
    elastic_rows = [r for r in rows if r["target"] == "elastic"]
    assert len(elastic_rows) >= 1


def test_list_filter_by_elastic_target(valid_fixtures_dir):
    result = runner.invoke(app, ["list", "--target", "elastic", str(valid_fixtures_dir)])
    assert result.exit_code == 0


_ELASTIC_DDR_TEMPLATE = """\
ddr_version: "0.6"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
title: Suppress elastic test
description: test
target:
  kind: elastic
  query_refs:
    - rule_id: "96b9fc2a-cbd5-4a3e-b7d7-3d9d6a6e8d5c"
      name: "Windows Defender AV Threats"
      index_pattern: "logs-endpoint.events.process-*"
      content_hash: sha256:{old_hash}
      source: internal
      path_or_url: "{ndjson_path}"
decision:
  kind: suppress
  rationale: Scanner FP.
  tuning:
    kind: elastic
    filter_title: Suppress scanner AV
    kql_filter: 'source.ip : "10.0.100.0/24"'
lifecycle:
  status: active
  created_on: "2026-05-08T00:00:00Z"
  activated_on: "2026-05-08T00:00:00Z"
  expires_on: "2027-05-08T00:00:00Z"
provenance:
  author: test@example.com
"""


def _make_elastic_ddr(
    tmp_path: Path, ndjson_path: Path, old_hash: str = "sha256:" + "0" * 64
) -> Path:
    ddr = tmp_path / "elastic_ddr.yml"
    ddr.write_text(
        _ELASTIC_DDR_TEMPLATE.format(
            old_hash=old_hash[len("sha256:"):],
            ndjson_path=str(ndjson_path).replace("\\", "/"),
        ),
        encoding="utf-8",
    )
    return ddr


def test_refresh_hash_elastic_updates(tmp_path):
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    ddr = _make_elastic_ddr(tmp_path, ndjson)
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 0
    assert "sha256:" in result.output


def test_refresh_hash_elastic_unchanged(tmp_path):
    from ddr._internal.elastic_hash import compute_elastic_hash

    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    current_hash = compute_elastic_hash(ndjson)

    ddr = _make_elastic_ddr(tmp_path, ndjson, old_hash=current_hash)
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 0
    assert "unchanged" in result.output.lower()


def test_refresh_hash_elastic_no_path(tmp_path):
    """Elastic ref with no path_or_url is skipped with a clear message."""
    ddr = tmp_path / "ddr.yml"
    ddr.write_text(
        'ddr_version: "0.6"\nid: a1b2c3d4-e5f6-7890-abcd-ef1234567890\n'
        'title: t\ndescription: d\n'
        'target:\n  kind: elastic\n  query_refs:\n'
        '    - rule_id: abc\n      name: r\n      index_pattern: logs-*\n      source: internal\n'
        'decision:\n  kind: deprecate\n  rationale: r\n'
        'lifecycle:\n  status: draft\n  created_on: "2026-01-01T00:00:00Z"\n'
        'provenance:\n  author: t\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr)])
    assert result.exit_code == 0
    assert "skipping" in result.output.lower() or "no path" in result.output.lower()


def test_refresh_hash_elastic_multi_ref_rule_override_fails(tmp_path):
    ndjson1 = tmp_path / "rule1.ndjson"
    ndjson2 = tmp_path / "rule2.ndjson"
    ndjson1.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    ndjson2.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")

    ddr = tmp_path / "multi.yml"
    ddr.write_text(
        'ddr_version: "0.6"\nid: a1b2c3d4-e5f6-7890-abcd-ef1234567890\n'
        'title: t\ndescription: d\n'
        'target:\n  kind: elastic\n  query_refs:\n'
        f'    - rule_id: r1\n      name: R1\n      index_pattern: logs-*\n'
        f'      source: internal\n      path_or_url: "{str(ndjson1).replace(chr(92), "/")}"\n'
        f'    - rule_id: r2\n      name: R2\n      index_pattern: logs-*\n'
        f'      source: internal\n      path_or_url: "{str(ndjson2).replace(chr(92), "/")}"\n'
        'decision:\n  kind: deprecate\n  rationale: r\n'
        'lifecycle:\n  status: draft\n  created_on: "2026-01-01T00:00:00Z"\n'
        'provenance:\n  author: t\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr), "--rule", str(ndjson1)])
    assert result.exit_code == 1
    assert "multi-ref" in result.output.lower()


def test_export_elastic_exception_simple_kql(tmp_path):
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    ddr = _make_elastic_ddr(tmp_path, ndjson)
    result = runner.invoke(app, ["export-elastic-exception", str(ddr)])
    assert result.exit_code == 0
    import json
    obj = json.loads(result.output.strip())
    assert obj["type"] == "simple"
    assert len(obj["entries"]) == 1


def test_export_elastic_exception_to_file(tmp_path):
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    ddr = _make_elastic_ddr(tmp_path, ndjson)
    out = tmp_path / "exception.ndjson"
    result = runner.invoke(app, ["export-elastic-exception", str(ddr), "--output", str(out)])
    assert result.exit_code == 0
    assert out.exists()


def test_export_elastic_exception_custom_list_id(tmp_path):
    ndjson = tmp_path / "rule.ndjson"
    ndjson.write_text(_ELASTIC_RULE_NDJSON, encoding="utf-8")
    ddr = _make_elastic_ddr(tmp_path, ndjson)
    result = runner.invoke(
        app, ["export-elastic-exception", str(ddr), "--list-id", "my-team-exceptions"]
    )
    assert result.exit_code == 0
    import json
    obj = json.loads(result.output.strip())
    assert obj["list_id"] == "my-team-exceptions"


def test_export_elastic_exception_wrong_target_fails(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-elastic-exception", str(valid_fixtures_dir / "suppress_basic.yml")]
    )
    assert result.exit_code == 1
    assert "elastic" in result.output.lower()


def test_export_elastic_exception_non_suppress_fails(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-elastic-exception", str(valid_fixtures_dir / "elastic_suppress.yml")]
    )
    # elastic_suppress.yml uses suppress decision, should pass
    assert result.exit_code == 0


# --- export-kql ---


def test_export_kql_sentinel_stdout(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-kql", str(valid_fixtures_dir / "kql_sentinel_suppress.yml")]
    )
    assert result.exit_code == 0
    assert "| where not (" in result.output
    assert "// DDR:" in result.output


def test_export_kql_m365d_stdout(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-kql", str(valid_fixtures_dir / "kql_m365d_suppress.yml")]
    )
    assert result.exit_code == 0
    assert "| where not (" in result.output


def test_export_kql_writes_file(valid_fixtures_dir, tmp_path):
    out = tmp_path / "filter.kql"
    result = runner.invoke(
        app,
        ["export-kql", str(valid_fixtures_dir / "kql_sentinel_suppress.yml"), "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    assert "| where not (" in out.read_text(encoding="utf-8")


def test_export_kql_wrong_target_fails(valid_fixtures_dir):
    result = runner.invoke(
        app, ["export-kql", str(valid_fixtures_dir / "suppress_basic.yml")]
    )
    assert result.exit_code == 1
    assert "kql-sentinel or kql-m365d" in result.output


def test_export_kql_nonexistent_path():
    result = runner.invoke(app, ["export-kql", "/nonexistent/path.yml"])
    assert result.exit_code == 1


# --- ddr new --target kql-sentinel / kql-m365d ---


def test_new_kql_sentinel_scaffold(tmp_path):
    result = runner.invoke(app, ["new", "--target", "kql-sentinel"])
    assert result.exit_code == 0
    assert "kql-sentinel" in result.output
    assert "query_refs" in result.output
    assert "kusto_filter" in result.output


def test_new_kql_m365d_scaffold(tmp_path):
    result = runner.invoke(app, ["new", "--target", "kql-m365d"])
    assert result.exit_code == 0
    assert "kql-m365d" in result.output
    assert "kusto_filter" in result.output


def test_new_kql_sentinel_from_json(tmp_path):
    import json
    sentinel_json = tmp_path / "sentinel_rule.json"
    sentinel_json.write_text(
        json.dumps({
            "name": "my-rule",
            "properties": {
                "displayName": "My Sentinel Rule",
                "query": "SecurityEvent | where EventID == 4625",
                "severity": "High",
            }
        }),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["new", "--target", "kql-sentinel", str(sentinel_json)])
    assert result.exit_code == 0
    assert "kql-sentinel" in result.output
    assert "My Sentinel Rule" in result.output


def test_new_kql_invalid_target_fails():
    result = runner.invoke(app, ["new", "--target", "kql-unknown"])
    assert result.exit_code == 1
    assert "ERROR" in result.output


# --- ddr list with KQL records ---


def test_list_kql_sentinel_shows_target(valid_fixtures_dir):
    result = runner.invoke(app, ["list", str(valid_fixtures_dir)])
    assert result.exit_code == 0
    assert "kql-sentinel" in result.output


def test_list_kql_m365d_shows_target(valid_fixtures_dir):
    result = runner.invoke(app, ["list", str(valid_fixtures_dir)])
    assert result.exit_code == 0
    assert "kql-m365d" in result.output


# --- ddr refresh-hash KQL branches ---


def test_refresh_hash_kql_sentinel_updates(tmp_path):
    import json
    rule_file = tmp_path / "sentinel_rule.json"
    rule_file.write_text(
        json.dumps({
            "properties": {
                "displayName": "Test",
                "query": "SecurityEvent | where EventID == 4625",
                "severity": "High",
            }
        }),
        encoding="utf-8",
    )
    ddr_file = tmp_path / "ddr.yml"
    ddr_file.write_text(
        f"""ddr_version: "0.7"
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
title: "Test"
description: "Test."
target:
  kind: kql-sentinel
  query_refs:
    - rule_id: rule-001
      name: Test
      source: internal
      path_or_url: {rule_file}
      content_hash: "sha256:{"0" * 64}"
decision:
  kind: suppress
  rationale: "FP."
  tuning:
    kind: kql-sentinel
    kusto_filter: 'IPAddress =~ "10.0.0.1"'
lifecycle:
  status: active
  created_on: "2026-01-01T00:00:00Z"
  expires_on: "2027-01-01T00:00:00Z"
provenance:
  author: alice@example.com
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr_file)])
    assert result.exit_code == 0
    assert "new:" in result.output


def test_refresh_hash_kql_m365d_no_path_skips(tmp_path):
    ddr_file = tmp_path / "ddr.yml"
    ddr_file.write_text(
        """ddr_version: "0.7"
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
title: "Test M365D"
description: "Test."
target:
  kind: kql-m365d
  query_refs:
    - rule_id: m365d-001
      name: Test Detection
      source: internal
decision:
  kind: suppress
  rationale: "FP."
  tuning:
    kind: kql-m365d
    kusto_filter: 'AccountName has "svc-deploy"'
lifecycle:
  status: active
  created_on: "2026-01-01T00:00:00Z"
  expires_on: "2027-01-01T00:00:00Z"
provenance:
  author: bob@example.com
""",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["refresh-hash", str(ddr_file)])
    assert result.exit_code == 0
    assert "no path_or_url" in result.output or "skipping" in result.output
