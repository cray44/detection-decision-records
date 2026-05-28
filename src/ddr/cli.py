"""DDR command-line interface."""

from __future__ import annotations

import io
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import typer
from pydantic import ValidationError
from ruamel.yaml import YAML

from ddr._internal.hash_utils import compute_content_hash
from ddr.exporters.sigma_filter import export_to_yaml
from ddr.models.record import (
    DDRRecord,
    ElasticTarget,
    KqlM365DTarget,
    KqlSentinelTarget,
    LifecycleStatus,
    SigmaTarget,
    SplunkTarget,
    SuppressDecision,
)

app = typer.Typer(
    name="ddr",
    help="Detection Decision Records — governance for detection-as-code.",
    no_args_is_help=True,
)

# Patterns used by --strict free-text lint (heuristic, warn-only).
# Bare IPs are not flagged — only IPs in log-line context (key=ip) or other log indicators.
_LOG_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"  # ISO timestamps
    r"|(\w+=(?:\d{1,3}\.){3}\d{1,3}\b)"  # key=ip (src_ip=1.2.3.4)
    r"|(\w+=\w+\|\w+=\w+)"  # key=value pipe logs
)

# Single source of truth for the DDR spec version emitted by all `ddr new` scaffolds.
# Bump this on every minor release. Never hardcode version strings inside the scaffold dicts.
LATEST_DDR_VERSION: str = "0.7"


def _safe_yaml() -> YAML:
    return YAML(typ="safe")


def _writer_yaml() -> YAML:
    y = YAML()
    y.default_flow_style = False
    y.width = 4096
    return y


def _load_record(path: Path) -> DDRRecord:
    loader = _safe_yaml()
    with open(path, encoding="utf-8") as fh:
        data = loader.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping, got {type(data).__name__}")
    return DDRRecord.model_validate(data)


def _iter_ddr_files(path: Path):
    if path.is_dir():
        yield from sorted(path.rglob("*.yml"))
        yield from sorted(path.rglob("*.yaml"))
    else:
        yield path


def _strip_none(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(v) for v in obj]
    return obj


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_path_or_url(
    source: Path | None,
    output: Path | None,
    override: str | None,
) -> str | None:
    """Return the best path_or_url value.

    If override is given, return it verbatim (metadata only).
    Prefer relative path under CWD or --output parent dir.
    Fall back to absolute (caller emits NOTE).
    """
    if override is not None:
        return override
    if source is None:
        return None

    try:
        cwd = Path.cwd().resolve()
        return str(source.resolve().relative_to(cwd))
    except ValueError:
        pass

    if output is not None:
        try:
            out_parent = output.resolve().parent
            return str(source.resolve().relative_to(out_parent))
        except ValueError:
            pass

    return str(source)


@app.command("new")
def cmd_new(
    sigma_rule: Path | None = typer.Argument(
        default=None,
        help="Path to Sigma rule YAML (--target sigma) or savedsearches.conf (--target splunk).",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write new DDR here (default: stdout)."
    ),
    decision_kind: str = typer.Option(
        "suppress", "--decision", "-d", help="Decision type: suppress | accept-risk | deprecate."
    ),
    target_kind: str = typer.Option(
        "sigma",
        "--target",
        "-t",
        help="Target kind: sigma | splunk | elastic | kql-sentinel | kql-m365d.",
    ),
    splunk_name: str | None = typer.Option(
        None, "--name", help="Splunk savedsearch stanza name (--target splunk)."
    ),
    splunk_app: str = typer.Option(
        "search",
        "--app",
        help="Splunk app context (default: search; overridden by path inference).",
    ),
    source_url: str | None = typer.Option(
        None,
        "--source-url",
        help="Override path_or_url (metadata only; hash still from positional source).",
    ),
) -> None:
    """Scaffold a DDR from a Sigma rule, savedsearches.conf, Elastic rule NDJSON, or KQL JSON."""
    # Infer --target elastic when a .ndjson file is provided
    if sigma_rule is not None and sigma_rule.suffix.lower() == ".ndjson":
        target_kind = "elastic"

    _VALID_TARGETS = ("sigma", "splunk", "elastic", "kql-sentinel", "kql-m365d")
    if target_kind not in _VALID_TARGETS:
        typer.echo(
            "ERROR: --target must be sigma | splunk | elastic | kql-sentinel | kql-m365d",
            err=True,
        )
        raise typer.Exit(1)

    if decision_kind not in ("suppress", "accept-risk", "deprecate"):
        typer.echo("ERROR: --decision must be suppress | accept-risk | deprecate", err=True)
        raise typer.Exit(1)

    if target_kind == "elastic":
        _cmd_new_elastic(
            ndjson_path=sigma_rule,
            output=output,
            decision_kind=decision_kind,
            source_url=source_url,
        )
        return

    if target_kind in ("kql-sentinel", "kql-m365d"):
        _cmd_new_kql(
            json_path=sigma_rule,
            output=output,
            decision_kind=decision_kind,
            target_kind=target_kind,
            source_url=source_url,
        )
        return

    if target_kind == "splunk":
        if sigma_rule is not None:
            _cmd_new_splunk_from_conf(
                conf_path=sigma_rule,
                output=output,
                decision_kind=decision_kind,
                splunk_name=splunk_name,
                splunk_app=splunk_app,
                source_url=source_url,
            )
        else:
            _cmd_new_splunk(
                output=output,
                decision_kind=decision_kind,
                splunk_name=splunk_name,
                splunk_app=splunk_app,
            )
        return

    # --- sigma target ---
    if sigma_rule is None:
        typer.echo("ERROR: a Sigma rule path is required for --target sigma", err=True)
        raise typer.Exit(1)

    if not sigma_rule.exists():
        typer.echo(f"ERROR: {sigma_rule} not found", err=True)
        raise typer.Exit(1)

    loader = _safe_yaml()
    with open(sigma_rule, encoding="utf-8") as fh:
        rule_data = loader.load(fh)

    if not isinstance(rule_data, dict):
        typer.echo("ERROR: Sigma rule is not a YAML mapping", err=True)
        raise typer.Exit(1)

    rule_id = str(rule_data.get("id", "TODO-FILL-IN-RULE-UUID"))
    rule_title = rule_data.get("title", "")
    ls = rule_data.get("logsource", {})
    content_hash = compute_content_hash(sigma_rule)

    path_or_url_val = _compute_path_or_url(sigma_rule, output, source_url)
    if path_or_url_val and not source_url and Path(path_or_url_val).is_absolute():
        typer.echo(
            "NOTE: path_or_url is absolute. Consider --source-url for portability.",
            err=True,
        )

    scaffold = _strip_none(
        {
            "ddr_version": LATEST_DDR_VERSION,
            "id": str(uuid4()),
            "title": f"Suppress: {rule_title}" if decision_kind == "suppress" else rule_title,
            "description": "",
            "target": {
                "kind": "sigma",
                "rule_refs": [
                    {
                        "rule_id": rule_id,
                        "content_hash": content_hash,
                        "source": "internal",
                        "path_or_url": path_or_url_val,
                    }
                ],
            },
            "decision": _build_sigma_decision_scaffold(decision_kind, dict(ls)),
            "lifecycle": {
                "status": "draft",
                "created_on": _now_utc(),
            },
            "provenance": {
                "author": "",
                "ticket_refs": [],
            },
        }
    )

    _write_scaffold(scaffold, output)


def _cmd_new_elastic(
    ndjson_path: Path | None,
    output: Path | None,
    decision_kind: str,
    source_url: str | None,
) -> None:
    """Scaffold a DDR for an Elastic Security detection rule."""
    rule_id = "TODO-FILL-IN-ELASTIC-RULE-UUID"
    rule_name = "TODO: rule name"
    index_pattern = "TODO: e.g. logs-endpoint.events.process-*"

    if ndjson_path is not None:
        if not ndjson_path.exists():
            typer.echo(f"ERROR: {ndjson_path} not found", err=True)
            raise typer.Exit(1)

        try:
            import json as _json

            text = ndjson_path.read_text(encoding="utf-8-sig")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                rule_obj = obj.get("rule", obj)
                rule_id = rule_obj.get("rule_id") or rule_obj.get("id") or rule_id
                rule_name = rule_obj.get("name") or rule_name
                break
        except Exception:
            pass  # fall back to placeholders

    path_or_url_val = _compute_path_or_url(ndjson_path, output, source_url)
    if path_or_url_val and not source_url and Path(path_or_url_val).is_absolute():
        typer.echo(
            "NOTE: path_or_url is absolute. Consider --source-url for portability.",
            err=True,
        )

    scaffold = _strip_none(
        {
            "ddr_version": LATEST_DDR_VERSION,
            "id": str(uuid4()),
            "title": f"Suppress: {rule_name}" if decision_kind == "suppress" else rule_name,
            "description": "TODO: describe this detection and why tuning is needed.",
            "target": {
                "kind": "elastic",
                "query_refs": [
                    {
                        "rule_id": rule_id,
                        "name": rule_name,
                        "index_pattern": index_pattern,
                        "source": "internal",
                        "path_or_url": path_or_url_val,
                    }
                ],
            },
            "decision": _build_elastic_decision_scaffold(decision_kind),
            "lifecycle": {
                "status": "draft",
                "created_on": _now_utc(),
            },
            "provenance": {
                "author": "",
                "ticket_refs": [],
            },
        }
    )

    _write_scaffold(scaffold, output)


def _cmd_new_kql(
    json_path: Path | None,
    output: Path | None,
    decision_kind: str,
    target_kind: str,
) -> None:
    """Scaffold a DDR for a Sentinel or M365D KQL-based detection."""
    rule_id = "TODO-FILL-IN-RULE-ID"
    rule_name = "TODO: rule name"
    path_or_url_val: str | None = None

    if json_path is not None:
        if not json_path.exists():
            typer.echo(f"ERROR: {json_path} not found", err=True)
            raise typer.Exit(1)

        try:
            text = json_path.read_text(encoding="utf-8-sig")
            obj = json.loads(text)
            if isinstance(obj, list) and obj:
                obj = obj[0]
            if isinstance(obj, dict):
                # ARM envelope
                body = obj.get("properties", obj)
                rule_id = body.get("displayName") or obj.get("name") or obj.get("id") or rule_id
                rule_name = body.get("displayName") or obj.get("name") or rule_name
                # M365D shape
                rule_id = body.get("id") or body.get("displayName") or rule_id
                rule_name = body.get("displayName") or body.get("name") or rule_name
        except Exception:
            pass  # fall back to placeholders

        path_or_url_val = str(json_path)

    optional_field = "workspace" if target_kind == "kql-sentinel" else "table"
    scaffold = _strip_none(
        {
            "ddr_version": LATEST_DDR_VERSION,
            "id": str(uuid4()),
            "title": f"Suppress: {rule_name}" if decision_kind == "suppress" else rule_name,
            "description": "TODO: describe this detection and why tuning is needed.",
            "target": {
                "kind": target_kind,
                "query_refs": [
                    {
                        "rule_id": rule_id,
                        "name": rule_name,
                        optional_field: None,
                        "source": "internal",
                        "path_or_url": path_or_url_val,
                    }
                ],
            },
            "decision": _build_kql_decision_scaffold(decision_kind, target_kind),
            "lifecycle": {
                "status": "draft",
                "created_on": _now_utc(),
            },
            "provenance": {
                "author": "",
                "ticket_refs": [],
            },
        }
    )

    _write_scaffold(scaffold, output)


def _build_kql_decision_scaffold(kind: str, target_kind: str) -> dict:
    if kind == "suppress":
        return {
            "kind": "suppress",
            "rationale": "TODO: explain why this is an acceptable false positive",
            "tuning": {
                "kind": target_kind,
                "filter_title": "TODO: descriptive filter name",
                "kusto_filter": (
                    "TODO: Kusto WHERE clause, e.g. InitiatingProcessParentFileName"
                    ' =~ "msiexec.exe"'
                ),
            },
        }
    if kind == "accept-risk":
        return {
            "kind": "accept-risk",
            "rationale": "TODO: explain why you are accepting this risk",
        }
    return {
        "kind": "deprecate",
        "rationale": "TODO: explain why this rule is being deprecated",
    }


def _build_elastic_decision_scaffold(kind: str) -> dict:
    if kind == "suppress":
        return {
            "kind": "suppress",
            "rationale": "TODO: explain why this is an acceptable false positive",
            "tuning": {
                "kind": "elastic",
                "filter_title": "TODO: descriptive filter name",
                "kql_filter": 'TODO: KQL filter clause, e.g. source.ip : "10.0.100.0/24"',
            },
        }
    if kind == "accept-risk":
        return {
            "kind": "accept-risk",
            "rationale": "TODO: explain why you are accepting this risk",
        }
    return {
        "kind": "deprecate",
        "rationale": "TODO: explain why this rule is being deprecated",
    }


def _cmd_new_splunk(
    output: Path | None,
    decision_kind: str,
    splunk_name: str | None,
    splunk_app: str,
) -> None:
    """Minimal scaffold without conf parsing (v0.3 behavior — no query_hash)."""
    if not splunk_name:
        typer.echo(
            "ERROR: --name <stanza> is required for --target splunk",
            err=True,
        )
        raise typer.Exit(1)

    scaffold = _strip_none(
        {
            "ddr_version": LATEST_DDR_VERSION,
            "id": str(uuid4()),
            "title": f"TODO: title for {splunk_name}",
            "description": "TODO: describe this detection and why tuning is needed.",
            "target": {
                "kind": "splunk",
                "query_refs": [
                    {
                        "name": splunk_name,
                        "app": splunk_app,
                    }
                ],
            },
            "decision": _build_splunk_decision_scaffold(decision_kind),
            "lifecycle": {
                "status": "draft",
                "created_on": _now_utc(),
            },
            "provenance": {
                "author": "",
                "ticket_refs": [],
            },
        }
    )

    _write_scaffold(scaffold, output)


def _cmd_new_splunk_from_conf(
    conf_path: Path,
    output: Path | None,
    decision_kind: str,
    splunk_name: str | None,
    splunk_app: str,
    source_url: str | None,
) -> None:
    """Scaffold from a real savedsearches.conf — computes query_hash, infers app."""
    from ddr._internal.splunk_conf import (
        compute_query_hash,
        extract_stanza,
        infer_app_from_path,
        parse_savedsearches_conf,
    )

    if not conf_path.exists():
        typer.echo(f"ERROR: {conf_path} not found", err=True)
        raise typer.Exit(1)

    try:
        conf = parse_savedsearches_conf(conf_path)
    except Exception as exc:
        typer.echo(f"ERROR: failed to parse {conf_path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not conf:
        typer.echo(f"ERROR: no stanzas found in {conf_path}", err=True)
        raise typer.Exit(1)

    # Stanza selection
    if splunk_name:
        try:
            stanza = extract_stanza(conf, splunk_name)
        except KeyError as exc:
            typer.echo(f"ERROR: {exc}", err=True)
            raise typer.Exit(1) from exc
        name = splunk_name
    else:
        stanzas = list(conf.keys())
        if len(stanzas) == 1:
            name = stanzas[0]
            stanza = conf[name]
        else:
            typer.echo(
                f"ERROR: {conf_path} contains {len(stanzas)} stanzas — use --name to select one:",
                err=True,
            )
            for s in stanzas:
                typer.echo(f"  {s!r}", err=True)
            raise typer.Exit(1)

    if stanza.get("disabled") in ("1", "true"):
        typer.echo(f"WARN: stanza {name!r} has disabled=1 — savedsearch is not scheduled", err=True)

    search = stanza.get("search", "").strip()
    if not search:
        typer.echo(f"ERROR: stanza {name!r} has no 'search' key or empty value", err=True)
        raise typer.Exit(1)

    try:
        query_hash = compute_query_hash(search)
    except ValueError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    # App inference: prefer inferred app over the "search" default; --app always wins
    inferred_app = infer_app_from_path(conf_path)
    app = inferred_app if splunk_app == "search" and inferred_app else splunk_app

    path_or_url_val = _compute_path_or_url(conf_path, output, source_url)
    if path_or_url_val and not source_url and Path(path_or_url_val).is_absolute():
        typer.echo(
            "NOTE: path_or_url is absolute. Consider --source-url for portability.",
            err=True,
        )

    scaffold = _strip_none(
        {
            "ddr_version": LATEST_DDR_VERSION,
            "id": str(uuid4()),
            "title": f"TODO: title for {name}",
            "description": "TODO: describe this detection and why tuning is needed.",
            "target": {
                "kind": "splunk",
                "query_refs": [
                    {
                        "name": name,
                        "app": app,
                        "query_hash": query_hash,
                        "path_or_url": path_or_url_val,
                    }
                ],
            },
            "decision": _build_splunk_decision_scaffold(decision_kind),
            "lifecycle": {
                "status": "draft",
                "created_on": _now_utc(),
            },
            "provenance": {
                "author": "",
                "ticket_refs": [],
            },
        }
    )

    _write_scaffold(scaffold, output)


def _write_scaffold(scaffold: dict, output: Path | None) -> None:
    writer = _writer_yaml()
    buf = io.StringIO()
    writer.dump(scaffold, buf)
    result = buf.getvalue()

    if output:
        output.write_text(result, encoding="utf-8")
        typer.echo(f"Created {output}")
    else:
        typer.echo(result, nl=False)


def _build_sigma_decision_scaffold(kind: str, logsource: dict) -> dict:
    if kind == "suppress":
        return {
            "kind": "suppress",
            "rationale": "TODO: explain why this is an acceptable false positive",
            "tuning": {
                "kind": "sigma",
                "filter_title": "TODO: descriptive filter name",
                "logsource": logsource or {"category": "TODO", "product": "TODO"},
                "selections": {"known_fp": {"FieldName|contains": ["benign_value"]}},
                "condition": "not known_fp",
            },
        }
    if kind == "accept-risk":
        return {
            "kind": "accept-risk",
            "rationale": "TODO: explain why you are accepting this risk",
        }
    return {
        "kind": "deprecate",
        "rationale": "TODO: explain why this rule is being deprecated",
    }


def _build_splunk_decision_scaffold(kind: str) -> dict:
    if kind == "suppress":
        return {
            "kind": "suppress",
            "rationale": "TODO: explain why this is an acceptable false positive",
            "tuning": {
                "kind": "splunk",
                "filter_title": "TODO: descriptive filter name",
                "splunk_filter": (
                    "TODO: raw SPL filter clause (e.g. user=svc_* OR src_ip=10.0.0.0/8)"
                ),
            },
        }
    if kind == "accept-risk":
        return {
            "kind": "accept-risk",
            "rationale": "TODO: explain why you are accepting this risk",
        }
    return {
        "kind": "deprecate",
        "rationale": "TODO: explain why this rule is being deprecated",
    }


# Back-compat: keep old helper name so existing callers don't break
def _build_decision_scaffold(kind: str, logsource: dict) -> dict:
    return _build_sigma_decision_scaffold(kind, logsource)


@app.command("list")
def cmd_list(
    path: Path = typer.Argument(..., help="DDR file or directory."),
    status: str | None = typer.Option(
        None, "--status", help="Filter by lifecycle status: draft | active | retired."
    ),
    target: str | None = typer.Option(
        None, "--target", help="Filter by target.kind (e.g. sigma, splunk)."
    ),
    decision: str | None = typer.Option(
        None, "--decision", help="Filter by decision.kind (e.g. suppress, accept-risk, deprecate)."
    ),
    expired: bool = typer.Option(False, "--expired", help="Only show expired active records."),
    due: bool = typer.Option(False, "--due", help="Only show active records due for review."),
    fmt: str = typer.Option("table", "--format", help="Output format: table | json."),
) -> None:
    """Summarise DDRs in a directory (read-only, always exits 0)."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    now = datetime.now(UTC)
    rows: list[dict] = []

    for fp in _iter_ddr_files(path):
        try:
            loader = _safe_yaml()
            with open(fp, encoding="utf-8") as fh:
                raw = loader.load(fh)
            if not isinstance(raw, dict) or "ddr_version" not in raw:
                continue
            record = DDRRecord.model_validate(raw)
        except Exception:
            continue

        lc = record.lifecycle
        refs_count = (
            len(record.target.rule_refs)
            if isinstance(record.target, SigmaTarget)
            else len(record.target.query_refs)
        )

        row: dict[str, Any] = {
            "file": str(fp),
            "id": str(record.id),
            "title": record.title,
            "status": lc.status.value,
            "target": record.target.kind,
            "decision": record.decision.kind,
            "refs": refs_count,
            "expires_on": lc.expires_on.isoformat() if lc.expires_on else None,
        }

        # compute flags
        is_expired = False
        is_due = False
        if lc.status == LifecycleStatus.active and lc.expires_on:
            exp = lc.expires_on if lc.expires_on.tzinfo else lc.expires_on.replace(tzinfo=UTC)
            is_expired = exp < now
        if lc.status == LifecycleStatus.active and lc.review_cadence_days and lc.last_reviewed_on:
            rev = (
                lc.last_reviewed_on
                if lc.last_reviewed_on.tzinfo
                else lc.last_reviewed_on.replace(tzinfo=UTC)
            )
            is_due = rev + timedelta(days=lc.review_cadence_days) < now

        row["expired"] = is_expired
        row["due"] = is_due

        # apply filters
        if status and row["status"] != status:
            continue
        if target and row["target"] != target:
            continue
        if decision and row["decision"] != decision:
            continue
        if expired and not is_expired:
            continue
        if due and not is_due:
            continue

        rows.append(row)

    if fmt == "json":
        typer.echo(json.dumps(rows, indent=2))
        return

    if not rows:
        typer.echo("No DDR records found.")
        return

    col_w = {"status": 8, "target": 10, "decision": 12, "refs": 4, "id": 38, "title": 42}
    header = (
        f"{'STATUS':<{col_w['status']}}  "
        f"{'TARGET':<{col_w['target']}}  "
        f"{'DECISION':<{col_w['decision']}}  "
        f"{'REFS':<{col_w['refs']}}  "
        f"{'ID':<{col_w['id']}}  "
        f"TITLE"
    )
    typer.echo(header)
    typer.echo("-" * len(header))
    for row in rows:
        flags = ""
        if row["expired"]:
            flags += " [EXPIRED]"
        if row["due"]:
            flags += " [DUE]"
        title = (row["title"] or "")[:40] + flags
        typer.echo(
            f"{row['status']:<{col_w['status']}}  "
            f"{row['target']:<{col_w['target']}}  "
            f"{row['decision']:<{col_w['decision']}}  "
            f"{row['refs']:<{col_w['refs']}}  "
            f"{row['id']:<{col_w['id']}}  "
            f"{title}"
        )


@app.command("validate")
def cmd_validate(
    path: Path = typer.Argument(..., help="DDR file or directory."),
    strict: bool = typer.Option(
        False, "--strict", help="Enable free-text lints beyond schema validation."
    ),
) -> None:
    """Validate one record or every .yml/.yaml under a directory."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    files = list(_iter_ddr_files(path))
    if not files:
        typer.echo(f"No .yml/.yaml files found under {path}", err=True)
        raise typer.Exit(1)

    failed = 0
    checked = 0

    for fp in files:
        try:
            loader = _safe_yaml()
            with open(fp, encoding="utf-8") as fh:
                raw = loader.load(fh)
            if not isinstance(raw, dict) or "ddr_version" not in raw:
                continue  # not a DDR file, skip silently

            checked += 1
            record = DDRRecord.model_validate(raw)
            typer.echo(f"OK     {fp}")

            if strict:
                _strict_lint(fp, record)
                _strict_splunk_drift_check(fp, record)
                _strict_elastic_drift_check(fp, record)
                _strict_sentinel_drift_check(fp, record)
                _strict_m365d_drift_check(fp, record)

        except ValidationError as exc:
            failed += 1
            typer.echo(f"FAIL   {fp}")
            for err in exc.errors():
                loc = ".".join(str(x) for x in err["loc"])
                typer.echo(f"       - {loc}: {err['msg']}")
        except Exception as exc:
            failed += 1
            typer.echo(f"FAIL   {fp}")
            typer.echo(f"       - {exc}")

    if checked == 0:
        typer.echo("No DDR records found (files missing ddr_version key).", err=True)
        raise typer.Exit(1)

    if failed:
        raise typer.Exit(1)


def _strict_lint(fp: Path, record: DDRRecord) -> None:
    texts = [record.description or ""]
    if hasattr(record.decision, "rationale"):
        texts.append(record.decision.rationale or "")

    for text in texts:
        if _LOG_LINE_RE.search(text):
            typer.echo(
                f"  WARN  {fp}: description/rationale may contain raw log data"
                " (use evidence.ref instead)",
                err=True,
            )
            break

    _query_ref_targets = (SplunkTarget, ElasticTarget, KqlSentinelTarget, KqlM365DTarget)
    refs_count = (
        len(record.target.rule_refs)
        if isinstance(record.target, SigmaTarget)
        else len(record.target.query_refs)
        if isinstance(record.target, _query_ref_targets)
        else 0
    )
    if refs_count > 10:
        typer.echo(
            f"  WARN  {fp}: record has {refs_count} refs — consider splitting for clarity",
            err=True,
        )


def _strict_splunk_drift_check(fp: Path, record: DDRRecord) -> None:
    """Warn if query_hash in a Splunk-target DDR doesn't match the local conf."""
    if not isinstance(record.target, SplunkTarget):
        return

    for idx, qref in enumerate(record.target.query_refs):
        ref_label = f"query_refs[{idx}]"
        if not qref.query_hash or not qref.path_or_url:
            continue
        if qref.path_or_url.startswith(("http://", "https://")):
            typer.echo(
                f"  NOTE  {fp} {ref_label}: query_hash drift cannot be verified"
                " for remote path_or_url",
                err=True,
            )
            continue

        conf_path = Path(qref.path_or_url)
        if not conf_path.is_absolute():
            conf_path = fp.parent / conf_path
        if not conf_path.exists():
            continue

        try:
            from ddr._internal.splunk_conf import (
                compute_query_hash,
                extract_stanza,
                parse_savedsearches_conf,
            )

            conf = parse_savedsearches_conf(conf_path)
            stanza = extract_stanza(conf, qref.name)
            search = stanza.get("search", "").strip()
            if not search:
                continue
            current_hash = compute_query_hash(search)
            if current_hash != qref.query_hash:
                typer.echo(
                    f"  WARN  {fp} {ref_label}: query_hash drift"
                    f" — run 'ddr refresh-hash {fp}' to update",
                    err=True,
                )
        except Exception:
            pass


def _strict_elastic_drift_check(fp: Path, record: DDRRecord) -> None:
    """Warn if content_hash in an Elastic-target DDR doesn't match the local NDJSON."""
    if not isinstance(record.target, ElasticTarget):
        return

    for idx, qref in enumerate(record.target.query_refs):
        ref_label = f"query_refs[{idx}]"
        if not qref.content_hash or not qref.path_or_url:
            continue
        if qref.path_or_url.startswith(("http://", "https://")):
            typer.echo(
                f"  NOTE  {fp} {ref_label}: content_hash drift cannot be verified"
                " for remote path_or_url",
                err=True,
            )
            continue

        ndjson_path = Path(qref.path_or_url)
        if not ndjson_path.is_absolute():
            ndjson_path = fp.parent / ndjson_path
        if not ndjson_path.exists():
            continue

        try:
            from ddr._internal.elastic_hash import compute_elastic_hash

            current_hash = compute_elastic_hash(ndjson_path)
            if current_hash != qref.content_hash:
                typer.echo(
                    f"  WARN  {fp} {ref_label}: content_hash drift"
                    f" — run 'ddr refresh-hash {fp}' to update",
                    err=True,
                )
        except Exception:
            pass


def _strict_sentinel_drift_check(fp: Path, record: DDRRecord) -> None:
    if not isinstance(record.target, KqlSentinelTarget):
        return

    for idx, qref in enumerate(record.target.query_refs):
        ref_label = f"query_refs[{idx}]"
        if not qref.content_hash or not qref.path_or_url:
            continue
        if qref.path_or_url.startswith(("http://", "https://")):
            typer.echo(
                f"  NOTE  {fp} {ref_label}: content_hash drift cannot be verified"
                " for remote path_or_url",
                err=True,
            )
            continue

        json_path = Path(qref.path_or_url)
        if not json_path.is_absolute():
            json_path = fp.parent / json_path
        if not json_path.exists():
            continue

        try:
            from ddr._internal.sentinel_hash import compute_sentinel_hash

            current_hash = compute_sentinel_hash(json_path)
            if current_hash != qref.content_hash:
                typer.echo(
                    f"  WARN  {fp} {ref_label}: content_hash drift"
                    f" — run 'ddr refresh-hash {fp}' to update",
                    err=True,
                )
        except Exception:
            pass


def _strict_m365d_drift_check(fp: Path, record: DDRRecord) -> None:
    if not isinstance(record.target, KqlM365DTarget):
        return

    for idx, qref in enumerate(record.target.query_refs):
        ref_label = f"query_refs[{idx}]"
        if not qref.content_hash or not qref.path_or_url:
            continue
        if qref.path_or_url.startswith(("http://", "https://")):
            typer.echo(
                f"  NOTE  {fp} {ref_label}: content_hash drift cannot be verified"
                " for remote path_or_url",
                err=True,
            )
            continue

        json_path = Path(qref.path_or_url)
        if not json_path.is_absolute():
            json_path = fp.parent / json_path
        if not json_path.exists():
            continue

        try:
            from ddr._internal.m365d_hash import compute_m365d_hash

            current_hash = compute_m365d_hash(json_path)
            if current_hash != qref.content_hash:
                typer.echo(
                    f"  WARN  {fp} {ref_label}: content_hash drift"
                    f" — run 'ddr refresh-hash {fp}' to update",
                    err=True,
                )
        except Exception:
            pass


@app.command("expire-check")
def cmd_expire_check(
    path: Path = typer.Argument(..., help="DDR file or directory."),
    days_ahead: int = typer.Option(
        0, "--days-ahead", help="Also flag records expiring within N days."
    ),
    fmt: str = typer.Option("table", "--format", help="Output format: table | json."),
) -> None:
    """Report expired or due-for-review active records (computed from dates, not stored state)."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    now = datetime.now(UTC)
    horizon = now + timedelta(days=days_ahead) if days_ahead > 0 else now

    expired: list[dict] = []
    due_for_review: list[dict] = []
    expiring_soon: list[dict] = []

    for fp in _iter_ddr_files(path):
        try:
            loader = _safe_yaml()
            with open(fp, encoding="utf-8") as fh:
                raw = loader.load(fh)
            if not isinstance(raw, dict) or "ddr_version" not in raw:
                continue
            record = DDRRecord.model_validate(raw)
        except Exception:
            continue

        lc = record.lifecycle
        if lc.status != LifecycleStatus.active:
            continue

        entry: dict[str, Any] = {
            "file": str(fp),
            "id": str(record.id),
            "title": record.title,
            "expires_on": lc.expires_on.isoformat() if lc.expires_on else None,
            "last_reviewed_on": lc.last_reviewed_on.isoformat() if lc.last_reviewed_on else None,
        }

        if lc.expires_on:
            exp = lc.expires_on if lc.expires_on.tzinfo else lc.expires_on.replace(tzinfo=UTC)
            if exp < now:
                expired.append({**entry, "issue": "EXPIRED"})
            elif days_ahead > 0 and exp <= horizon:
                expiring_soon.append({**entry, "issue": f"EXPIRING_IN_{(exp - now).days}d"})

        if lc.review_cadence_days and lc.last_reviewed_on:
            rev = (
                lc.last_reviewed_on
                if lc.last_reviewed_on.tzinfo
                else lc.last_reviewed_on.replace(tzinfo=UTC)
            )
            if rev + timedelta(days=lc.review_cadence_days) < now:
                due_for_review.append({**entry, "issue": "DUE_FOR_REVIEW"})

    all_issues = expired + due_for_review + expiring_soon

    if fmt == "json":
        typer.echo(
            json.dumps(
                {
                    "expired": expired,
                    "due_for_review": due_for_review,
                    "expiring_soon": expiring_soon,
                },
                indent=2,
            )
        )
    else:
        if not all_issues:
            typer.echo("No expired or due-for-review records found.")
            return
        header = f"{'ISSUE':<20} {'ID':<38} {'TITLE':<38} {'EXPIRES_ON'}"
        typer.echo(header)
        typer.echo("-" * len(header))
        for e in all_issues:
            title = (e["title"] or "")[:36]
            exp = (e["expires_on"] or "")[:19]
            typer.echo(f"{e['issue']:<20} {e['id']:<38} {title:<38} {exp}")

    if all_issues:
        raise typer.Exit(1)


@app.command("export-sigma-filter")
def cmd_export_sigma_filter(
    path: Path = typer.Argument(..., help="DDR file with decision.kind == 'suppress'."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write filter YAML here (default: stdout)."
    ),
) -> None:
    """Emit a Sigma Filter YAML from a suppress DDR record (Sigma targets only)."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    try:
        record = _load_record(path)
    except (ValidationError, ValueError) as exc:
        typer.echo(f"ERROR: {path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not isinstance(record.target, SigmaTarget):
        typer.echo(
            f"ERROR: export-sigma-filter requires target.kind='sigma', got '{record.target.kind}'. "
            "Use 'ddr export-splunk' for Splunk-native targets.",
            err=True,
        )
        raise typer.Exit(1)

    if not isinstance(record.decision, SuppressDecision):
        typer.echo(
            f"ERROR: decision.kind is '{record.decision.kind}', expected 'suppress'",
            err=True,
        )
        raise typer.Exit(1)

    try:
        result = export_to_yaml(record, output=output)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output:
        typer.echo(f"Exported Sigma Filter to {output}")
    else:
        typer.echo(result, nl=False)


@app.command("export-splunk")
def cmd_export_splunk(
    path: Path = typer.Argument(..., help="DDR file with decision.kind == 'suppress'."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write SPL here (default: stdout)."
    ),
    fmt: str = typer.Option(
        "fragment", "--format", help="Output format: fragment | savedsearches."
    ),
    config: Path | None = typer.Option(
        None, "--config", help="Path to sigma-to-spl config YAML (Sigma targets only)."
    ),
) -> None:
    """Emit a SPL NOT clause from a suppress DDR record.

    Sigma targets require sigma-to-spl. Splunk-native targets work standalone.
    """
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    if fmt not in ("fragment", "savedsearches"):
        typer.echo("ERROR: --format must be 'fragment' or 'savedsearches'", err=True)
        raise typer.Exit(1)

    try:
        record = _load_record(path)
    except (ValidationError, ValueError) as exc:
        typer.echo(f"ERROR: {path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    if not isinstance(record.decision, SuppressDecision):
        typer.echo(
            f"ERROR: decision.kind is '{record.decision.kind}', expected 'suppress'",
            err=True,
        )
        raise typer.Exit(1)

    if config is not None and record.target.kind == "splunk":
        typer.echo(
            "WARN: --config has no effect on Splunk-native targets (sigma-to-spl not used)",
            err=True,
        )

    try:
        from ddr.exporters.splunk import export_to_spl

        result = export_to_spl(record, output=output, fmt=fmt, config=config)
    except RuntimeError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output:
        typer.echo(f"Exported SPL fragment to {output}")
    else:
        typer.echo(result, nl=False)


@app.command("refresh-hash")
def cmd_refresh_hash(
    path: Path = typer.Argument(..., help="DDR file to update."),
    rule: Path | None = typer.Option(None, "--rule", "-r", help="Override Sigma rule file path."),
    conf: Path | None = typer.Option(
        None, "--conf", help="Override savedsearches.conf path (Splunk targets)."
    ),
) -> None:
    """Recompute content/query hash after a confirmed cosmetic-only change."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    loader = _safe_yaml()
    writer = _writer_yaml()

    with open(path, encoding="utf-8") as fh:
        data = loader.load(fh)

    if not isinstance(data, dict):
        typer.echo("ERROR: not a YAML mapping", err=True)
        raise typer.Exit(1)

    target_kind = data.get("target", {}).get("kind", "sigma")

    if target_kind == "splunk":
        _cmd_refresh_hash_splunk(path, data, writer, conf)
        return

    if target_kind == "elastic":
        _cmd_refresh_hash_elastic(path, data, writer, rule)
        return

    if target_kind == "kql-sentinel":
        _cmd_refresh_hash_kql(path, data, writer, rule, target_kind)
        return

    if target_kind == "kql-m365d":
        _cmd_refresh_hash_kql(path, data, writer, rule, target_kind)
        return

    # --- sigma path ---
    # Normalise: handle both legacy rule_ref (singular) and new rule_refs (list)
    target_data = data.get("target", {})
    has_plural = "rule_refs" in target_data
    raw_refs: list[dict] = (
        target_data["rule_refs"] if has_plural else [target_data.get("rule_ref", {})]
    )

    if rule and len(raw_refs) > 1:
        typer.echo(
            "ERROR: --rule override cannot be used with multi-ref targets; "
            "edit path_or_url in each ref directly.",
            err=True,
        )
        raise typer.Exit(1)

    any_changed = False
    for i, ref in enumerate(raw_refs):
        ref_label = f"rule_refs[{i}]" if len(raw_refs) > 1 else "rule_ref"
        stored = ref.get("path_or_url", "")
        rule_path = rule or (Path(stored) if stored else None)

        if not rule_path or not rule_path.exists():
            typer.echo(
                f"ERROR: {ref_label}: rule file not found at '{rule_path}'. "
                "Use --rule to specify the path.",
                err=True,
            )
            raise typer.Exit(1)

        new_hash = compute_content_hash(rule_path)
        old_hash = ref.get("content_hash", "")

        if old_hash == new_hash:
            typer.echo(f"  {ref_label}: hash unchanged: {new_hash}")
        else:
            ref["content_hash"] = new_hash
            any_changed = True
            typer.echo(f"  {ref_label}: old: {old_hash}")
            typer.echo(f"  {ref_label}: new: {new_hash}")

    if not any_changed:
        return

    # Write back in the same format (singular or plural)
    if has_plural:
        data["target"]["rule_refs"] = raw_refs
    else:
        data["target"]["rule_ref"] = raw_refs[0]

    with open(path, "w", encoding="utf-8") as fh:
        writer.dump(data, fh)

    typer.echo(f"Updated {path}")


def _cmd_refresh_hash_splunk(
    ddr_path: Path,
    data: dict,
    writer: Any,
    conf_override: Path | None,
) -> None:
    from ddr._internal.splunk_conf import (
        compute_query_hash,
        extract_stanza,
        parse_savedsearches_conf,
    )

    target_data = data.get("target", {})
    has_plural = "query_refs" in target_data
    raw_refs: list[dict] = (
        target_data["query_refs"] if has_plural else [target_data.get("query_ref", {})]
    )

    if conf_override and len(raw_refs) > 1:
        typer.echo(
            "ERROR: --conf override cannot be used with multi-ref targets; "
            "edit path_or_url in each ref directly.",
            err=True,
        )
        raise typer.Exit(1)

    any_changed = False

    for i, qref in enumerate(raw_refs):
        ref_label = f"query_refs[{i}]" if len(raw_refs) > 1 else "query_ref"
        stanza_name = qref.get("name", "")
        stored_path = qref.get("path_or_url", "")

        if not stanza_name:
            typer.echo(f"ERROR: {ref_label}.name is missing", err=True)
            raise typer.Exit(1)

        if conf_override:
            conf_path = conf_override
        elif stored_path:
            if stored_path.startswith(("http://", "https://")):
                typer.echo(
                    f"NOTE: {ref_label}: path_or_url is a remote URL — use --conf to provide a local savedsearches.conf",  # noqa: E501
                    err=True,
                )
                raise typer.Exit(1)
            conf_path = Path(stored_path)
            if not conf_path.is_absolute():
                conf_path = ddr_path.parent / conf_path
        else:
            typer.echo(
                f"ERROR: {ref_label}: no conf path available. Set path_or_url or use --conf.",
                err=True,
            )
            raise typer.Exit(1)

        if not conf_path.exists():
            typer.echo(
                f"ERROR: {ref_label}: conf file not found at '{conf_path}'. Use --conf to specify the path.",  # noqa: E501
                err=True,
            )
            raise typer.Exit(1)

        try:
            conf = parse_savedsearches_conf(conf_path)
            stanza = extract_stanza(conf, stanza_name)
        except KeyError as exc:
            typer.echo(f"ERROR: {ref_label}: {exc}", err=True)
            raise typer.Exit(1) from exc
        except Exception as exc:
            typer.echo(f"ERROR: {ref_label}: failed to parse {conf_path}: {exc}", err=True)
            raise typer.Exit(1) from exc

        search = stanza.get("search", "").strip()
        if not search:
            typer.echo(
                f"ERROR: {ref_label}: stanza {stanza_name!r} has no 'search' key or empty value",
                err=True,
            )
            raise typer.Exit(1)

        new_hash = compute_query_hash(search)
        old_hash = qref.get("query_hash", "")

        if old_hash == new_hash:
            typer.echo(f"  {ref_label}: hash unchanged: {new_hash}")
        else:
            qref["query_hash"] = new_hash
            any_changed = True
            typer.echo(f"  {ref_label}: old: {old_hash or '(none)'}")
            typer.echo(f"  {ref_label}: new: {new_hash}")

    if not any_changed:
        return

    if has_plural:
        data["target"]["query_refs"] = raw_refs
    else:
        data["target"]["query_ref"] = raw_refs[0]

    with open(ddr_path, "w", encoding="utf-8") as fh:
        writer.dump(data, fh)

    typer.echo(f"Updated {ddr_path}")


def _cmd_refresh_hash_elastic(
    ddr_path: Path,
    data: dict,
    writer: Any,
    rule_override: Path | None,
) -> None:
    from ddr._internal.elastic_hash import compute_elastic_hash

    target_data = data.get("target", {})
    raw_refs: list[dict] = target_data.get("query_refs", [])

    if rule_override and len(raw_refs) > 1:
        typer.echo(
            "ERROR: --rule override cannot be used with multi-ref targets; "
            "edit path_or_url in each ref directly.",
            err=True,
        )
        raise typer.Exit(1)

    any_changed = False

    for i, qref in enumerate(raw_refs):
        ref_label = f"query_refs[{i}]" if len(raw_refs) > 1 else "query_refs[0]"
        stored_path = qref.get("path_or_url", "")

        if rule_override:
            ndjson_path = rule_override
        elif stored_path:
            if stored_path.startswith(("http://", "https://")):
                typer.echo(
                    f"  {ref_label}: skipping remote ref — update content_hash manually",
                    err=True,
                )
                continue
            ndjson_path = Path(stored_path)
            if not ndjson_path.is_absolute():
                ndjson_path = ddr_path.parent / ndjson_path
        else:
            typer.echo(f"  {ref_label}: no path_or_url set; skipping", err=True)
            continue

        if not ndjson_path.exists():
            typer.echo(f"  {ref_label}: rule file not found at '{ndjson_path}'", err=True)
            continue

        try:
            new_hash = compute_elastic_hash(ndjson_path)
        except Exception as exc:
            typer.echo(f"  {ref_label}: failed to compute hash: {exc}", err=True)
            continue

        old_hash = qref.get("content_hash", "")
        if old_hash == new_hash:
            typer.echo(f"  {ref_label}: hash unchanged: {new_hash}")
        else:
            qref["content_hash"] = new_hash
            any_changed = True
            typer.echo(f"  {ref_label}: old: {old_hash or '(none)'}")
            typer.echo(f"  {ref_label}: new: {new_hash}")

    if not any_changed:
        return

    data["target"]["query_refs"] = raw_refs
    with open(ddr_path, "w", encoding="utf-8") as fh:
        writer.dump(data, fh)
    typer.echo(f"Updated {ddr_path}")


def _cmd_refresh_hash_kql(
    ddr_path: Path,
    data: dict,
    writer: Any,
    rule_override: Path | None,
    target_kind: str,
) -> None:
    if target_kind == "kql-sentinel":
        from ddr._internal.sentinel_hash import compute_sentinel_hash as _compute_hash
    else:
        from ddr._internal.m365d_hash import compute_m365d_hash as _compute_hash  # type: ignore[assignment]  # noqa: I001

    target_data = data.get("target", {})
    raw_refs: list[dict] = target_data.get("query_refs", [])

    if rule_override and len(raw_refs) > 1:
        typer.echo(
            "ERROR: --rule override cannot be used with multi-ref targets; "
            "edit path_or_url in each ref directly.",
            err=True,
        )
        raise typer.Exit(1)

    any_changed = False

    for i, qref in enumerate(raw_refs):
        ref_label = f"query_refs[{i}]" if len(raw_refs) > 1 else "query_refs[0]"
        stored_path = qref.get("path_or_url", "")

        if rule_override:
            json_path = rule_override
        elif stored_path:
            if stored_path.startswith(("http://", "https://")):
                typer.echo(
                    f"  {ref_label}: skipping remote ref — update content_hash manually",
                    err=True,
                )
                continue
            json_path = Path(stored_path)
            if not json_path.is_absolute():
                json_path = ddr_path.parent / json_path
        else:
            typer.echo(f"  {ref_label}: no path_or_url set for ref[{i}]; skipping", err=True)
            continue

        if not json_path.exists():
            typer.echo(f"  {ref_label}: rule file not found at '{json_path}'", err=True)
            continue

        try:
            new_hash = _compute_hash(json_path)
        except Exception as exc:
            typer.echo(f"  {ref_label}: failed to compute hash: {exc}", err=True)
            continue

        old_hash = qref.get("content_hash", "")
        if old_hash == new_hash:
            typer.echo(f"  {ref_label}: hash unchanged: {new_hash}")
        else:
            qref["content_hash"] = new_hash
            any_changed = True
            typer.echo(f"  {ref_label}: old: {old_hash or '(none)'}")
            typer.echo(f"  {ref_label}: new: {new_hash}")

    if not any_changed:
        return

    data["target"]["query_refs"] = raw_refs
    with open(ddr_path, "w", encoding="utf-8") as fh:
        writer.dump(data, fh)
    typer.echo(f"Updated {ddr_path}")


@app.command("export-elastic-exception")
def cmd_export_elastic_exception(
    path: Path = typer.Argument(..., help="DDR file with decision.kind == 'suppress'."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write exception NDJSON here (default: stdout)."
    ),
    list_id: str = typer.Option("ddr-exceptions", "--list-id", help="Elastic exception list ID."),
) -> None:
    """Emit a Kibana exception list item NDJSON from an Elastic suppress DDR record."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    try:
        record = _load_record(path)
    except (ValidationError, ValueError) as exc:
        typer.echo(f"ERROR: {path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    if record.target.kind != "elastic":
        typer.echo(
            f"ERROR: export-elastic-exception requires target.kind='elastic', "
            f"got '{record.target.kind}'",
            err=True,
        )
        raise typer.Exit(1)

    if not isinstance(record.decision, SuppressDecision):
        typer.echo(
            f"ERROR: decision.kind is '{record.decision.kind}', expected 'suppress'. "
            "accept-risk and deprecate decisions have no exception to export.",
            err=True,
        )
        raise typer.Exit(1)

    try:
        from ddr.exporters.elastic_exception import export_to_ndjson

        ndjson, is_manual = export_to_ndjson(record, output=output, list_id=list_id)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if is_manual:
        typer.echo(
            "# MANUAL: KQL filter was too complex to auto-parse into structured entries[].\n"
            "#         Review entries[] in the output and populate before importing into Kibana.",
            err=True,
        )

    if output:
        typer.echo(f"Exported Elastic exception to {output}")
    else:
        typer.echo(ndjson)


@app.command("export-kql")
def cmd_export_kql(
    path: Path = typer.Argument(..., help="DDR file with decision.kind == 'suppress'."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write .kql fragment here (default: stdout)."
    ),
) -> None:
    """Emit a Kusto | where not (...) fragment from a kql-sentinel or kql-m365d suppress DDR."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    try:
        record = _load_record(path)
    except (ValidationError, ValueError) as exc:
        typer.echo(f"ERROR: {path}: {exc}", err=True)
        raise typer.Exit(1) from exc

    if record.target.kind not in ("kql-sentinel", "kql-m365d"):
        typer.echo(
            f"ERROR: export-kql requires target.kind kql-sentinel or kql-m365d, "
            f"got '{record.target.kind}'",
            err=True,
        )
        raise typer.Exit(1)

    if not isinstance(record.decision, SuppressDecision):
        typer.echo(
            f"ERROR: decision.kind is '{record.decision.kind}', expected 'suppress'. "
            "accept-risk and deprecate decisions have no KQL fragment to export.",
            err=True,
        )
        raise typer.Exit(1)

    try:
        from ddr.exporters.kql_fragment import export_kql_fragment

        fragment = export_kql_fragment(record, output=output)
    except Exception as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(1) from exc

    if output:
        typer.echo(f"Exported KQL fragment to {output}")
    else:
        typer.echo(fragment, nl=False)


if __name__ == "__main__":
    app()
