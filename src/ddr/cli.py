"""DDR command-line interface — five commands for v0.1."""

from __future__ import annotations

import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import typer
from pydantic import ValidationError
from ruamel.yaml import YAML

from ddr._internal.hash_utils import compute_content_hash
from ddr.exporters.sigma_filter import export_to_yaml
from ddr.models.record import DDRRecord, LifecycleStatus, SuppressDecision

app = typer.Typer(
    name="ddr",
    help="Detection Decision Records — governance for detection-as-code.",
    no_args_is_help=True,
)

# Patterns used by --strict free-text lint (heuristic, warn-only)
_LOG_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"  # ISO timestamps
    r"|(\b(?:\d{1,3}\.){3}\d{1,3}\b)"              # IPv4
    r"|(\w+=\w+\|\w+=\w+)"                          # key=value pipe logs
)


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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.command("new")
def cmd_new(
    sigma_rule: Path = typer.Argument(..., help="Path to the Sigma rule YAML."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write new DDR here (default: stdout)."),
    decision_kind: str = typer.Option(
        "suppress", "--decision", "-d", help="Decision type: suppress | accept-risk | deprecate."
    ),
) -> None:
    """Scaffold a DDR from a Sigma rule (content-hashes the rule, prefills target)."""
    if not sigma_rule.exists():
        typer.echo(f"ERROR: {sigma_rule} not found", err=True)
        raise typer.Exit(1)

    if decision_kind not in ("suppress", "accept-risk", "deprecate"):
        typer.echo("ERROR: --decision must be suppress | accept-risk | deprecate", err=True)
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

    scaffold = _strip_none(
        {
            "ddr_version": "0.1",
            "id": str(uuid4()),
            "title": f"Suppress: {rule_title}" if decision_kind == "suppress" else rule_title,
            "description": "",
            "target": {
                "kind": "sigma",
                "rule_ref": {
                    "rule_id": rule_id,
                    "content_hash": content_hash,
                    "source": "internal",
                    "path_or_url": str(sigma_rule.resolve()),
                },
            },
            "decision": _build_decision_scaffold(decision_kind, dict(ls)),
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

    writer = _writer_yaml()
    buf = io.StringIO()
    writer.dump(scaffold, buf)
    result = buf.getvalue()

    if output:
        output.write_text(result, encoding="utf-8")
        typer.echo(f"Created {output}")
    else:
        typer.echo(result, nl=False)


def _build_decision_scaffold(kind: str, logsource: dict) -> dict:
    if kind == "suppress":
        return {
            "kind": "suppress",
            "rationale": "TODO: explain why this is an acceptable false positive",
            "tuning": {
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


@app.command("validate")
def cmd_validate(
    path: Path = typer.Argument(..., help="DDR file or directory."),
    strict: bool = typer.Option(False, "--strict", help="Enable free-text lints beyond schema validation."),
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
                f"  WARN  {fp}: description/rationale may contain raw log data (use evidence.ref instead)",
                err=True,
            )
            break


@app.command("expire-check")
def cmd_expire_check(
    path: Path = typer.Argument(..., help="DDR file or directory."),
    days_ahead: int = typer.Option(0, "--days-ahead", help="Also flag records expiring within N days."),
    fmt: str = typer.Option("table", "--format", help="Output format: table | json."),
) -> None:
    """Report expired or due-for-review active records (computed from dates, not stored state)."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    now = datetime.now(timezone.utc)
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
            exp = lc.expires_on if lc.expires_on.tzinfo else lc.expires_on.replace(tzinfo=timezone.utc)
            if exp < now:
                expired.append({**entry, "issue": "EXPIRED"})
            elif days_ahead > 0 and exp <= horizon:
                expiring_soon.append({**entry, "issue": f"EXPIRING_IN_{(exp - now).days}d"})

        if lc.review_cadence_days and lc.last_reviewed_on:
            rev = lc.last_reviewed_on if lc.last_reviewed_on.tzinfo else lc.last_reviewed_on.replace(tzinfo=timezone.utc)
            if rev + timedelta(days=lc.review_cadence_days) < now:
                due_for_review.append({**entry, "issue": "DUE_FOR_REVIEW"})

    all_issues = expired + due_for_review + expiring_soon

    if fmt == "json":
        typer.echo(
            json.dumps(
                {"expired": expired, "due_for_review": due_for_review, "expiring_soon": expiring_soon},
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
    output: Path | None = typer.Option(None, "--output", "-o", help="Write filter YAML here (default: stdout)."),
) -> None:
    """Emit a Sigma Filter YAML from a suppress DDR record."""
    if not path.exists():
        typer.echo(f"ERROR: {path} not found", err=True)
        raise typer.Exit(1)

    try:
        record = _load_record(path)
    except (ValidationError, ValueError) as exc:
        typer.echo(f"ERROR: {path}: {exc}", err=True)
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
        raise typer.Exit(1)

    if output:
        typer.echo(f"Exported Sigma Filter to {output}")
    else:
        typer.echo(result, nl=False)


@app.command("refresh-hash")
def cmd_refresh_hash(
    path: Path = typer.Argument(..., help="DDR file to update."),
    rule: Path | None = typer.Option(None, "--rule", "-r", help="Override rule file path."),
) -> None:
    """Recompute target.rule_ref.content_hash after a confirmed cosmetic-only rule change."""
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

    stored = data.get("target", {}).get("rule_ref", {}).get("path_or_url", "")
    rule_path = rule or (Path(stored) if stored else None)

    if not rule_path or not rule_path.exists():
        typer.echo(
            f"ERROR: rule file not found at '{rule_path}'. Use --rule to specify the path.",
            err=True,
        )
        raise typer.Exit(1)

    new_hash = compute_content_hash(rule_path)
    old_hash = data.get("target", {}).get("rule_ref", {}).get("content_hash", "")

    if old_hash == new_hash:
        typer.echo(f"Hash unchanged: {new_hash}")
        return

    data["target"]["rule_ref"]["content_hash"] = new_hash

    with open(path, "w", encoding="utf-8") as fh:
        writer.dump(data, fh)

    typer.echo(f"Updated {path}")
    typer.echo(f"  old: {old_hash}")
    typer.echo(f"  new: {new_hash}")


if __name__ == "__main__":
    app()
