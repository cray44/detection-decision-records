"""Splunk SPL NOT-clause exporter for DDR suppress decisions."""

from __future__ import annotations

import re
import tempfile
import warnings
from pathlib import Path
from typing import Any

import yaml

from ddr.models.record import DDRRecord, SigmaTuning, SplunkTuning, SuppressDecision

_NOT_RE = re.compile(r"^not\s+\(?(.+?)\)?$", re.IGNORECASE)
_OUTER_NOT_RE = re.compile(r"^NOT\s*\((.+)\)$", re.DOTALL)


def _strip_not(condition: str) -> tuple[str, bool]:
    """Return (inner_condition, had_not). had_not=True → wrap output in NOT(...)."""
    m = _NOT_RE.match(condition.strip())
    if m:
        return m.group(1).strip(), True
    return condition.strip(), False


def _normalize_splunk_filter(splunk_filter: str) -> str:
    """Strip outer NOT(...) wrapper if present; return inner clause."""
    m = _OUTER_NOT_RE.match(splunk_filter.strip())
    if m:
        return m.group(1).strip()
    return splunk_filter.strip()


def _require_sigma_to_spl() -> None:
    try:
        import sigma_to_spl  # noqa: F401
        from sigma.backends.splunk import SplunkBackend  # noqa: F401
        from sigma.collection import SigmaCollection  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            f"sigma-to-spl is required for export-splunk on Sigma targets ({exc}). "
            "Install with: pip install -e <path-to-sigma-to-spl>"
        ) from exc


def _build_splunk_suppression_sigma(record: DDRRecord, config: Path | Any | None = None) -> str:
    """Lower a Sigma-targeted suppress record to a SPL NOT clause."""
    _require_sigma_to_spl()

    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection
    from sigma_to_spl.config import default_config, load_config
    from sigma_to_spl.postprocess import PostProcessor

    dec = record.decision
    tuning: SigmaTuning = dec.tuning  # type: ignore[assignment]
    ls = tuning.logsource

    inner_cond, had_not = _strip_not(tuning.condition)
    if not had_not:
        warnings.warn(
            f"condition '{tuning.condition}' does not start with 'not' — "
            "emitting plain clause without NOT wrapper",
            stacklevel=3,
        )

    logsource_dict: dict[str, str] = {}
    if ls.category:
        logsource_dict["category"] = ls.category
    if ls.product:
        logsource_dict["product"] = ls.product
    if ls.service:
        logsource_dict["service"] = ls.service

    detection: dict[str, Any] = dict(tuning.selections)
    detection["condition"] = inner_cond

    rule_yaml = yaml.dump(
        {
            "title": f"DDR Suppression Fragment: {record.title}",
            "name": f"ddr_suppression_{record.id.hex[:8]}",
            "status": "experimental",
            "logsource": logsource_dict,
            "detection": detection,
        },
        allow_unicode=True,
        default_flow_style=False,
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as fh:
        fh.write(rule_yaml)
        tmp_path = Path(fh.name)

    try:
        collection = SigmaCollection.load_ruleset([tmp_path])
        backend = SplunkBackend()
        queries = backend.convert(collection)
    finally:
        tmp_path.unlink(missing_ok=True)

    if not queries:
        raise RuntimeError("SplunkBackend produced no output from the tuning selections.")

    spl = queries[0]

    if config is None:
        cfg = default_config()
    elif isinstance(config, Path):
        cfg = load_config(config)
    else:
        cfg = config

    pp = PostProcessor(cfg)
    spl = pp._apply_field_map(spl)

    return f"NOT ({spl})" if had_not else f"({spl})"


def _build_splunk_suppression_native(record: DDRRecord) -> str:
    """Return SPL NOT clause from a Splunk-native suppress record (no sigma-to-spl required)."""
    dec = record.decision
    tuning: SplunkTuning = dec.tuning  # type: ignore[assignment]
    inner = _normalize_splunk_filter(tuning.splunk_filter)
    return f"NOT ({inner})"


def build_splunk_suppression(record: DDRRecord, config: Path | Any | None = None) -> str:
    """Return a SPL NOT clause from a suppress DDR record.

    For Sigma targets: requires sigma-to-spl. config is a Path, SplunkConfig, or None.
    For Splunk-native targets: no sigma-to-spl needed; config is ignored.
    """
    if not isinstance(record.decision, SuppressDecision):
        raise ValueError(
            f"export-splunk requires decision.kind='suppress', got '{record.decision.kind}'"
        )

    if record.target.kind == "splunk":
        return _build_splunk_suppression_native(record)

    return _build_splunk_suppression_sigma(record, config=config)


def export_to_spl(
    record: DDRRecord,
    output: Path | None = None,
    fmt: str = "fragment",
    config: Path | Any | None = None,
) -> str:
    """Return SPL string; write to output path if given.

    fmt: 'fragment' (default) — bare NOT(...) clause
         'savedsearches' — savedsearches.conf stanza
    """
    spl = build_splunk_suppression(record, config=config)

    if fmt == "savedsearches":
        if record.target.kind == "splunk":
            tuning: SplunkTuning = record.decision.tuning  # type: ignore[assignment]
            title = tuning.filter_title or record.title
            result = _format_savedsearches_native(title, spl)
        else:
            from sigma_to_spl.postprocess import format_savedsearches

            tuning_sigma: SigmaTuning = record.decision.tuning  # type: ignore[assignment]
            title = tuning_sigma.filter_title or record.title
            result = format_savedsearches(title, spl)
    else:
        result = spl

    if output is not None:
        output.write_text(result, encoding="utf-8")

    return result


def _format_savedsearches_native(title: str, spl_fragment: str) -> str:
    """Format a savedsearches.conf stanza for a native Splunk target."""
    stanza_name = re.sub(r"[^a-z0-9_]", "_", title.lower()).strip("_")
    return (
        f"[{stanza_name}]\n"
        f"search = {spl_fragment}\n"
        f"dispatch.earliest_time = -24h\n"
        f"dispatch.latest_time = now\n"
        f"enableSched = 1\n"
        f"cron_schedule = 0 * * * *\n"
    )
