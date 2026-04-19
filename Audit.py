"""
pii_safe_cli/audit.py
======================
Generates downloadable audit reports from a list of RedactionEvents.

Output formats:
  - JSON  (.json) — machine-readable
  - CSV   (.csv)  — spreadsheet-friendly

Each entry contains:
  timestamp, source_file, line_number, entity_type,
  original_value_hash (SHA-256 — never the raw value),
  placeholder, start, end

A summary section counts total events per entity type and per file.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Literal

from pii_safe_cli.redactor import RedactionEvent

ReportFormat = Literal["json", "csv"]


def write_audit_report(
    events: List[RedactionEvent],
    output_path: Path,
    fmt: ReportFormat = "json",
    mode: str = "unknown",
    input_path: str = "",
) -> None:
    """
    Write an audit report to *output_path*.

    Parameters
    ----------
    events      : All RedactionEvents produced during the batch run.
    output_path : Destination file (extension determines format if fmt not set).
    fmt         : "json" or "csv".
    mode        : The redaction mode used (for report metadata).
    input_path  : The input path scanned (for report metadata).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        _write_csv(events, output_path, mode, input_path)
    else:
        _write_json(events, output_path, mode, input_path)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def _write_json(
    events: List[RedactionEvent],
    output_path: Path,
    mode: str,
    input_path: str,
) -> None:
    summary = _build_summary(events)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_path":   input_path,
        "mode":         mode,
        "summary": {
            "total_interceptions": summary["total"],
            "by_entity_type":      summary["by_type"],
            "by_file":             summary["by_file"],
            "blocked_records":     summary["blocked"],
        },
        "events": [_event_to_dict(e) for e in events],
    }
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CSV report
# ---------------------------------------------------------------------------

def _write_csv(
    events: List[RedactionEvent],
    output_path: Path,
    mode: str,
    input_path: str,
) -> None:
    fieldnames = [
        "source_file", "line_number", "entity_type",
        "original_value_hash", "placeholder", "start", "end",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for e in events:
            writer.writerow(_event_to_dict(e))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event_to_dict(e: RedactionEvent) -> dict:
    return {
        "source_file":          e.source_file or "",
        "line_number":          e.line_number,
        "entity_type":          e.entity_type,
        "original_value_hash":  e.original_hash,
        "placeholder":          e.placeholder,
        "start":                e.start,
        "end":                  e.end,
    }


def _build_summary(events: List[RedactionEvent]) -> dict:
    by_type  = Counter(e.entity_type for e in events)
    by_file  = Counter(e.source_file or "unknown" for e in events)
    blocked  = sum(1 for e in events if e.placeholder == "[BLOCKED]")
    return {
        "total":   len(events),
        "by_type": dict(by_type),
        "by_file": dict(by_file),
        "blocked": blocked,
    }
