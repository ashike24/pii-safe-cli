"""
pii_safe_cli/processors.py
===========================
Format-specific batch processors.

Each processor:
  1. Reads the input file
  2. Applies the Redactor to every text field / line
  3. Writes the sanitized output file
  4. Returns a list of RedactionEvents for the audit report

Supported formats:
  - Plain text  (.txt, .log, and any unrecognized extension)
  - CSV         (.csv)
  - JSON        (.json)
"""

from __future__ import annotations

import csv
import json
import io
from pathlib import Path
from typing import List, Optional

from pii_safe_cli.redactor import Redactor, RedactionEvent, RedactionResult


def _ext(path: Path) -> str:
    return path.suffix.lower()


def process_file(
    input_path: Path,
    output_path: Path,
    redactor: Redactor,
) -> List[RedactionEvent]:
    """
    Dispatch to the correct format processor.
    Returns all RedactionEvents produced during processing.
    """
    ext = _ext(input_path)
    if ext == ".csv":
        return _process_csv(input_path, output_path, redactor)
    elif ext == ".json":
        return _process_json(input_path, output_path, redactor)
    else:
        return _process_text(input_path, output_path, redactor)


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------

def _process_text(
    input_path: Path,
    output_path: Path,
    redactor: Redactor,
) -> List[RedactionEvent]:
    events: List[RedactionEvent] = []
    lines_out: List[str] = []

    text = input_path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(keepends=True), start=1):
        result = redactor.redact(
            line.rstrip("\n\r"),
            line_number=line_no,
            source_file=str(input_path),
        )
        for e in result.events:
            e.source_file = str(input_path)
        events.extend(result.events)

        if result.blocked:
            lines_out.append("[RECORD BLOCKED — PII DETECTED]\n")
        else:
            lines_out.append(result.sanitized_text + "\n")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(lines_out), encoding="utf-8")
    return events


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def _process_csv(
    input_path: Path,
    output_path: Path,
    redactor: Redactor,
) -> List[RedactionEvent]:
    events: List[RedactionEvent] = []
    rows_out: List[List[str]] = []
    header: Optional[List[str]] = None

    text = input_path.read_text(encoding="utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))

    for row_no, row in enumerate(reader, start=1):
        if row_no == 1:
            # Keep header row untouched
            header = row
            rows_out.append(row)
            continue

        if redactor._mode == "block":
            # Scan entire row joined; block entire row if any PII found
            joined = " ".join(row)
            result = redactor.redact(joined, line_number=row_no, source_file=str(input_path))
            if result.blocked:
                for e in result.events:
                    e.source_file = str(input_path)
                events.extend(result.events)
                rows_out.append(["[RECORD BLOCKED]"] * len(row))
                continue

        sanitized_row: List[str] = []
        for cell in row:
            result = redactor.redact(cell, line_number=row_no, source_file=str(input_path))
            for e in result.events:
                e.source_file = str(input_path)
            events.extend(result.events)
            sanitized_row.append(result.sanitized_text)
        rows_out.append(sanitized_row)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerows(rows_out)
    return events


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _process_json(
    input_path: Path,
    output_path: Path,
    redactor: Redactor,
) -> List[RedactionEvent]:
    events: List[RedactionEvent] = []
    text = input_path.read_text(encoding="utf-8", errors="replace")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {input_path}: {exc}") from exc

    sanitized_data = _redact_json_value(data, redactor, events, str(input_path))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sanitized_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return events


def _redact_json_value(value, redactor: Redactor, events: list, source_file: str):
    """Recursively walk a JSON structure and redact string leaves."""
    if isinstance(value, str):
        result = redactor.redact(value, source_file=source_file)
        for e in result.events:
            e.source_file = source_file
        events.extend(result.events)
        return result.sanitized_text
    elif isinstance(value, dict):
        return {k: _redact_json_value(v, redactor, events, source_file) for k, v in value.items()}
    elif isinstance(value, list):
        return [_redact_json_value(item, redactor, events, source_file) for item in value]
    else:
        return value  # int, float, bool, None — pass through unchanged
