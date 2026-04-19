"""
pii_safe_cli/cli.py
====================
CLI entrypoint — built with Click.

Commands
--------
  pii-safe sanitize   Sanitize a file or directory of files
  pii-safe scan       Dry-run scan: show detections without modifying files
  pii-safe version    Print version info

Usage examples
--------------
  pii-safe sanitize --input ./logs/ --policy policy.yaml --output ./clean/
  pii-safe sanitize --input report.csv --mode pseudonymize
  pii-safe sanitize --input data/ --mode redact --audit-format csv --output out/
  pii-safe scan --input data.json
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import click

from pii_safe_cli import __version__
from pii_safe_cli.audit import write_audit_report
from pii_safe_cli.detector import PIIDetector
from pii_safe_cli.policy import load_policy
from pii_safe_cli.processors import process_file
from pii_safe_cli.redactor import Redactor, RedactionEvent

# ---------------------------------------------------------------------------
# Supported file extensions
# ---------------------------------------------------------------------------
SUPPORTED_EXTS = {".csv", ".json", ".txt", ".log", ".tsv", ".text"}


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="pii-safe")
def cli() -> None:
    """PII-Safe — Batch dataset PII sanitization CLI."""


# ---------------------------------------------------------------------------
# sanitize command
# ---------------------------------------------------------------------------

@cli.command("sanitize")
@click.option(
    "--input", "-i", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Input file or directory to sanitize.",
)
@click.option(
    "--output", "-o", "output_path",
    default=None,
    type=click.Path(),
    help="Output file or directory. Defaults to <input>_sanitized/.",
)
@click.option(
    "--policy", "-p", "policy_path",
    default=None,
    type=click.Path(exists=True),
    help="YAML policy file. Overrides --mode and --entity-types if provided.",
)
@click.option(
    "--mode", "-m",
    default=None,
    type=click.Choice(["redact", "pseudonymize", "block"], case_sensitive=False),
    help="Redaction mode (overridden by --policy if both given).",
)
@click.option(
    "--entity-types", "-e",
    default=None,
    multiple=True,
    help="Entity types to scan for (repeatable). E.g. -e EMAIL -e SSN",
)
@click.option(
    "--audit-report", "-a", "audit_report_path",
    default=None,
    type=click.Path(),
    help="Path for the audit report file. Defaults to <output>/audit_report.json.",
)
@click.option(
    "--audit-format",
    default=None,
    type=click.Choice(["json", "csv"], case_sensitive=False),
    help="Audit report format (json or csv). Overrides policy setting.",
)
@click.option(
    "--recursive/--no-recursive", "-r",
    default=True,
    show_default=True,
    help="Recursively process directories.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress progress output.",
)
def sanitize(
    input_path: str,
    output_path: Optional[str],
    policy_path: Optional[str],
    mode: Optional[str],
    entity_types: tuple,
    audit_report_path: Optional[str],
    audit_format: Optional[str],
    recursive: bool,
    quiet: bool,
) -> None:
    """Sanitize PII from a file or directory of files."""

    inp = Path(input_path)

    # Load policy (file > CLI flags > defaults)
    policy = load_policy(Path(policy_path) if policy_path else None)
    if mode:
        policy.mode = mode
    if entity_types:
        policy.entity_types = list(entity_types)
    if audit_format:
        policy.output_format = audit_format

    # Resolve output directory
    if output_path is None:
        out_dir = inp.parent / f"{inp.stem}_sanitized" if inp.is_file() else Path(str(inp) + "_sanitized")
    else:
        out_dir = Path(output_path)

    # Collect input files
    input_files = _collect_files(inp, recursive)
    if not input_files:
        click.echo("⚠  No supported files found.", err=True)
        sys.exit(1)

    # Set up detector + redactor
    detector = PIIDetector(
        entity_types=policy.entity_types or None,
        extra_patterns=policy.extra_patterns,
    )
    redactor = Redactor(detector, mode=policy.mode)   # type: ignore[arg-type]

    all_events: List[RedactionEvent] = []
    ok = 0
    skipped = 0

    for file_path in input_files:
        # Mirror directory structure in output
        try:
            rel = file_path.relative_to(inp) if inp.is_dir() else file_path.name
        except ValueError:
            rel = file_path.name

        out_file = out_dir / rel if inp.is_dir() else out_dir / file_path.name
        out_file = out_file.with_suffix(file_path.suffix)  # keep extension

        if not quiet:
            click.echo(f"  → {file_path}  ", nl=False)

        try:
            events = process_file(file_path, out_file, redactor)
            all_events.extend(events)
            ok += 1
            if not quiet:
                n = len(events)
                click.echo(
                    click.style(f"✓  {n} interception{'s' if n != 1 else ''}", fg="green")
                )
        except Exception as exc:
            skipped += 1
            if not quiet:
                click.echo(click.style(f"✗  {exc}", fg="red"))

    # Write audit report
    if audit_report_path:
        report_path = Path(audit_report_path)
    else:
        suffix = ".csv" if policy.output_format == "csv" else ".json"
        report_path = out_dir / f"audit_report{suffix}"

    write_audit_report(
        all_events,
        report_path,
        fmt=policy.output_format,   # type: ignore[arg-type]
        mode=policy.mode,
        input_path=str(inp),
    )

    # Summary
    if not quiet:
        click.echo("")
        click.echo(f"{'─'*50}")
        click.echo(f"  Files processed : {ok}")
        if skipped:
            click.echo(click.style(f"  Files skipped   : {skipped}", fg="yellow"))
        click.echo(f"  Total PII hits  : {len(all_events)}")
        click.echo(f"  Mode            : {policy.mode}")
        click.echo(f"  Sanitized →      {out_dir}/")
        click.echo(f"  Audit report →   {report_path}")

    sys.exit(0 if skipped == 0 else 2)


# ---------------------------------------------------------------------------
# scan command (dry-run)
# ---------------------------------------------------------------------------

@cli.command("scan")
@click.option("--input", "-i", "input_path", required=True, type=click.Path(exists=True))
@click.option("--policy", "-p", "policy_path", default=None, type=click.Path(exists=True))
@click.option("--entity-types", "-e", default=None, multiple=True)
@click.option("--recursive/--no-recursive", "-r", default=True)
def scan(
    input_path: str,
    policy_path: Optional[str],
    entity_types: tuple,
    recursive: bool,
) -> None:
    """Dry-run scan: show PII detections without modifying any files."""

    inp = Path(input_path)
    policy = load_policy(Path(policy_path) if policy_path else None)
    if entity_types:
        policy.entity_types = list(entity_types)

    detector = PIIDetector(
        entity_types=policy.entity_types or None,
        extra_patterns=policy.extra_patterns,
    )

    input_files = _collect_files(inp, recursive)
    total_hits = 0

    for file_path in input_files:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        click.echo(click.style(f"\n{file_path}", bold=True))
        file_hits = 0
        for line_no, line_result in detector.scan_lines(text):
            if line_result.has_pii:
                for d in line_result.detections:
                    click.echo(
                        f"  Line {line_no:4d} | "
                        + click.style(d.entity_type, fg="yellow")
                        + f" | {d.value!r}"
                    )
                    file_hits += 1
        if file_hits == 0:
            click.echo("  " + click.style("✓ No PII detected", fg="green"))
        total_hits += file_hits

    click.echo(f"\n{'─'*50}")
    click.echo(f"Total PII detections: {total_hits}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_files(path: Path, recursive: bool) -> List[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() in SUPPORTED_EXTS else []
    pattern = "**/*" if recursive else "*"
    return [
        f for f in path.glob(pattern)
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTS
    ]


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
