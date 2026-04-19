"""
tests/test_cli.py
==================
Comprehensive test suite for pii-safe-cli.

Covers:
  - PIIDetector  (all built-in entity types)
  - Redactor     (redact / pseudonymize / block modes)
  - File processors (text, CSV, JSON)
  - Audit report  (JSON and CSV output)
  - Policy loader
  - CLI commands  (sanitize, scan) via Click test runner

Run with:
    pytest tests/ -v
"""

import csv
import json
import sys
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_safe_cli.audit import write_audit_report
from pii_safe_cli.cli import cli
from pii_safe_cli.detector import PIIDetector
from pii_safe_cli.policy import Policy, load_policy
from pii_safe_cli.processors import process_file
from pii_safe_cli.redactor import Redactor


# ===========================================================================
# PIIDetector
# ===========================================================================

class TestPIIDetector:
    def test_email_detected(self):
        d = PIIDetector()
        r = d.scan("Send to alice@example.com")
        assert any(e.entity_type == "EMAIL" for e in r.detections)

    def test_ssn_detected(self):
        d = PIIDetector()
        r = d.scan("SSN: 123-45-6789")
        assert any(e.entity_type == "SSN" for e in r.detections)

    def test_phone_detected(self):
        d = PIIDetector()
        r = d.scan("Call +1-800-555-0199")
        assert any(e.entity_type == "PHONE" for e in r.detections)

    def test_ip_detected(self):
        d = PIIDetector()
        r = d.scan("Server at 192.168.1.1")
        assert any(e.entity_type == "IP_ADDR" for e in r.detections)

    def test_no_pii_clean_text(self):
        d = PIIDetector()
        r = d.scan("The quarterly revenue grew by 12%.")
        assert not r.has_pii

    def test_entity_type_filter(self):
        d = PIIDetector(entity_types=["EMAIL"])
        r = d.scan("alice@example.com and SSN 123-45-6789")
        types = {e.entity_type for e in r.detections}
        assert "EMAIL" in types
        assert "SSN" not in types

    def test_multiple_entities_same_text(self):
        d = PIIDetector()
        r = d.scan("Email alice@x.com, SSN 111-22-3333")
        assert len(r.detections) >= 2

    def test_custom_pattern(self):
        d = PIIDetector(extra_patterns={"EMP_ID": r"EMP-\d{4}"})
        r = d.scan("Employee EMP-1234 has joined.")
        assert any(e.entity_type == "EMP_ID" for e in r.detections)

    def test_scan_lines_yields_line_numbers(self):
        d = PIIDetector()
        text = "clean line\nalice@x.com here\nanother clean"
        results = list(d.scan_lines(text))
        assert results[1][0] == 2
        assert results[1][1].has_pii

    def test_detection_positions(self):
        d = PIIDetector()
        r = d.scan("contact alice@x.com today")
        email_hit = next(e for e in r.detections if e.entity_type == "EMAIL")
        assert email_hit.start == 8
        assert email_hit.end == 8 + len("alice@x.com")


# ===========================================================================
# Redactor — redact mode
# ===========================================================================

class TestRedactMode:
    def _make(self, **kw):
        return Redactor(PIIDetector(**kw), mode="redact")

    def test_email_replaced(self):
        r = self._make()
        result = r.redact("Contact alice@example.com.")
        assert "alice@example.com" not in result.sanitized_text
        assert "[EMAIL]" in result.sanitized_text

    def test_multiple_replaced(self):
        r = self._make()
        result = r.redact("alice@x.com or bob@y.com")
        assert "alice@x.com" not in result.sanitized_text
        assert "bob@y.com" not in result.sanitized_text

    def test_clean_text_unchanged(self):
        r = self._make()
        result = r.redact("Nothing sensitive here.")
        assert not result.was_modified
        assert result.events == []

    def test_audit_events_have_hash_not_raw(self):
        r = self._make()
        result = r.redact("alice@example.com")
        assert result.events
        assert "alice@example.com" not in result.events[0].original_hash
        assert len(result.events[0].original_hash) == 64  # SHA-256 hex

    def test_custom_label(self):
        r = Redactor(PIIDetector(), mode="redact", custom_labels={"EMAIL": "<<<EMAIL>>>"})
        result = r.redact("Send to alice@x.com")
        assert "<<<EMAIL>>>" in result.sanitized_text

    def test_was_modified_flag(self):
        r = self._make()
        assert r.redact("alice@x.com").was_modified is True
        assert r.redact("nothing here").was_modified is False


# ===========================================================================
# Redactor — pseudonymize mode
# ===========================================================================

class TestPseudonymizeMode:
    def _make(self):
        return Redactor(PIIDetector(), mode="pseudonymize")

    def test_email_gets_token(self):
        r = self._make()
        result = r.redact("Contact alice@example.com.")
        assert "EMAIL_01" in result.sanitized_text

    def test_same_value_same_token(self):
        r = self._make()
        result = r.redact("alice@x.com and alice@x.com again")
        assert result.sanitized_text.count("EMAIL_01") == 2

    def test_different_values_different_tokens(self):
        r = self._make()
        r.redact("alice@x.com")
        r.redact("bob@y.com")
        assert "EMAIL_01" in r.token_map.values()
        assert "EMAIL_02" in r.token_map.values()

    def test_token_map_resets(self):
        r = self._make()
        r.redact("alice@x.com")
        r.reset_token_map()
        result = r.redact("alice@x.com")
        assert "EMAIL_01" in result.sanitized_text

    def test_cross_file_consistency(self):
        """Same email in two files should get the same placeholder."""
        r = self._make()
        r1 = r.redact("alice@x.com in file1")
        r2 = r.redact("alice@x.com in file2")
        assert r1.sanitized_text.split()[0] == r2.sanitized_text.split()[0]


# ===========================================================================
# Redactor — block mode
# ===========================================================================

class TestBlockMode:
    def _make(self):
        return Redactor(PIIDetector(), mode="block")

    def test_pii_record_blocked(self):
        r = self._make()
        result = r.redact("alice@example.com is here")
        assert result.blocked is True
        assert "[RECORD BLOCKED" in result.sanitized_text

    def test_clean_record_passes(self):
        r = self._make()
        result = r.redact("This is fine.")
        assert result.blocked is False
        assert result.sanitized_text == "This is fine."

    def test_block_events_generated(self):
        r = self._make()
        result = r.redact("SSN 123-45-6789")
        assert result.events


# ===========================================================================
# File processors
# ===========================================================================

class TestTextProcessor:
    def test_sanitizes_text_file(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("Email alice@x.com for info.\nClean line here.\n")
        out = tmp_path / "output.txt"
        redactor = Redactor(PIIDetector(), mode="redact")
        events = process_file(src, out, redactor)
        sanitized = out.read_text()
        assert "alice@x.com" not in sanitized
        assert "[EMAIL]" in sanitized
        assert len(events) >= 1

    def test_clean_file_unchanged(self, tmp_path):
        src = tmp_path / "clean.txt"
        src.write_text("Nothing to see here.\n")
        out = tmp_path / "clean_out.txt"
        events = process_file(src, out, Redactor(PIIDetector(), mode="redact"))
        assert events == []
        assert out.read_text() == "Nothing to see here.\n"


class TestCSVProcessor:
    def test_sanitizes_csv(self, tmp_path):
        src = tmp_path / "data.csv"
        src.write_text("name,email,notes\nAlice,alice@x.com,hello\nBob,bob@y.com,world\n")
        out = tmp_path / "out.csv"
        events = process_file(src, out, Redactor(PIIDetector(), mode="pseudonymize"))
        rows = list(csv.reader(out.read_text().splitlines()))
        assert rows[0] == ["name", "email", "notes"]     # header unchanged
        assert "alice@x.com" not in rows[1][1]
        assert len(events) >= 2

    def test_header_preserved(self, tmp_path):
        src = tmp_path / "h.csv"
        src.write_text("id,email\n1,a@b.com\n")
        out = tmp_path / "h_out.csv"
        process_file(src, out, Redactor(PIIDetector(), mode="redact"))
        rows = list(csv.reader(out.read_text().splitlines()))
        assert rows[0] == ["id", "email"]

    def test_block_mode_csv(self, tmp_path):
        src = tmp_path / "block.csv"
        src.write_text("name,email\nAlice,alice@x.com\nBob,clean@row.invalid\n")
        out = tmp_path / "block_out.csv"
        process_file(src, out, Redactor(PIIDetector(), mode="block"))
        content = out.read_text()
        assert "BLOCKED" in content


class TestJSONProcessor:
    def test_sanitizes_json_strings(self, tmp_path):
        src = tmp_path / "data.json"
        src.write_text(json.dumps({"user": "alice@x.com", "age": 30}))
        out = tmp_path / "out.json"
        events = process_file(src, out, Redactor(PIIDetector(), mode="redact"))
        data = json.loads(out.read_text())
        assert "alice@x.com" not in data["user"]
        assert data["age"] == 30  # non-string preserved

    def test_nested_json(self, tmp_path):
        src = tmp_path / "nested.json"
        src.write_text(json.dumps({"a": {"b": {"email": "x@y.com"}}}))
        out = tmp_path / "nested_out.json"
        process_file(src, out, Redactor(PIIDetector(), mode="redact"))
        data = json.loads(out.read_text())
        assert "x@y.com" not in data["a"]["b"]["email"]

    def test_json_array(self, tmp_path):
        src = tmp_path / "arr.json"
        src.write_text(json.dumps([{"e": "a@b.com"}, {"e": "clean"}]))
        out = tmp_path / "arr_out.json"
        process_file(src, out, Redactor(PIIDetector(), mode="redact"))
        data = json.loads(out.read_text())
        assert "a@b.com" not in data[0]["e"]
        assert data[1]["e"] == "clean"

    def test_invalid_json_raises(self, tmp_path):
        src = tmp_path / "bad.json"
        src.write_text("not { valid json")
        out = tmp_path / "bad_out.json"
        with pytest.raises(ValueError, match="Invalid JSON"):
            process_file(src, out, Redactor(PIIDetector(), mode="redact"))


# ===========================================================================
# Audit report
# ===========================================================================

class TestAuditReport:
    def _make_events(self):
        r = Redactor(PIIDetector(), mode="redact")
        result = r.redact("alice@x.com and SSN 123-45-6789")
        for e in result.events:
            e.source_file = "test.txt"
            e.line_number = 1
        return result.events

    def test_json_report_written(self, tmp_path):
        path = tmp_path / "report.json"
        events = self._make_events()
        write_audit_report(events, path, fmt="json", mode="redact", input_path="test.txt")
        assert path.exists()
        data = json.loads(path.read_text())
        assert "summary" in data
        assert "events" in data
        assert data["summary"]["total_interceptions"] == len(events)

    def test_json_report_no_raw_pii(self, tmp_path):
        path = tmp_path / "report.json"
        events = self._make_events()
        write_audit_report(events, path, fmt="json", mode="redact", input_path="test.txt")
        content = path.read_text()
        assert "alice@x.com" not in content
        assert "123-45-6789" not in content

    def test_csv_report_written(self, tmp_path):
        path = tmp_path / "report.csv"
        events = self._make_events()
        write_audit_report(events, path, fmt="csv", mode="redact", input_path="test.txt")
        assert path.exists()
        rows = list(csv.DictReader(path.read_text().splitlines()))
        assert len(rows) == len(events)
        assert "entity_type" in rows[0]
        assert "original_value_hash" in rows[0]

    def test_summary_by_entity_type(self, tmp_path):
        path = tmp_path / "report.json"
        events = self._make_events()
        write_audit_report(events, path, fmt="json", mode="redact", input_path="test.txt")
        data = json.loads(path.read_text())
        assert "by_entity_type" in data["summary"]

    def test_empty_events(self, tmp_path):
        path = tmp_path / "empty.json"
        write_audit_report([], path, fmt="json", mode="redact", input_path="clean.txt")
        data = json.loads(path.read_text())
        assert data["summary"]["total_interceptions"] == 0
        assert data["events"] == []


# ===========================================================================
# Policy loader
# ===========================================================================

class TestPolicy:
    def test_default_policy(self):
        p = load_policy(None)
        assert p.mode == "redact"
        assert p.output_format == "json"

    def test_load_yaml_policy(self, tmp_path):
        f = tmp_path / "policy.yaml"
        f.write_text("mode: pseudonymize\nentity_types:\n  - EMAIL\noutput_format: csv\n")
        p = load_policy(f)
        assert p.mode == "pseudonymize"
        assert p.entity_types == ["EMAIL"]
        assert p.output_format == "csv"

    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            Policy(mode="destroy")

    def test_missing_policy_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_policy(tmp_path / "nonexistent.yaml")

    def test_extra_patterns_loaded(self, tmp_path):
        f = tmp_path / "p.yaml"
        f.write_text("extra_patterns:\n  EMP_ID: 'EMP-\\d{4}'\n")
        p = load_policy(f)
        assert "EMP_ID" in p.extra_patterns


# ===========================================================================
# CLI — sanitize command
# ===========================================================================

class TestCLISanitize:
    def test_sanitize_single_txt_file(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("Email alice@example.com for help.")
        out = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--mode", "redact", "--quiet",
        ])
        assert result.exit_code == 0
        sanitized = (out / "input.txt").read_text()
        assert "alice@example.com" not in sanitized

    def test_sanitize_csv(self, tmp_path):
        src = tmp_path / "data.csv"
        src.write_text("name,email\nAlice,alice@x.com\n")
        out = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--mode", "pseudonymize", "--quiet",
        ])
        assert result.exit_code == 0
        rows = list(csv.reader((out / "data.csv").read_text().splitlines()))
        assert "alice@x.com" not in rows[1][1]

    def test_sanitize_json(self, tmp_path):
        src = tmp_path / "data.json"
        src.write_text(json.dumps({"email": "a@b.com"}))
        out = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--mode", "redact", "--quiet",
        ])
        assert result.exit_code == 0
        data = json.loads((out / "data.json").read_text())
        assert "a@b.com" not in data["email"]

    def test_sanitize_directory(self, tmp_path):
        d = tmp_path / "inputs"
        d.mkdir()
        (d / "a.txt").write_text("alice@x.com")
        (d / "b.txt").write_text("bob@y.com")
        out = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "sanitize", "--input", str(d), "--output", str(out),
            "--mode", "redact", "--quiet",
        ])
        assert result.exit_code == 0
        assert "alice@x.com" not in (out / "a.txt").read_text()
        assert "bob@y.com"   not in (out / "b.txt").read_text()

    def test_audit_report_created(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("alice@x.com")
        out = tmp_path / "out"
        runner = CliRunner()
        runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--mode", "redact", "--quiet",
        ])
        assert (out / "audit_report.json").exists()

    def test_audit_report_csv_format(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("alice@x.com")
        out = tmp_path / "out"
        runner = CliRunner()
        runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--mode", "redact", "--audit-format", "csv", "--quiet",
        ])
        assert (out / "audit_report.csv").exists()

    def test_custom_audit_report_path(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("alice@x.com")
        out = tmp_path / "out"
        report = tmp_path / "my_audit.json"
        runner = CliRunner()
        runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--mode", "redact", "--audit-report", str(report), "--quiet",
        ])
        assert report.exists()

    def test_with_policy_file(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("alice@x.com and SSN 123-45-6789")
        out = tmp_path / "out"
        policy = tmp_path / "policy.yaml"
        policy.write_text("mode: pseudonymize\nentity_types:\n  - EMAIL\n")
        runner = CliRunner()
        result = runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out),
            "--policy", str(policy), "--quiet",
        ])
        assert result.exit_code == 0
        text = (out / "input.txt").read_text()
        assert "alice@x.com" not in text
        # SSN not in entity_types list → should survive
        assert "123-45-6789" in text

    def test_shows_summary_output(self, tmp_path):
        src = tmp_path / "input.txt"
        src.write_text("alice@x.com")
        out = tmp_path / "out"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "sanitize", "--input", str(src), "--output", str(out), "--mode", "redact",
        ])
        assert "Files processed" in result.output
        assert "Total PII hits" in result.output


# ===========================================================================
# CLI — scan command
# ===========================================================================

class TestCLIScan:
    def test_scan_shows_detections(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_text("alice@example.com is here\nnothing here\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--input", str(src)])
        assert result.exit_code == 0
        assert "EMAIL" in result.output
        assert "alice@example.com" in result.output

    def test_scan_clean_file(self, tmp_path):
        src = tmp_path / "clean.txt"
        src.write_text("All clear, no PII here.\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--input", str(src)])
        assert "No PII detected" in result.output

    def test_scan_does_not_write_output(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_text("alice@x.com")
        files_before = list(tmp_path.iterdir())
        runner = CliRunner()
        runner.invoke(cli, ["scan", "--input", str(src)])
        files_after = list(tmp_path.iterdir())
        assert len(files_after) == len(files_before)  # no new files written

    def test_scan_entity_filter(self, tmp_path):
        src = tmp_path / "data.txt"
        src.write_text("alice@x.com and SSN 123-45-6789")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--input", str(src), "--entity-types", "EMAIL"])
        assert "EMAIL" in result.output
        assert "SSN" not in result.output
