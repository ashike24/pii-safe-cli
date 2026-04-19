# PII-Safe CLI — Batch Dataset PII Sanitization

**Fixes:** [c2siorg/PII-Safe Issue #11](https://github.com/c2siorg/PII-Safe/issues/11)

A standalone CLI tool for batch sanitization of historical datasets before they are fed into LLM pipelines. Complements the real-time PII-Safe FastAPI middleware with an offline batch processing capability.

---

## Install

```bash
pip install .
# or in editable/dev mode:
pip install -e ".[dev]"
```

This registers the `pii-safe` command globally.

---

## Usage

### Sanitize a single file
```bash
pii-safe sanitize --input report.csv --mode pseudonymize
```

### Sanitize a directory (recursive)
```bash
pii-safe sanitize --input ./logs/ --output ./clean/ --mode redact
```

### Use a policy file
```bash
pii-safe sanitize --input ./logs/ --policy policy.yaml --output ./clean/
```

### Dry-run scan (no files modified)
```bash
pii-safe scan --input ./data/
```

### Filter entity types
```bash
pii-safe sanitize --input data.json --mode redact -e EMAIL -e SSN
```

### CSV audit report
```bash
pii-safe sanitize --input ./data/ --mode pseudonymize --audit-format csv
```

---

## Redaction Modes

| Mode | Behaviour | Example output |
|---|---|---|
| `redact` | Replace PII with a static label | `[EMAIL]`, `[SSN]` |
| `pseudonymize` | Replace with a session token (reversible via audit map) | `EMAIL_01`, `SSN_02` |
| `block` | Refuse to output the entire record if PII is detected | `[RECORD BLOCKED — PII DETECTED]` |

---

## Supported Formats

| Extension | Processor |
|---|---|
| `.csv` | Header preserved; each cell scanned independently |
| `.json` | Recursive walk of all string values; non-strings (int, bool) untouched |
| `.txt`, `.log`, `.text` | Line-by-line scanning |
| Any other extension | Treated as plain text |

---

## Built-in Entity Types

`EMAIL` · `SSN` · `PHONE` · `CREDIT_CARD` · `IP_ADDR` · `DATE` · `ZIP_CODE` · `URL`

Add custom patterns in `policy.yaml`:
```yaml
extra_patterns:
  EMPLOYEE_ID: "EMP-\\d{6}"
```

---

## Policy File

```yaml
# policy.yaml
mode: pseudonymize
entity_types:
  - EMAIL
  - SSN
output_format: json        # audit report format: json | csv
extra_patterns:
  EMPLOYEE_ID: "EMP-\\d{6}"
api_url: http://localhost:8000   # optional: delegate to FastAPI backend
```

---

## Audit Report

Every run produces a downloadable audit report alongside the sanitized output:

```
out/
├── data_sanitized.csv
└── audit_report.json      ← interceptions: entity type, hash, placeholder, line
```

The report **never stores raw PII** — only SHA-256 hashes of intercepted values.

JSON report structure:
```json
{
  "generated_at": "2026-04-18T...",
  "mode": "pseudonymize",
  "summary": {
    "total_interceptions": 42,
    "by_entity_type": {"EMAIL": 20, "SSN": 22},
    "by_file": {"data.csv": 42}
  },
  "events": [...]
}
```

---

## FastAPI Backend Integration

If the PII-Safe Docker stack (Issue #7) is running, add `api_url` to your policy file to delegate detection to the backend instead of the local regex engine:

```yaml
api_url: http://localhost:8000
```

---

## File Structure

```
pii_safe_cli/
├── __init__.py
├── cli.py          # Click commands: sanitize, scan
├── detector.py     # PIIDetector — regex engine + custom patterns
├── redactor.py     # Redactor — redact / pseudonymize / block
├── processors.py   # Format handlers: CSV, JSON, plain text
├── audit.py        # Audit report generator (JSON + CSV)
└── policy.py       # YAML policy loader
tests/
└── test_cli.py     # 56 tests across all modules
policy.yaml         # Example policy file
pyproject.toml      # Package config + CLI entrypoint
```

---

## Running Tests

```bash
pytest tests/ -v
```

**56 tests, all passing** across: detector, redactor (all 3 modes), file processors, audit report, policy loader, CLI commands.

---

## License

Apache 2.0 — consistent with the parent [PII-Safe](https://github.com/c2siorg/PII-Safe) project.
