"""
pii_safe_cli/policy.py
=======================
Loads and validates a YAML policy file (compatible with the PII-Safe
FastAPI backend policy engine format).

If no policy file is given, safe defaults are used.

Policy file example (policy.yaml):
------------------------------------
mode: pseudonymize                  # redact | pseudonymize | block
entity_types:                       # leave empty for all
  - EMAIL
  - SSN
  - PHONE
output_format: json                 # json | csv (for audit report)
extra_patterns:                     # custom regex patterns
  EMPLOYEE_ID: "EMP-\\d{6}"
  PROJECT_CODE: "PRJ-[A-Z]{3}-\\d{4}"
api_url: http://localhost:8000      # optional: delegate to FastAPI backend
------------------------------------
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


@dataclass
class Policy:
    mode:           str                  = "redact"
    entity_types:   List[str]            = field(default_factory=list)
    output_format:  str                  = "json"
    extra_patterns: Dict[str, str]       = field(default_factory=dict)
    api_url:        Optional[str]        = None

    def __post_init__(self) -> None:
        valid_modes = {"redact", "pseudonymize", "block"}
        if self.mode not in valid_modes:
            raise ValueError(f"Invalid mode '{self.mode}'. Choose from: {valid_modes}")
        valid_fmts = {"json", "csv"}
        if self.output_format not in valid_fmts:
            raise ValueError(f"Invalid output_format '{self.output_format}'. Choose from: {valid_fmts}")


def load_policy(policy_path: Optional[Path] = None) -> Policy:
    """
    Load policy from a YAML file, or return default Policy if path is None.

    Raises
    ------
    FileNotFoundError  : if policy_path is specified but doesn't exist.
    ValueError         : if the YAML contains invalid values.
    ImportError        : if PyYAML is not installed and a policy file is given.
    """
    if policy_path is None:
        return Policy()

    if not policy_path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")

    if not _HAS_YAML:
        raise ImportError(
            "PyYAML is required to load policy files: pip install pyyaml"
        )

    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}

    return Policy(
        mode           = raw.get("mode", "redact"),
        entity_types   = raw.get("entity_types") or [],
        output_format  = raw.get("output_format", "json"),
        extra_patterns = raw.get("extra_patterns") or {},
        api_url        = raw.get("api_url"),
    )
