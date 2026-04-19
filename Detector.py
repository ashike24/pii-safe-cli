"""
pii_safe_cli/detector.py
=========================
Tiered PII detection engine.

Tier 1 — Regex patterns for deterministic entities (EMAIL, PHONE, SSN, etc.)
Tier 2 — Extensible: callers can register custom patterns at runtime.

Designed to be backend-agnostic so it works standalone (CLI) or wired to
the FastAPI policy engine when a server URL is configured.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Pattern


# ---------------------------------------------------------------------------
# Built-in pattern registry
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: Dict[str, str] = {
    "EMAIL":       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "SSN":         r"\b\d{3}-\d{2}-\d{4}\b",
    "PHONE":       r"(?<!\d)(?:\+?\d[\d\-\s().]{7,}\d)(?!\d)",
    "CREDIT_CARD": r"\b(?:\d[ \-]?){13,16}\b",
    "IP_ADDR":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "DATE":        r"\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}-\d{2}-\d{2})\b",
    "ZIP_CODE":    r"\b\d{5}(?:-\d{4})?\b",
    "URL":         r"https?://[^\s\"'<>]+",
}


@dataclass
class Detection:
    """A single PII match inside a string."""
    entity_type: str
    value:       str
    start:       int
    end:         int


@dataclass
class DetectionResult:
    """All detections for one piece of text."""
    text:       str
    detections: List[Detection] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return bool(self.detections)

    @property
    def entity_types(self) -> List[str]:
        return list({d.entity_type for d in self.detections})


class PIIDetector:
    """
    Scans text for PII using compiled regex patterns.

    Parameters
    ----------
    entity_types : list of str, optional
        Subset of entity types to scan for.  Defaults to all built-ins.
    extra_patterns : dict, optional
        Additional ``{entity_type: regex_string}`` entries.
    """

    def __init__(
        self,
        entity_types: Optional[List[str]] = None,
        extra_patterns: Optional[Dict[str, str]] = None,
    ) -> None:
        all_patterns = {**_BUILTIN_PATTERNS, **(extra_patterns or {})}
        if entity_types:
            all_patterns = {k: v for k, v in all_patterns.items() if k in entity_types}
        self._compiled: Dict[str, Pattern] = {
            k: re.compile(v) for k, v in all_patterns.items()
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, text: str) -> DetectionResult:
        """Return all PII detections in *text*, ordered by position."""
        detections: List[Detection] = []
        for entity_type, pattern in self._compiled.items():
            for match in pattern.finditer(text):
                detections.append(Detection(
                    entity_type=entity_type,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                ))
        detections.sort(key=lambda d: d.start)
        return DetectionResult(text=text, detections=detections)

    def scan_lines(self, text: str) -> Iterator[tuple[int, DetectionResult]]:
        """Yield ``(line_number, DetectionResult)`` for every line."""
        for i, line in enumerate(text.splitlines(), start=1):
            yield i, self.scan(line)

    @property
    def entity_types(self) -> List[str]:
        return list(self._compiled.keys())
