"""
pii_safe_cli/redactor.py
=========================
Three redaction modes:

  redact       — replace PII with a static label:  [EMAIL]
  pseudonymize — replace with session token:        EMAIL_01
  block        — refuse to process the record entirely if PII found

All modes return a RedactionResult so callers can produce audit reports.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple

from pii_safe_cli.detector import Detection, DetectionResult, PIIDetector

Mode = Literal["redact", "pseudonymize", "block"]


@dataclass
class RedactionEvent:
    """One PII replacement event, safe for audit logs (no raw PII stored)."""
    entity_type:        str
    original_hash:      str   # SHA-256 of raw value — never the value itself
    placeholder:        str
    start:              int
    end:                int
    line_number:        Optional[int] = None
    source_file:        Optional[str] = None


@dataclass
class RedactionResult:
    """Result of redacting a single piece of text."""
    original_text:  str
    sanitized_text: str
    mode:           Mode
    blocked:        bool = False
    events:         List[RedactionEvent] = field(default_factory=list)

    @property
    def was_modified(self) -> bool:
        return self.original_text != self.sanitized_text

    @property
    def entity_types_found(self) -> List[str]:
        return list({e.entity_type for e in self.events})


class Redactor:
    """
    Applies a chosen redaction mode to text, driven by a PIIDetector.

    Parameters
    ----------
    detector : PIIDetector
        Pre-configured detector instance.
    mode : {"redact", "pseudonymize", "block"}
    custom_labels : dict, optional
        Override default ``[ENTITY_TYPE]`` labels for redact mode.
    """

    def __init__(
        self,
        detector: PIIDetector,
        mode: Mode = "redact",
        custom_labels: Optional[Dict[str, str]] = None,
    ) -> None:
        self._detector = detector
        self._mode = mode
        self._custom_labels = custom_labels or {}
        # Pseudonymization state (per-session)
        self._token_map:   Dict[str, str] = {}   # real_value → placeholder
        self._counters:    Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(
        self,
        text: str,
        line_number: Optional[int] = None,
        source_file: Optional[str] = None,
    ) -> RedactionResult:
        result = self._detector.scan(text)

        if self._mode == "block":
            return self._block(text, result, line_number, source_file)
        elif self._mode == "pseudonymize":
            return self._pseudonymize(text, result, line_number, source_file)
        else:
            return self._redact(text, result, line_number, source_file)

    def reset_token_map(self) -> None:
        """Clear the pseudonymization session (call between unrelated files)."""
        self._token_map.clear()
        self._counters.clear()

    @property
    def token_map(self) -> Dict[str, str]:
        """Read-only view of the current pseudonymization map."""
        return dict(self._token_map)

    # ------------------------------------------------------------------
    # Internal mode implementations
    # ------------------------------------------------------------------

    def _redact(
        self,
        text: str,
        result: DetectionResult,
        line_number: Optional[int],
        source_file: Optional[str],
    ) -> RedactionResult:
        events: List[RedactionEvent] = []
        # Replace longest matches first to avoid partial overlaps
        sanitized, events = self._apply_replacements(
            text,
            result.detections,
            lambda d: self._custom_labels.get(d.entity_type, f"[{d.entity_type}]"),
            line_number,
            source_file,
        )
        return RedactionResult(
            original_text=text,
            sanitized_text=sanitized,
            mode="redact",
            events=events,
        )

    def _pseudonymize(
        self,
        text: str,
        result: DetectionResult,
        line_number: Optional[int],
        source_file: Optional[str],
    ) -> RedactionResult:
        def get_placeholder(d: Detection) -> str:
            if d.value in self._token_map:
                return self._token_map[d.value]
            idx = self._counters.get(d.entity_type, 0) + 1
            self._counters[d.entity_type] = idx
            placeholder = f"{d.entity_type}_{idx:02d}"
            self._token_map[d.value] = placeholder
            return placeholder

        sanitized, events = self._apply_replacements(
            text, result.detections, get_placeholder, line_number, source_file
        )
        return RedactionResult(
            original_text=text,
            sanitized_text=sanitized,
            mode="pseudonymize",
            events=events,
        )

    def _block(
        self,
        text: str,
        result: DetectionResult,
        line_number: Optional[int],
        source_file: Optional[str],
    ) -> RedactionResult:
        if not result.has_pii:
            return RedactionResult(
                original_text=text,
                sanitized_text=text,
                mode="block",
                blocked=False,
            )
        events = [
            RedactionEvent(
                entity_type=d.entity_type,
                original_hash=hashlib.sha256(d.value.encode()).hexdigest(),
                placeholder="[BLOCKED]",
                start=d.start,
                end=d.end,
                line_number=line_number,
                source_file=source_file,
            )
            for d in result.detections
        ]
        return RedactionResult(
            original_text=text,
            sanitized_text="[RECORD BLOCKED — PII DETECTED]",
            mode="block",
            blocked=True,
            events=events,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _apply_replacements(
        self,
        text: str,
        detections: List[Detection],
        placeholder_fn,
        line_number: Optional[int],
        source_file: Optional[str],
    ) -> Tuple[str, List[RedactionEvent]]:
        """Apply all replacements, longest-match-first, left-to-right."""
        events: List[RedactionEvent] = []
        # Work on unique values, longest first to prevent partial matches
        seen: Dict[str, str] = {}
        for d in sorted(detections, key=lambda x: len(x.value), reverse=True):
            if d.value not in seen:
                seen[d.value] = placeholder_fn(d)

        sanitized = text
        for raw_value, placeholder in sorted(seen.items(), key=lambda x: len(x[0]), reverse=True):
            if raw_value in sanitized:
                sanitized = sanitized.replace(raw_value, placeholder)
                # Find original position in the *original* text for the audit log
                idx = text.find(raw_value)
                events.append(RedactionEvent(
                    entity_type=next(
                        d.entity_type for d in detections if d.value == raw_value
                    ),
                    original_hash=hashlib.sha256(raw_value.encode()).hexdigest(),
                    placeholder=placeholder,
                    start=idx,
                    end=idx + len(raw_value),
                    line_number=line_number,
                    source_file=source_file,
                ))
        return sanitized, events
