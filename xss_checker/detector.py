"""Scanning engine: normalizes input and matches it against XSS signatures."""

from __future__ import annotations

import html
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_plus

from .patterns import PATTERNS, Pattern
from .severity import Severity

MAX_DECODE_ROUNDS = 3
MAX_MATCH_PREVIEW = 120

_ESCAPE_SEQUENCE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u\{?([0-9a-fA-F]{4,6})\}?)")


@dataclass(frozen=True)
class Finding:
    """A single signature match against one representation of the input."""

    pattern_id: str
    name: str
    severity: Severity
    description: str
    matched: str
    start: int
    end: int
    layer: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "matched": self.matched,
            "start": self.start,
            "end": self.end,
            "layer": self.layer,
        }


@dataclass(frozen=True)
class ScanResult:
    """Outcome of scanning one input string."""

    value: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def is_malicious(self) -> bool:
        return bool(self.findings)

    @property
    def severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.value,
            "malicious": self.is_malicious,
            "severity": self.severity.value if self.severity else None,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _decode_escapes(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        code = match.group(1) or match.group(2)
        try:
            return chr(int(code, 16))
        except (ValueError, OverflowError):
            return match.group(0)

    return _ESCAPE_SEQUENCE.sub(replace, value)


def normalize(value: str) -> list[tuple[str, str]]:
    """Return labelled representations of ``value`` to scan.

    Attackers hide payloads behind URL, HTML entity, unicode escape and
    compatibility encodings, so every decoded layer is scanned as well as the
    raw input. Identical layers are collapsed.
    """
    layers: list[tuple[str, str]] = [("raw", value)]
    seen = {value}
    current = value

    for round_index in range(1, MAX_DECODE_ROUNDS + 1):
        expanded = _decode_escapes(html.unescape(unquote_plus(current)))
        decoded = unicodedata.normalize("NFKC", expanded).replace("\x00", "")
        if decoded == current:
            break
        current = decoded
        if decoded not in seen:
            seen.add(decoded)
            layers.append((f"decoded:{round_index}", decoded))

    return layers


def _scan_layer(pattern: Pattern, layer: str, text: str) -> list[Finding]:
    findings = []
    for match in pattern.regex.finditer(text):
        findings.append(
            Finding(
                pattern_id=pattern.id,
                name=pattern.name,
                severity=pattern.severity,
                description=pattern.description,
                matched=match.group(0)[:MAX_MATCH_PREVIEW],
                start=match.start(),
                end=match.end(),
                layer=layer,
            )
        )
    return findings


def scan(
    value: str,
    *,
    patterns: Sequence[Pattern] = PATTERNS,
    min_severity: Severity = Severity.LOW,
    decode: bool = True,
) -> ScanResult:
    """Scan ``value`` and return every signature match at or above ``min_severity``."""
    if not isinstance(value, str):
        raise TypeError(f"expected str, got {type(value).__name__}")

    layers = normalize(value) if decode else [("raw", value)]
    findings: list[Finding] = []
    for pattern in patterns:
        if pattern.severity < min_severity:
            continue
        for layer, text in layers:
            findings.extend(_scan_layer(pattern, layer, text))

    findings.sort(key=lambda finding: (-finding.severity.rank, finding.layer, finding.start))
    return ScanResult(value=value, findings=tuple(findings))


def is_malicious(value: str, *, min_severity: Severity = Severity.LOW) -> bool:
    """Return ``True`` when ``value`` matches any signature at or above ``min_severity``."""
    return scan(value, min_severity=min_severity).is_malicious


def scan_all(values: Iterable[str], *, min_severity: Severity = Severity.LOW) -> list[ScanResult]:
    """Scan each value in ``values``."""
    return [scan(value, min_severity=min_severity) for value in values]
