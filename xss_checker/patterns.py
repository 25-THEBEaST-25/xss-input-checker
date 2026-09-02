"""Signature definitions used to detect XSS payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .severity import Severity


@dataclass(frozen=True)
class Pattern:
    """A single XSS signature."""

    id: str
    name: str
    severity: Severity
    regex: re.Pattern[str]
    description: str


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        id="script-tag",
        name="Script tag",
        severity=Severity.CRITICAL,
        regex=_compile(r"<\s*/?\s*script\b[^>]*>"),
        description="Inline <script> element that executes attacker-controlled code.",
    ),
    Pattern(
        id="dangerous-tag",
        name="Dangerous HTML tag",
        severity=Severity.HIGH,
        regex=_compile(
            r"<\s*(iframe|object|embed|svg|math|link|meta|base|form|template|portal)\b[^>]*>"
        ),
        description="Tag commonly abused to load or execute remote content.",
    ),
    Pattern(
        id="event-handler",
        name="Inline event handler",
        severity=Severity.HIGH,
        regex=_compile(r"\bon[a-z]{3,}\s*=\s*(?:[\"'][^\"']*[\"']|[^\s>]+)"),
        description="HTML attribute such as onerror/onload that runs JavaScript.",
    ),
    Pattern(
        id="js-uri",
        name="JavaScript URI",
        severity=Severity.CRITICAL,
        regex=_compile(r"\bj\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:"),
        description="javascript: URI, including whitespace-obfuscated variants.",
    ),
    Pattern(
        id="vbscript-uri",
        name="VBScript URI",
        severity=Severity.HIGH,
        regex=_compile(r"\bvbscript\s*:"),
        description="Legacy vbscript: URI executed by older browsers.",
    ),
    Pattern(
        id="data-uri-html",
        name="HTML data URI",
        severity=Severity.HIGH,
        regex=_compile(r"data\s*:\s*[^,;]*(?:html|javascript|xml)[^,]*,"),
        description="data: URI carrying markup or script payloads.",
    ),
    Pattern(
        id="srcdoc",
        name="iframe srcdoc",
        severity=Severity.HIGH,
        regex=_compile(r"\bsrcdoc\s*="),
        description="srcdoc attribute embedding an inline HTML document.",
    ),
    Pattern(
        id="js-sink",
        name="JavaScript execution sink",
        severity=Severity.HIGH,
        regex=_compile(
            r"\b(eval|setTimeout|setInterval|Function|execScript|"
            r"document\s*\.\s*write(?:ln)?|insertAdjacentHTML|"
            r"(?:inner|outer)HTML)\s*(?:\(|=)"
        ),
        description="Call or assignment that turns a string into executable code or markup.",
    ),
    Pattern(
        id="expression",
        name="CSS expression",
        severity=Severity.MEDIUM,
        regex=_compile(r"\bexpression\s*\("),
        description="Legacy CSS expression() used for script execution.",
    ),
    Pattern(
        id="css-import",
        name="CSS import or url()",
        severity=Severity.MEDIUM,
        regex=_compile(r"@\s*import\b|\burl\s*\(\s*[\"']?\s*(?:javascript|data)\s*:"),
        description="Stylesheet directive pulling in attacker-controlled resources.",
    ),
    Pattern(
        id="entity-escape",
        name="Encoded markup",
        severity=Severity.MEDIUM,
        regex=_compile(r"&#x?[0-9a-f]{2,6};?|%3c\s*/?\s*\w|\\u00[36]|\\x[36][ce]"),
        description="HTML, URL or unicode escapes hiding markup characters.",
    ),
    Pattern(
        id="html-injection",
        name="Raw HTML injection",
        severity=Severity.LOW,
        regex=_compile(r"<\s*/?\s*[a-z][a-z0-9-]*\b[^>]*>"),
        description="Raw HTML tag; unsafe when reflected without escaping.",
    ),
    Pattern(
        id="attribute-breakout",
        name="Attribute breakout",
        severity=Severity.MEDIUM,
        regex=_compile(r"[\"'][\s/]*>|[\"'][^\"'<>]{0,40}[\"']\s*(?:>|\bon[a-z]{3,}\s*=)"),
        description="Quote sequence that escapes an HTML attribute context.",
    ),
    Pattern(
        id="null-byte",
        name="Control character",
        severity=Severity.MEDIUM,
        regex=_compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),
        description="Control characters used to break naive sanitizers.",
    ),
)

PATTERNS_BY_ID: dict[str, Pattern] = {pattern.id: pattern for pattern in PATTERNS}
