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
    remediation: str


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        id="script-tag",
        name="Script tag",
        severity=Severity.CRITICAL,
        regex=_compile(r"<\s*/?\s*script\b[^>]*>"),
        description="Inline <script> element that executes attacker-controlled code.",
        remediation=(
            "HTML-escape output before rendering, or strip <script> with an allow-list "
            "HTML sanitizer (e.g. DOMPurify) — never render user input as markup directly."
        ),
    ),
    Pattern(
        id="dangerous-tag",
        name="Dangerous HTML tag",
        severity=Severity.HIGH,
        regex=_compile(
            r"<\s*(iframe|object|embed|svg|math|link|meta|base|form|template|portal)\b[^>]*>"
        ),
        description="Tag commonly abused to load or execute remote content.",
        remediation=(
            "Strip these tags with an allow-list HTML sanitizer; if legitimate, restrict "
            "their src/href/action to a trusted origin allow-list."
        ),
    ),
    Pattern(
        id="event-handler",
        name="Inline event handler",
        severity=Severity.HIGH,
        regex=_compile(r"\bon[a-z]{3,}\s*=\s*(?:[\"'][^\"']*[\"']|[^\s>]+)"),
        description="HTML attribute such as onerror/onload that runs JavaScript.",
        remediation=(
            "Strip on* attributes with an allow-list sanitizer and ship a CSP without "
            "'unsafe-inline' so inline handlers can't execute even if injected."
        ),
    ),
    Pattern(
        id="js-uri",
        name="JavaScript URI",
        severity=Severity.CRITICAL,
        regex=_compile(r"\bj\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:"),
        description="javascript: URI, including whitespace-obfuscated variants.",
        remediation=(
            "Validate URLs against an allow-list of schemes (http/https/mailto) before "
            "using them in href/src/location — reject javascript: outright."
        ),
    ),
    Pattern(
        id="vbscript-uri",
        name="VBScript URI",
        severity=Severity.HIGH,
        regex=_compile(r"\bvbscript\s*:"),
        description="Legacy vbscript: URI executed by older browsers.",
        remediation=(
            "Same fix as javascript: URIs — validate the URI scheme against an allow-list "
            "before using any user-supplied URL."
        ),
    ),
    Pattern(
        id="data-uri-html",
        name="HTML data URI",
        severity=Severity.HIGH,
        regex=_compile(r"data\s*:\s*[^,;]*(?:html|javascript|xml)[^,]*,"),
        description="data: URI carrying markup or script payloads.",
        remediation=(
            "Block data: URIs in user-controlled href/src, or restrict them to safe MIME "
            "types (e.g. image/png, image/jpeg) with an allow-list."
        ),
    ),
    Pattern(
        id="srcdoc",
        name="iframe srcdoc",
        severity=Severity.HIGH,
        regex=_compile(r"\bsrcdoc\s*="),
        description="srcdoc attribute embedding an inline HTML document.",
        remediation=(
            "Never set srcdoc from user input; if inline HTML is required, sanitize it "
            "first with an allow-list HTML sanitizer."
        ),
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
        remediation=(
            "Avoid eval/innerHTML/document.write on untrusted data; use textContent, an "
            "auto-escaping templating engine, or a sanitizer for any HTML you must render."
        ),
    ),
    Pattern(
        id="expression",
        name="CSS expression",
        severity=Severity.MEDIUM,
        regex=_compile(r"\bexpression\s*\("),
        description="Legacy CSS expression() used for script execution.",
        remediation=(
            "Reject CSS values containing expression(); modern browsers no longer support "
            "it, but block it as defense-in-depth for legacy rendering engines."
        ),
    ),
    Pattern(
        id="css-import",
        name="CSS import or url()",
        severity=Severity.MEDIUM,
        regex=_compile(r"@\s*import\b|\burl\s*\(\s*[\"']?\s*(?:javascript|data)\s*:"),
        description="Stylesheet directive pulling in attacker-controlled resources.",
        remediation=(
            "Strip or validate @import and url() values in user-supplied CSS; never let "
            "user input reach a stylesheet unsanitized."
        ),
    ),
    Pattern(
        id="entity-escape",
        name="Encoded markup",
        severity=Severity.MEDIUM,
        regex=_compile(r"&#x?[0-9a-f]{2,6};?|%3c\s*/?\s*\w|\\u00[36]|\\x[36][ce]"),
        description="HTML, URL or unicode escapes hiding markup characters.",
        remediation=(
            "Decode and re-scan before trusting: encoded input is likely hiding a payload "
            "from naive filters — normalize fully, then validate, don't just encode and stop."
        ),
    ),
    Pattern(
        id="null-byte",
        name="Control character",
        severity=Severity.MEDIUM,
        regex=_compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),
        description="Control characters used to break naive sanitizers.",
        remediation=(
            "Strip control characters before validation/storage; never pass them to "
            "downstream parsers."
        ),
    ),
)

PATTERNS_BY_ID: dict[str, Pattern] = {pattern.id: pattern for pattern in PATTERNS}
