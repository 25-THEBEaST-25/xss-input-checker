from __future__ import annotations

import pytest

from xss_checker import Severity, is_malicious, normalize, scan

MALICIOUS = [
    "<script>alert(1)</script>",
    "<SCRIPT SRC=//evil.tld/x.js></SCRIPT>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '<iframe src="javascript:alert(1)"></iframe>',
    "java\tscript:alert(1)",
    "<a href='vbscript:msgbox(1)'>x</a>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "data:text/html,<script>alert(1)</script>",
    "document.write('<img src=x onerror=alert(1)>')",
    "el.innerHTML = userInput",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    '<div style="width:expression(alert(1))">x</div>',
    '" onmouseover="alert(1)',
    "<body onload=alert('xss')>",
    'foo"><script>alert(1)</script>',
    "<math><mtext><script>alert(1)</script></mtext></math>",
    '<base href="javascript:alert(1)//">',
    '<form action="javascript:alert(1)"><input type=submit></form>',
    "@import url(javascript:alert(1));",
    "background:url('data:text/html,<script>alert(1)</script>')",
]

BENIGN = [
    "hello world",
    "Aryan Wesavkar",
    "2 < 3 and 5 > 4",
    "SELECT * FROM users WHERE id = 1",
    "email@example.com",
    "it's a test",
    "price is $5 (discount: 10%)",
    "C:\\Users\\aryan\\file.txt",
    "https://example.com/path?query=value&other=1",
]

# Legitimate, non-scripting HTML that a naive checker could easily misflag.
# These must NOT be treated as malicious: a static checker that can't tell
# a normal <b>/<a href>/<img src> from an attack payload is useless for any
# real page containing ordinary markup (comments, rich text fields, etc).
BENIGN_HTML = [
    "<b>bold</b>",
    "<i>italic</i> and <u>underline</u>",
    '<a href="https://example.com">a normal link</a>',
    '<a href="mailto:person@example.com">email me</a>',
    '<img src="cat.jpg" alt="a cat">',
    '<img src="https://cdn.example.com/logo.png" width="200" height="100"/>',
    "<p>Some <strong>legit</strong> markup.</p>",
    "<ul><li>Item one</li><li>Item two</li></ul>",
    '<div class="card"><h2>Title</h2><p>Body text.</p></div>',
    "<blockquote>A quoted sentence.</blockquote>",
]


@pytest.mark.parametrize("payload", MALICIOUS)
def test_detects_malicious_payloads(payload: str) -> None:
    result = scan(payload)
    assert result.is_malicious, payload
    assert result.severity is not None


@pytest.mark.parametrize("payload", BENIGN)
def test_allows_benign_input(payload: str) -> None:
    assert not scan(payload).is_malicious, payload


@pytest.mark.parametrize("payload", BENIGN_HTML)
def test_does_not_flag_legitimate_non_scripting_html(payload: str) -> None:
    """False-positive guard: ordinary formatting/markup must scan clean.

    A checker that treats every <b>, <a href> or <img src> as an attack is
    unusable for anything that legitimately contains HTML (comments, rich
    text, templated pages), so this is verified explicitly and separately
    from the general BENIGN corpus above.
    """
    result = scan(payload)
    assert not result.is_malicious, (payload, [f.pattern_id for f in result.findings])


def test_empty_input_is_clean() -> None:
    result = scan("")
    assert not result.is_malicious
    assert result.severity is None
    assert result.findings == ()


def test_reports_matching_pattern_and_offsets() -> None:
    result = scan("<img src=x onerror=alert(1)>")
    ids = {finding.pattern_id for finding in result.findings}
    assert "event-handler" in ids
    handler = next(f for f in result.findings if f.pattern_id == "event-handler")
    assert handler.matched.startswith("onerror=")
    assert result.value[handler.start : handler.end] == handler.matched


def test_findings_sorted_by_descending_severity() -> None:
    findings = scan("<script>alert(1)</script>").findings
    ranks = [finding.severity.rank for finding in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_severity_is_the_maximum_of_findings() -> None:
    assert scan("<script>alert(1)</script>").severity is Severity.CRITICAL
    assert scan("width:expression(alert(1))").severity is Severity.MEDIUM


def test_min_severity_filters_low_signal_findings() -> None:
    assert scan("width:expression(alert(1))", min_severity=Severity.HIGH).is_malicious is False
    assert scan("<script>x</script>", min_severity=Severity.HIGH).is_malicious is True


def test_decode_can_be_disabled() -> None:
    encoded = "%3Cscript%3Ealert(1)%3C/script%3E"
    assert scan(encoded, decode=False).severity is not Severity.CRITICAL
    assert scan(encoded).severity is Severity.CRITICAL


def test_normalize_collapses_identical_layers() -> None:
    assert normalize("plain text") == [("raw", "plain text")]
    layers = normalize("%3Cscript%3E")
    assert [name for name, _ in layers] == ["raw", "decoded:1"]
    assert layers[1][1] == "<script>"


def test_normalize_strips_null_bytes() -> None:
    assert scan("<scr\x00ipt>alert(1)</script>").is_malicious


def test_scan_rejects_non_string_input() -> None:
    with pytest.raises(TypeError):
        scan(123)  # type: ignore[arg-type]


def test_is_malicious_helper_matches_scan() -> None:
    assert is_malicious("<script>alert(1)</script>")
    assert not is_malicious("hello")


def test_result_serializes_to_json_friendly_dict() -> None:
    payload = scan("<script>alert(1)</script>").to_dict()
    assert payload["malicious"] is True
    assert payload["severity"] == "critical"
    assert payload["findings"][0]["pattern_id"]
    assert isinstance(payload["findings"][0]["severity"], str)


def test_severity_parsing_and_ordering() -> None:
    assert Severity.parse("HIGH ") is Severity.HIGH
    assert Severity.LOW < Severity.CRITICAL
    with pytest.raises(ValueError):
        Severity.parse("extreme")


def test_every_finding_carries_actionable_remediation() -> None:
    for payload in MALICIOUS:
        for finding in scan(payload).findings:
            assert finding.remediation, finding.pattern_id
            assert len(finding.remediation) > 20, finding.pattern_id


def test_every_pattern_has_unique_remediation_text() -> None:
    from xss_checker.patterns import PATTERNS

    remediations = [pattern.remediation for pattern in PATTERNS]
    assert len(remediations) == len(set(remediations))


def test_remediation_included_in_serialized_finding() -> None:
    finding = scan("<script>alert(1)</script>").findings[0]
    assert finding.to_dict()["remediation"] == finding.remediation
