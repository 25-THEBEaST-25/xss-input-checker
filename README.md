# XSS Input Checker 🔐

A Python library and CLI that flags common Cross-Site Scripting (XSS) payloads in untrusted input.

> Detection is a defence-in-depth signal, not a sanitizer. Always escape output with a
> context-aware encoder (or use a strict allow-list sanitizer) — never rely on pattern matching alone.

## Features

- Signature catalogue with severities (`low` → `critical`): script tags, dangerous tags,
  inline event handlers, `javascript:`/`vbscript:`/`data:` URIs, `srcdoc`, JS sinks
  (`eval`, `innerHTML`, `document.write`), CSS `expression()`/`@import`, attribute breakouts
  and control characters.
- Evasion-aware normalization: repeated URL decoding, HTML entity decoding, `\xNN`/`\uNNNN`
  escapes, NFKC normalization and null-byte stripping — each decoded layer is scanned.
- Structured results: every finding reports the pattern id, severity, matched text, offset
  and the layer it was found in.
- CLI with text or JSON output, severity filtering, file/stdin input and meaningful exit codes.
- Typed (`mypy --strict`), linted (`ruff`) and covered by a pytest suite.

## Install

```bash
pip install -e ".[dev]"
```

## CLI

```bash
xss-check "<img src=x onerror=alert(1)>"      # or: python checker.py "..."
xss-check --json "%3Cscript%3Ealert(1)%3C/script%3E"
xss-check --file payloads.txt --min-severity high
cat access.log | xss-check --quiet && echo "clean"
xss-check --list-patterns
```

Exit codes: `0` clean, `1` payload detected, `2` usage or I/O error — so it drops straight into
CI pipelines and pre-commit checks.

Options: `--json`, `--quiet`, `--min-severity {low,medium,high,critical}`, `--no-decode`,
`--file PATH` (`-` for stdin), `--list-patterns`, `--version`.

## Library

```python
from xss_checker import Severity, scan

result = scan("<svg/onload=alert(1)>", min_severity=Severity.MEDIUM)
result.is_malicious          # True
result.severity              # Severity.HIGH
result.findings[0].pattern_id  # 'event-handler'
result.to_dict()             # JSON-serializable report
```

## Development

```bash
pytest        # tests
ruff check .  # lint
ruff format . # format
mypy          # type check
```
