# XSS Input Checker 🔐

A Python library and CLI that flags common Cross-Site Scripting (XSS) payloads in untrusted input.

> Detection is a defence-in-depth signal, not a sanitizer. Always escape output with a
> context-aware encoder (or use a strict allow-list sanitizer) — never rely on pattern matching alone.

## What it detects

Every finding maps to a signature in `xss_checker/patterns.py`, each tagged with a severity
(`low` → `critical`). Run `xss-check --list-patterns` to print the live catalogue. Categories
covered:

| Category | Examples | Severity |
| --- | --- | --- |
| `<script>` tags | `<script>alert(1)</script>`, obfuscated open/close tags | critical |
| Dangerous HTML tags | `<iframe>`, `<object>`, `<embed>`, `<svg>`, `<math>`, `<link>`, `<meta>`, `<base>`, `<form>`, `<template>`, `<portal>` | high |
| Inline event-handler attributes | `onerror=`, `onload=`, `onmouseover=`, `onfocus=`, any `on*=` attribute | high |
| `javascript:` URIs | including whitespace/tab-obfuscated variants like `java\tscript:` | critical |
| `vbscript:` URIs | legacy IE vector | high |
| `data:` URIs carrying markup/script | `data:text/html,<script>...`, `data:text/html;base64,...` | high |
| `srcdoc` attribute | inline HTML documents embedded in an `<iframe srcdoc=...>` | high |
| JS execution sinks | `eval(`, `setTimeout(`, `Function(`, `document.write(`, `innerHTML =`, `insertAdjacentHTML(` | high |
| CSS `expression()` | legacy IE CSS-to-script execution | medium |
| CSS `@import` / `url(javascript:...)` / `url(data:...)` | stylesheet-based vectors | medium |
| Encoded/obfuscated markup | HTML entities (`&#x3c;`), URL encoding (`%3C`), `\uNNNN`/`\xNN` escapes | medium |
| Control characters | null bytes and other control chars used to confuse naive filters | medium |

**Evasion-aware normalization**: before matching, input is passed through up to three rounds of
URL decoding, HTML entity decoding, `\xNN`/`\uNNNN` unescaping, NFKC normalization and null-byte
stripping. Every decoded layer is scanned in addition to the raw input, so `%3Cscript%3E`,
`&lt;script&gt;`, and `<script>` are all caught.

**Structured results**: every finding reports the pattern id, severity, matched text, offset and
the decoding layer it was found in (`scan(...).to_dict()` / `xss-check --json`).

**False-positive calibration**: ordinary, non-scripting HTML — a plain `<b>`, `<a href="...">`,
or `<img src="...">` — is *not* flagged. Earlier iterations of this tool matched *any* HTML tag
or *any* attribute ending in a quote, which meant routine markup (blog comments, templated pages)
was reported as "detected" by default. Detection now requires an actual dangerous construct
(a script tag, a dangerous element, an event handler, a script-bearing URI/sink, etc.) rather than
just the presence of HTML. See `tests/test_detector.py::test_does_not_flag_legitimate_non_scripting_html`
for the explicit regression tests.

CLI features: text or JSON output, severity filtering, file/stdin input and meaningful exit codes.
Typed (`mypy --strict`), linted (`ruff`) and covered by a pytest suite.

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
result.is_malicious  # True
result.severity  # Severity.HIGH
result.findings[0].pattern_id  # 'event-handler'
result.to_dict()  # JSON-serializable report
```

## Development

```bash
pytest        # tests
ruff check .  # lint
ruff format . # format
mypy          # type check
```

## Limitations

This is a **static, regex-based heuristic scanner**, not a sanitizer, parser, or WAF. It is a
useful defence-in-depth signal (e.g. flagging suspicious input in logs, forms, or a CI gate on
committed fixtures), but it has real, structural blind spots:

- **It does not parse HTML, CSS or JavaScript.** It matches text patterns, so it has no real
  notion of document structure, attribute context, or script semantics. A sufficiently novel
  encoding, browser-specific parsing quirk, or mutation-XSS technique (where a payload is inert
  as submitted but becomes dangerous only after the browser's HTML parser "fixes up" malformed
  markup) can evade every signature here.
- **It cannot guarantee zero false negatives.** The signature list covers well-known vectors
  (script tags, event handlers, `javascript:`/`data:` URIs, dangerous tags, JS sinks, CSS
  expression/import, common encodings) but a novel or highly obfuscated payload — e.g. one built
  entirely from CSS custom properties, a bespoke JS sink not in the list, or an application
  framework's own templating quirk — can slip through undetected.
- **It cannot guarantee zero false positives.** Because it works on text, not a parsed document,
  some legitimate content can still look like an attack, e.g. a security blog post that quotes
  `<script>alert(1)</script>` as an example, or minified HTML with no whitespace between an
  attribute-closing quote and a following `<script>`/dangerous tag. Prefer `--min-severity` or
  per-finding review over treating every detection as a confirmed attack.
- **It is not a replacement for output encoding or a real sanitizer.** The only reliable defence
  against XSS is context-aware output escaping (HTML/attribute/JS/URL encoding as appropriate) or
  an allow-list HTML sanitizer (e.g. a DOM-based library) at the point where untrusted data is
  rendered. This tool is a detection aid to catch obviously malicious input earlier (e.g. at
  ingestion or in CI), not a substitute for that.
- **It does not understand second-order or stored XSS flows.** It only scans the string you give
  it; it cannot tell you where that string ends up being rendered or in what context, which is
  what actually determines exploitability.
- **No allowance for intentionally rich-text input.** If your application legitimately accepts a
  restricted subset of HTML (e.g. from a WYSIWYG editor), pair this tool with your sanitizer's
  allow-list rather than relying on it to distinguish "safe rich text" from "attack" — some
  high-severity signatures (e.g. dangerous tags, event handlers) will still trigger on tags that
  are attacker-controlled but happen to appear in otherwise-trusted templates.

In short: treat a "clean" result as "no known signature matched," not as "provably safe," and
treat a "detected" result as "worth a human or a stricter sanitizer looking at it," not as a
guaranteed attack.
