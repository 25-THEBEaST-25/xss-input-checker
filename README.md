# XSS Input Checker 🔐

A simple Python CLI tool to detect common Cross-Site Scripting (XSS) attack patterns in user input.

## Why this matters
XSS vulnerabilities occur when applications trust unsanitized user input. This tool demonstrates basic detection logic.

## Features
- Detects `<script>` tags
- Detects JavaScript-based injection
- Regex-based pattern matching

## How to Run
```bash
python checker.py
