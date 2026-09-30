"""Command line interface for the XSS input checker."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import IO

from . import __version__
from .detector import ScanResult, scan
from .patterns import PATTERNS
from .severity import Severity

EXIT_CLEAN = 0
EXIT_DETECTED = 1
EXIT_ERROR = 2

_ICONS = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warn",
    Severity.HIGH: "alert",
    Severity.CRITICAL: "critical",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xss-check",
        description="Detect common cross-site scripting payloads in untrusted input.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("inputs", nargs="*", default=[], help="values to scan")
    source.add_argument("-f", "--file", help="scan each line of a file ('-' for stdin)")
    parser.add_argument(
        "--min-severity",
        default=Severity.LOW.value,
        choices=[level.value for level in Severity],
        help="ignore findings below this severity (default: low)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine readable JSON")
    parser.add_argument("--quiet", action="store_true", help="suppress output; rely on exit code")
    parser.add_argument("--no-decode", action="store_true", help="scan raw input only")
    parser.add_argument(
        "--list-patterns", action="store_true", help="print the signature catalogue and exit"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _read_values(args: argparse.Namespace, stdin: IO[str]) -> list[str]:
    if args.file:
        if args.file == "-":
            return [line.rstrip("\n") for line in stdin if line.strip()]
        with open(args.file, encoding="utf-8", errors="replace") as handle:
            return [line.rstrip("\n") for line in handle if line.strip()]
    if args.inputs:
        return list(args.inputs)
    if not stdin.isatty():
        return [line.rstrip("\n") for line in stdin if line.strip()]
    return [input("Enter input to test: ")]


def _render_text(results: Sequence[ScanResult], stream: IO[str]) -> None:
    for result in results:
        if not result.is_malicious:
            print(f"[clean] {result.value!r}", file=stream)
            continue
        severity = result.severity
        assert severity is not None
        print(f"[{_ICONS[severity]}] {result.value!r} -> {severity} risk", file=stream)
        seen_remediations: set[str] = set()
        for finding in result.findings:
            print(
                f"    {finding.severity.value:<8} {finding.name} "
                f"({finding.pattern_id}, layer={finding.layer}) matched {finding.matched!r}",
                file=stream,
            )
            if finding.pattern_id not in seen_remediations:
                seen_remediations.add(finding.pattern_id)
                print(f"      fix: {finding.remediation}", file=stream)


def _list_patterns(stream: IO[str]) -> None:
    for pattern in sorted(PATTERNS, key=lambda item: (-item.severity.rank, item.id)):
        print(f"{pattern.severity.value:<8} {pattern.id:<20} {pattern.description}", file=stream)
        print(f"{'':<8} {'':<20} fix: {pattern.remediation}", file=stream)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    if args.list_patterns:
        _list_patterns(stdout)
        return EXIT_CLEAN

    try:
        values = _read_values(args, stdin)
    except OSError as error:
        print(f"error: {error}", file=stderr)
        return EXIT_ERROR
    except (EOFError, KeyboardInterrupt):
        return EXIT_ERROR

    if not values:
        print("error: no input provided", file=stderr)
        return EXIT_ERROR

    min_severity = Severity.parse(args.min_severity)
    results = [
        scan(value, min_severity=min_severity, decode=not args.no_decode) for value in values
    ]

    if not args.quiet:
        if args.json:
            payload = [result.to_dict() for result in results]
            json.dump(payload if len(payload) > 1 else payload[0], stdout, indent=2)
            print(file=stdout)
        else:
            _render_text(results, stdout)

    return EXIT_DETECTED if any(result.is_malicious for result in results) else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
