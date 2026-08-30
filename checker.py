"""Backwards-compatible entry point: ``python checker.py``."""

from xss_checker.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
