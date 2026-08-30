"""Detect common cross-site scripting payloads in untrusted input."""

from .detector import Finding, ScanResult, is_malicious, normalize, scan, scan_all
from .patterns import PATTERNS, Pattern
from .severity import Severity

__version__ = "1.0.0"

__all__ = [
    "Finding",
    "PATTERNS",
    "Pattern",
    "ScanResult",
    "Severity",
    "__version__",
    "is_malicious",
    "normalize",
    "scan",
    "scan_all",
]
