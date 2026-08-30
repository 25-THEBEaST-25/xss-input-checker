"""Severity levels for XSS findings."""

from __future__ import annotations

from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(Enum):
    """Ordered severity of a detection, from least to most dangerous."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _ORDER[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __str__(self) -> str:
        return self.value

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(level.value for level in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from None


_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}
