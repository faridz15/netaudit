"""
Configuration drift detection.

Compares two snapshots of a device configuration and reports what changed. A
plain text diff would do most of this, but a plain diff treats every changed
line as equally interesting. This module classifies each change by security
relevance, so a reviewer sees "an ACL entry was removed" before "a description
was reworded".
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from .parser import ParsedConfig, parse_config
from .rules import run_audit


# Patterns whose appearance or disappearance is security-relevant. Ordered most
# to least serious; the first match wins.
_SECURITY_PATTERNS: list[tuple[str, str]] = [
    (r"^(no )?enable secret", "Privileged access credential"),
    (r"^(no )?aaa ", "Authentication, authorisation, accounting"),
    (r"^(no )?snmp-server", "SNMP exposure"),
    (r"^(no )?ip access-list|^(no )?access-list", "Access control list"),
    (r"access-class", "Management access restriction"),
    (r"transport input", "Remote access transport"),
    (r"^(no )?ip http", "HTTP management service"),
    (r"^(no )?ip ssh", "SSH configuration"),
    (r"^(no )?service password-encryption", "Password storage"),
    (r"^(no )?logging", "Logging destination"),
    (r"^(no )?ntp ", "Time synchronisation"),
    (r"^(no )?username ", "Local user account"),
    (r"^(no )?crypto ", "Cryptographic configuration"),
    (r"exec-timeout", "Session timeout"),
    (r"^(no )?login block-for", "Brute-force protection"),
    (r"^(no )?cdp ", "Discovery protocol"),
    (r"^(no )?ip source-route", "Source routing"),
    (r"shutdown", "Interface administrative state"),
]


def _classify(line: str) -> str | None:
    """Return a security category for a changed line, or None if routine."""
    s = line.strip()
    for pattern, label in _SECURITY_PATTERNS:
        if re.search(pattern, s):
            return label
    return None


@dataclass
class DriftChange:
    """A single added or removed configuration line."""

    action: str  # "added" or "removed"
    line: str
    category: str | None = None

    @property
    def is_security_relevant(self) -> bool:
        return self.category is not None


@dataclass
class DriftResult:
    """The outcome of comparing two configuration snapshots."""

    baseline_hostname: str
    current_hostname: str
    changes: list[DriftChange] = field(default_factory=list)
    baseline_score: int = 0
    current_score: int = 0

    @property
    def security_changes(self) -> list[DriftChange]:
        return [c for c in self.changes if c.is_security_relevant]

    @property
    def routine_changes(self) -> list[DriftChange]:
        return [c for c in self.changes if not c.is_security_relevant]

    @property
    def score_delta(self) -> int:
        return self.current_score - self.baseline_score

    def summary_line(self) -> str:
        sec = len(self.security_changes)
        total = len(self.changes)
        if total == 0:
            return "No configuration difference detected."
        delta = self.score_delta
        direction = "improved" if delta > 0 else "declined" if delta < 0 else "unchanged"
        return (
            f"{total} configuration lines changed, {sec} of them security-relevant. "
            f"Compliance score {direction} by {abs(delta)} points."
        )

    def by_category(self) -> dict[str, list[DriftChange]]:
        out: dict[str, list[DriftChange]] = {}
        for c in self.security_changes:
            out.setdefault(c.category or "Other", []).append(c)
        return out


def _normalise(text: str) -> list[str]:
    """Strip comment markers, blank lines, and trailing whitespace for comparison."""
    out: list[str] = []
    for ln in text.splitlines():
        s = ln.rstrip()
        if s.strip() == "" or s.strip() == "!":
            continue
        out.append(s)
    return out


def compare_configs(baseline_text: str, current_text: str) -> DriftResult:
    """Compare two configuration snapshots and classify the differences."""
    baseline_cfg: ParsedConfig = parse_config(baseline_text)
    current_cfg: ParsedConfig = parse_config(current_text)

    baseline_audit = run_audit(baseline_cfg)
    current_audit = run_audit(current_cfg)

    result = DriftResult(
        baseline_hostname=baseline_cfg.hostname,
        current_hostname=current_cfg.hostname,
        baseline_score=baseline_audit.score(),
        current_score=current_audit.score(),
    )

    a = _normalise(baseline_text)
    b = _normalise(current_text)

    matcher = difflib.SequenceMatcher(None, a, b)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("delete", "replace"):
            for ln in a[i1:i2]:
                result.changes.append(DriftChange("removed", ln, _classify(ln)))
        if tag in ("insert", "replace"):
            for ln in b[j1:j2]:
                result.changes.append(DriftChange("added", ln, _classify(ln)))

    return result
