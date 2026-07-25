"""NetAudit — Cisco IOS configuration compliance auditor.

A hybrid rule-based and LLM-assisted tool that checks running-config files
against a CIS-inspired hardening baseline, reports findings with severity and
paste-ready remediation, and detects configuration drift between snapshots.
"""

__version__ = "1.0.0"

from .parser import parse_config, ParsedConfig
from .rules import run_audit, AuditResult, Finding, RULES
from .drift import compare_configs, DriftResult

__all__ = [
    "parse_config",
    "ParsedConfig",
    "run_audit",
    "AuditResult",
    "Finding",
    "RULES",
    "compare_configs",
    "DriftResult",
]
