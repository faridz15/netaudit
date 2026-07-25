"""
Report generation.

Three output formats, each for a different consumer:
  - Markdown  : the human-readable audit report
  - CSV       : findings as rows, for tracking in a ticket system or spreadsheet
  - Remediation config : a paste-ready IOS block, ordered so it does not lock you out
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from .rules import AuditResult

# Remediation ordering matters. Applying an access-class before the SSH and AAA
# configuration is in place is a well-known way to disconnect yourself from a
# device you are working on remotely. Categories are emitted in dependency order.
_REMEDIATION_ORDER = [
    "Logging & Time",
    "Management Plane",
    "Remote Access",
    "SNMP",
    "Unnecessary Services",
    "Interface Hygiene",
    "Banner",
]


def to_markdown(result: AuditResult, include_passed: bool = True) -> str:
    """Full audit report as Markdown."""
    counts = result.counts_by_severity()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out: list[str] = []
    out.append(f"# Configuration Compliance Report — {result.hostname}")
    out.append("")
    out.append(f"Generated {generated} by NetAudit")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- **Compliance score:** {result.score()}/100 (grade {result.grade()})")
    out.append(f"- **Checks run:** {result.total_rules}")
    out.append(f"- **Passed:** {result.passed_count}")
    out.append(f"- **Failed:** {result.failed_count}")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        out.append(f"| {sev} | {counts[sev]} |")
    out.append("")

    if result.failed_count == 0:
        out.append("No findings. The device passed every check in this rule set.")
        out.append("")
    else:
        out.append("## Findings")
        out.append("")
        for category, findings in result.by_category().items():
            out.append(f"### {category}")
            out.append("")
            for f in findings:
                out.append(f"#### `{f.rule_id}` {f.title}")
                out.append("")
                out.append(f"**Severity:** {f.severity}")
                if f.reference:
                    out.append(f" &nbsp;·&nbsp; **Reference:** {f.reference}")
                out.append("")
                out.append(f.detail)
                out.append("")
                if f.evidence:
                    out.append("**Evidence**")
                    out.append("")
                    out.append("```")
                    out.extend(f.evidence)
                    out.append("```")
                    out.append("")
                if f.remediation:
                    out.append("**Remediation**")
                    out.append("")
                    out.append("```cisco")
                    out.extend(f.remediation)
                    out.append("```")
                    out.append("")

    if include_passed and result.passed_rules:
        out.append("## Checks passed")
        out.append("")
        for r in sorted(result.passed_rules, key=lambda x: x.rule_id):
            out.append(f"- `{r.rule_id}` {r.title}")
        out.append("")

    out.append("---")
    out.append("")
    out.append(
        "*Rule set modelled on the CIS Cisco IOS Benchmark. This is not a certified CIS "
        "assessment and does not substitute for one.*"
    )
    out.append("")
    return "\n".join(out)


def to_csv(result: AuditResult) -> str:
    """Findings as CSV rows, one finding per row."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["device", "rule_id", "severity", "category", "title", "reference", "evidence"]
    )
    for f in result.findings_sorted():
        writer.writerow(
            [
                result.hostname,
                f.rule_id,
                f.severity,
                f.category,
                f.title,
                f.reference,
                " | ".join(f.evidence),
            ]
        )
    return buf.getvalue()


def to_remediation_config(result: AuditResult) -> str:
    """A paste-ready IOS remediation block, ordered to avoid self-lockout."""
    if result.failed_count == 0:
        return "! No remediation required.\n"

    by_cat = result.by_category()

    out: list[str] = []
    out.append(f"! Remediation configuration for {result.hostname}")
    out.append(f"! Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by NetAudit")
    out.append("!")
    out.append("! REVIEW BEFORE APPLYING. Placeholders in <ANGLE-BRACKETS> must be replaced")
    out.append("! with values from your own environment.")
    out.append("!")
    out.append("! Ordering note: logging and authentication are configured before access")
    out.append("! restrictions, so that if a later command drops your session you still")
    out.append("! have a working authentication path and a record of what changed.")
    out.append("!")
    out.append("! Apply through a console or out-of-band path where possible, and have a")
    out.append("! reload-in timer set before you begin:")
    out.append("!   reload in 15")
    out.append("!   ... apply changes, confirm reachability ...")
    out.append("!   reload cancel")
    out.append("!")
    out.append("")

    ordered = [c for c in _REMEDIATION_ORDER if c in by_cat]
    ordered += [c for c in by_cat if c not in _REMEDIATION_ORDER]

    for category in ordered:
        findings = by_cat[category]
        emitted = [f for f in findings if f.remediation]
        if not emitted:
            continue
        out.append(f"! ==== {category} " + "=" * max(0, 56 - len(category)))
        out.append("!")
        for f in emitted:
            out.append(f"! {f.rule_id} [{f.severity}] {f.title}")
            out.extend(f.remediation)
            out.append("!")
        out.append("")

    out.append("! End of remediation block.")
    out.append("! Save with: copy running-config startup-config")
    out.append("")
    return "\n".join(out)
