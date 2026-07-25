"""
LLM assistance layer.

This layer is strictly optional. The audit runs, scores, and reports without it.
Its job is narrow: take findings the deterministic engine has already produced
and turn them into an explanation aimed at a specific audience.

The architectural rule, which matters more than the code: the model never
decides whether a device passes, and never executes anything. It receives
findings as input and produces prose as output. Compliance decisions stay in
rules.py where they are reproducible, testable, and auditable.

This mirrors the hybrid pattern the industry settled on for network automation:
a language model is useful for interpretation and planning, and unsuitable as
the control layer for infrastructure that has to behave predictably.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .rules import AuditResult

# Optional dependency. The app degrades gracefully if it is not installed.
try:
    from anthropic import Anthropic

    _SDK_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SDK_AVAILABLE = False


MODEL = "claude-sonnet-4-6"


AUDIENCES = {
    "engineer": (
        "a network engineer who will implement the fix. Be technically precise. "
        "Reference IOS syntax and operational impact, including whether a change "
        "risks dropping the current management session."
    ),
    "manager": (
        "an IT manager who is not a network specialist. Explain business risk and "
        "operational consequence. Avoid IOS syntax entirely. No jargon without a "
        "plain-language gloss."
    ),
    "auditor": (
        "an external auditor. Focus on control objectives, the evidence that would "
        "demonstrate compliance, and residual risk if the finding is accepted "
        "rather than remediated."
    ),
}


@dataclass
class LLMConfig:
    api_key: str | None = None
    model: str = MODEL
    max_tokens: int = 1500

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    @property
    def is_available(self) -> bool:
        return _SDK_AVAILABLE and bool(self.api_key)


def _findings_payload(result: AuditResult, limit: int = 12) -> str:
    """Serialise findings compactly so the prompt stays small and focused."""
    items = []
    for f in result.findings_sorted()[:limit]:
        items.append(
            {
                "id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "evidence": f.evidence[:3],
            }
        )
    return json.dumps(items, indent=2)


def build_prompt(result: AuditResult, audience: str = "engineer") -> str:
    """Construct the prompt. Exposed separately so it can be inspected and tested."""
    audience_desc = AUDIENCES.get(audience, AUDIENCES["engineer"])
    counts = result.counts_by_severity()

    return f"""You are reviewing the output of a network configuration compliance audit.

Device: {result.hostname}
Compliance score: {result.score()}/100 (grade {result.grade()})
Checks run: {result.total_rules} | Passed: {result.passed_count} | Failed: {result.failed_count}
Severity breakdown: {counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low

Findings (JSON):
{_findings_payload(result)}

Write a remediation briefing for {audience_desc}

Structure your response as:

1. A two-sentence assessment of the device's overall posture.
2. The three findings that should be fixed first, and why those three. Justify the
   ordering by actual exploitability and blast radius, not by severity label alone.
3. One paragraph on what the pattern of findings suggests about how this device
   was built and maintained.

Do not restate every finding. Do not invent findings that are not in the list.
If the evidence for a finding is thin, say so rather than overstating it.
Write in plain prose. No bullet-point padding."""


def explain_findings(result: AuditResult, audience: str = "engineer",
                     config: LLMConfig | None = None) -> str:
    """Generate a natural-language briefing for a completed audit.

    Returns a message explaining what is missing rather than raising if the
    LLM layer is unavailable. The tool is expected to work without it.
    """
    cfg = config or LLMConfig.from_env()

    if not _SDK_AVAILABLE:
        return (
            "The `anthropic` package is not installed, so the briefing layer is off. "
            "Install it with `pip install anthropic` to enable it. "
            "The audit results above are complete and were produced without it."
        )

    if not cfg.api_key:
        return (
            "No ANTHROPIC_API_KEY is set, so the briefing layer is off. "
            "Set the environment variable to enable it. "
            "The audit results above are complete and were produced without it."
        )

    if result.failed_count == 0:
        return "No findings to explain. The device passed every check in the rule set."

    try:
        client = Anthropic(api_key=cfg.api_key)
        response = client.messages.create(
            model=cfg.model,
            max_tokens=cfg.max_tokens,
            messages=[{"role": "user", "content": build_prompt(result, audience)}],
        )
        return "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
    except Exception as exc:
        return f"The briefing layer could not complete: {exc}"
