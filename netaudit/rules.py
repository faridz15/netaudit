"""
Compliance rule set.

Each rule is a small, self-contained function that receives a ParsedConfig and
returns either None (the device passes) or a Finding (it does not).

The rule set is modelled on the CIS Cisco IOS Benchmark and on the hardening
guidance operators apply to management-plane, control-plane, and data-plane
configuration. It is not a certified CIS implementation and does not claim to
be; it covers the checks that appear most often in real audit findings.

Design rule: every check here is deterministic. No language model is involved
in deciding whether a device passes. That decision has to be reproducible and
explainable, which is exactly what an LLM is not. The model's role comes later,
in llm.py, and is limited to explaining findings that this engine has already
made.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from .parser import ParsedConfig

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Weights feed the compliance score. A critical finding costs more than a low
# one, so a device with one critical failure does not score the same as a device
# with one cosmetic gap.
SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}


@dataclass
class Finding:
    """A single failed check."""

    rule_id: str
    title: str
    severity: str
    category: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    reference: str = ""


@dataclass
class Rule:
    """A registered check."""

    rule_id: str
    title: str
    severity: str
    category: str
    reference: str
    check: Callable[[ParsedConfig], Finding | None]


RULES: list[Rule] = []


def rule(rule_id: str, title: str, severity: str, category: str, reference: str = ""):
    """Decorator that registers a check function in the global rule set."""

    def wrapper(fn: Callable[[ParsedConfig], Finding | None]) -> Callable:
        RULES.append(
            Rule(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                reference=reference,
                check=fn,
            )
        )
        return fn

    return wrapper


def _finding(r: Rule, detail: str, evidence: list[str], remediation: list[str]) -> Finding:
    return Finding(
        rule_id=r.rule_id,
        title=r.title,
        severity=r.severity,
        category=r.category,
        detail=detail,
        evidence=evidence,
        remediation=remediation,
        reference=r.reference,
    )


def _r(rule_id: str) -> Rule:
    """Look up a registered rule by id, used inside check bodies."""
    for r in RULES:
        if r.rule_id == rule_id:
            return r
    raise KeyError(rule_id)


# ===========================================================================
# CATEGORY: Management plane — authentication
# ===========================================================================

@rule("MGMT-001", "Enable secret is not configured",
      "CRITICAL", "Management Plane", "CIS Cisco IOS 1.1.1")
def check_enable_secret(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^enable secret "):
        return None
    evidence = cfg.find_global(r"^enable password ") or ["(no enable secret line present)"]
    return _finding(
        _r("MGMT-001"),
        "The device does not use `enable secret`. Privileged EXEC access is either "
        "unprotected or protected only by `enable password`, which is stored using a "
        "reversible Type 7 encoding that can be decoded instantly with freely available tools.",
        evidence,
        ["no enable password", "enable secret <STRONG-SECRET>"],
    )


@rule("MGMT-002", "Password encryption service is disabled",
      "HIGH", "Management Plane", "CIS Cisco IOS 1.1.2")
def check_password_encryption(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^service password-encryption"):
        return None
    return _finding(
        _r("MGMT-002"),
        "`service password-encryption` is not enabled. Any password stored in the "
        "configuration appears in cleartext, including in backups, TFTP transfers, and "
        "screenshots taken during troubleshooting.",
        ["(service password-encryption absent)"],
        ["service password-encryption"],
    )


@rule("MGMT-003", "AAA is not enabled",
      "HIGH", "Management Plane", "CIS Cisco IOS 1.3")
def check_aaa(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^aaa new-model"):
        return None
    return _finding(
        _r("MGMT-003"),
        "`aaa new-model` is not configured. The device relies on local line passwords "
        "rather than centralised authentication, which removes per-user accountability "
        "and makes credential rotation a per-device manual task.",
        ["(aaa new-model absent)"],
        [
            "aaa new-model",
            "aaa authentication login default group tacacs+ local",
            "aaa authorization exec default group tacacs+ local",
            "aaa accounting exec default start-stop group tacacs+",
        ],
    )


@rule("MGMT-004", "No minimum password length enforced",
      "MEDIUM", "Management Plane", "CIS Cisco IOS 1.1.3")
def check_min_password_length(cfg: ParsedConfig) -> Finding | None:
    line = cfg.first_global(r"^security passwords min-length (\d+)")
    if line:
        length = int(re.search(r"(\d+)", line).group(1))
        if length >= 8:
            return None
        return _finding(
            _r("MGMT-004"),
            f"Minimum password length is set to {length}, below the recommended floor of 8.",
            [line],
            ["security passwords min-length 8"],
        )
    return _finding(
        _r("MGMT-004"),
        "No minimum password length is enforced, so short passwords can be set without warning.",
        ["(security passwords min-length absent)"],
        ["security passwords min-length 8"],
    )


@rule("MGMT-005", "Login brute-force protection not configured",
      "MEDIUM", "Management Plane", "CIS Cisco IOS 1.2.3")
def check_login_block(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^login block-for "):
        return None
    return _finding(
        _r("MGMT-005"),
        "`login block-for` is not configured. Repeated failed authentication attempts are "
        "not rate-limited, leaving the management interface open to sustained brute-force attempts.",
        ["(login block-for absent)"],
        ["login block-for 120 attempts 3 within 60", "login on-failure log", "login on-success log"],
    )


# ===========================================================================
# CATEGORY: Management plane — remote access
# ===========================================================================

@rule("VTY-001", "Telnet is permitted on VTY lines",
      "CRITICAL", "Remote Access", "CIS Cisco IOS 1.5.4")
def check_vty_telnet(cfg: ParsedConfig) -> Finding | None:
    offenders: list[str] = []
    for blk in cfg.vty_blocks():
        transports = blk.transport_input
        if not transports:
            offenders.append(f"line {blk.name}: transport input not set (defaults permit telnet)")
        elif "telnet" in transports or "all" in transports:
            offenders.append(f"line {blk.name}: transport input {' '.join(transports)}")
    if not offenders:
        return None
    return _finding(
        _r("VTY-001"),
        "One or more VTY lines accept Telnet. Telnet carries credentials and session data in "
        "cleartext, so anyone able to observe the management path can capture privileged "
        "credentials without breaking anything.",
        offenders,
        ["line vty 0 4", " transport input ssh", " transport output ssh"],
    )


@rule("VTY-002", "SSH version 2 is not enforced",
      "HIGH", "Remote Access", "CIS Cisco IOS 1.5.2")
def check_ssh_version(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^ip ssh version 2"):
        return None
    return _finding(
        _r("VTY-002"),
        "`ip ssh version 2` is not configured. The device may negotiate SSH version 1, which "
        "has known cryptographic weaknesses and should not be reachable on a production network.",
        ["(ip ssh version 2 absent)"],
        ["ip ssh version 2", "ip ssh time-out 60", "ip ssh authentication-retries 3"],
    )


@rule("VTY-003", "VTY lines have no access-class ACL",
      "HIGH", "Remote Access", "CIS Cisco IOS 1.5.5")
def check_vty_acl(cfg: ParsedConfig) -> Finding | None:
    offenders = [f"line {b.name}: no access-class applied" for b in cfg.vty_blocks() if not b.access_class]
    if not offenders:
        return None
    return _finding(
        _r("VTY-003"),
        "VTY lines are not restricted by an access-class ACL. Management access is reachable "
        "from any source address that can route to the device, rather than from the management "
        "network only.",
        offenders,
        [
            "ip access-list standard MGMT-HOSTS",
            " permit 10.0.0.0 0.0.0.255",
            " deny any log",
            "line vty 0 4",
            " access-class MGMT-HOSTS in",
        ],
    )


@rule("VTY-004", "Session timeout is missing or disabled",
      "MEDIUM", "Remote Access", "CIS Cisco IOS 1.5.1")
def check_exec_timeout(cfg: ParsedConfig) -> Finding | None:
    offenders: list[str] = []
    for blk in cfg.line_blocks:
        if blk.kind not in ("vty", "console", "aux"):
            continue
        # A line configured with `no exec` cannot open an EXEC session at all,
        # so exec-timeout has nothing to time out. Flagging it would be a false
        # positive, and false positives are how an audit tool loses its audience.
        if blk.has_line(r"no exec"):
            continue
        timeout = blk.exec_timeout
        if timeout is None:
            offenders.append(f"line {blk.name}: exec-timeout not configured")
        elif timeout == (0, 0):
            offenders.append(f"line {blk.name}: exec-timeout 0 0 (never times out)")
        elif timeout[0] > 15:
            offenders.append(f"line {blk.name}: exec-timeout {timeout[0]} {timeout[1]} (exceeds 15 minutes)")
    if not offenders:
        return None
    return _finding(
        _r("VTY-004"),
        "One or more management lines will hold an idle session open indefinitely or for an "
        "extended period. An unattended terminal remains authenticated and usable.",
        offenders,
        ["line con 0", " exec-timeout 10 0", "line vty 0 4", " exec-timeout 10 0"],
    )


@rule("VTY-005", "AUX port is not disabled",
      "MEDIUM", "Remote Access", "CIS Cisco IOS 1.1.9")
def check_aux_disabled(cfg: ParsedConfig) -> Finding | None:
    aux = cfg.aux_blocks()
    if not aux:
        return None
    offenders = [f"line {b.name}: not disabled" for b in aux if not b.has_line(r"no exec")]
    if not offenders:
        return None
    return _finding(
        _r("VTY-005"),
        "The auxiliary port still offers an EXEC session. It is rarely used in production and "
        "is a commonly overlooked physical access path.",
        offenders,
        ["line aux 0", " no exec", " transport input none"],
    )


# ===========================================================================
# CATEGORY: Unnecessary services
# ===========================================================================

@rule("SVC-001", "HTTP server is enabled",
      "HIGH", "Unnecessary Services", "CIS Cisco IOS 1.1.7")
def check_http_server(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^no ip http server"):
        return None
    if cfg.has_global(r"^ip http server"):
        return _finding(
            _r("SVC-001"),
            "The unencrypted HTTP management server is enabled. It exposes an additional "
            "management surface and transmits session credentials without encryption.",
            cfg.find_global(r"^ip http server"),
            ["no ip http server", "ip http secure-server", "ip http authentication aaa"],
        )
    return _finding(
        _r("SVC-001"),
        "The configuration does not explicitly disable the HTTP server. Platform defaults vary "
        "by IOS release, so the state is indeterminate and should be pinned explicitly.",
        ["(neither 'ip http server' nor 'no ip http server' present)"],
        ["no ip http server"],
    )


@rule("SVC-002", "TCP/UDP small servers are not explicitly disabled",
      "LOW", "Unnecessary Services", "CIS Cisco IOS 1.1.5")
def check_small_servers(cfg: ParsedConfig) -> Finding | None:
    missing: list[str] = []
    if not cfg.has_global(r"^no service tcp-small-servers"):
        missing.append("no service tcp-small-servers")
    if not cfg.has_global(r"^no service udp-small-servers"):
        missing.append("no service udp-small-servers")
    if not missing:
        return None
    return _finding(
        _r("SVC-002"),
        "Legacy diagnostic services (echo, discard, chargen, daytime) are not explicitly "
        "disabled. They serve no operational purpose and have historically been abused for "
        "traffic amplification.",
        [f"(missing: {m})" for m in missing],
        missing,
    )


@rule("SVC-003", "CDP is running globally",
      "MEDIUM", "Unnecessary Services", "CIS Cisco IOS 1.1.8")
def check_cdp(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^no cdp run"):
        return None
    return _finding(
        _r("SVC-003"),
        "Cisco Discovery Protocol is enabled device-wide. CDP advertises platform, software "
        "version, and management address to any directly connected device, which is useful "
        "internally and equally useful to anyone who gains access to an edge port.",
        ["(no cdp run absent)"],
        ["no cdp run", "! or, to keep CDP internally:", "interface <EDGE-PORT>", " no cdp enable"],
    )


@rule("SVC-004", "IP source routing is not disabled",
      "MEDIUM", "Unnecessary Services", "CIS Cisco IOS 2.1.1")
def check_source_route(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^no ip source-route"):
        return None
    return _finding(
        _r("SVC-004"),
        "IP source routing is not disabled. It allows a sender to dictate the path a packet "
        "takes, which can be used to bypass routing-based security controls.",
        ["(no ip source-route absent)"],
        ["no ip source-route"],
    )


# ===========================================================================
# CATEGORY: SNMP
# ===========================================================================

DEFAULT_COMMUNITIES = {"public", "private", "cisco", "admin", "secret", "community"}


@rule("SNMP-001", "Default or weak SNMP community string in use",
      "CRITICAL", "SNMP", "CIS Cisco IOS 1.4.1")
def check_snmp_default(cfg: ParsedConfig) -> Finding | None:
    offenders = [
        c.raw for c in cfg.snmp_communities
        if c.string.lower() in DEFAULT_COMMUNITIES or len(c.string) < 8
    ]
    if not offenders:
        return None
    return _finding(
        _r("SNMP-001"),
        "One or more SNMP community strings are default or trivially short. Default community "
        "strings are the first thing an automated scanner tries, and a read-write community "
        "grants full configuration access.",
        offenders,
        [
            "no snmp-server community public RO",
            "no snmp-server community private RW",
            "ip access-list standard SNMP-HOSTS",
            " permit 10.0.0.0 0.0.0.255",
            "snmp-server community <STRONG-STRING> RO SNMP-HOSTS",
        ],
    )


@rule("SNMP-002", "SNMP read-write access is configured",
      "HIGH", "SNMP", "CIS Cisco IOS 1.4.2")
def check_snmp_rw(cfg: ParsedConfig) -> Finding | None:
    offenders = [c.raw for c in cfg.snmp_communities if c.access == "RW"]
    if not offenders:
        return None
    return _finding(
        _r("SNMP-002"),
        "SNMP read-write access is enabled. Anyone holding the community string can modify "
        "device configuration over UDP, without an interactive session and often without logging.",
        offenders,
        ["no snmp-server community <STRING> RW", "! use read-only, or SNMPv3 with authPriv"],
    )


@rule("SNMP-003", "SNMP community is not restricted by ACL",
      "HIGH", "SNMP", "CIS Cisco IOS 1.4.3")
def check_snmp_acl(cfg: ParsedConfig) -> Finding | None:
    offenders = [c.raw for c in cfg.snmp_communities if not c.acl]
    if not offenders:
        return None
    return _finding(
        _r("SNMP-003"),
        "SNMP communities are configured without a source ACL, so polling is accepted from any "
        "reachable host rather than from the monitoring platform only.",
        offenders,
        [
            "ip access-list standard SNMP-HOSTS",
            " permit 10.0.0.10",
            " deny any log",
            "snmp-server community <STRING> RO SNMP-HOSTS",
        ],
    )


# ===========================================================================
# CATEGORY: Logging and time
# ===========================================================================

@rule("LOG-001", "No remote syslog destination configured",
      "HIGH", "Logging & Time", "CIS Cisco IOS 2.2.1")
def check_logging_host(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^logging (host )?\d+\.\d+\.\d+\.\d+"):
        return None
    return _finding(
        _r("LOG-001"),
        "No remote syslog server is configured. Logs live only in a local buffer that is lost on "
        "reload and can be cleared by anyone with privileged access, which removes the audit "
        "trail exactly when it matters most.",
        ["(no logging host configured)"],
        ["logging host 10.0.0.20", "logging trap informational", "logging buffered 64000 informational"],
    )


@rule("LOG-002", "Log timestamps are not enabled",
      "MEDIUM", "Logging & Time", "CIS Cisco IOS 2.2.2")
def check_log_timestamps(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^service timestamps log"):
        return None
    return _finding(
        _r("LOG-002"),
        "Log messages are not timestamped. Events cannot be correlated across devices during "
        "an incident, which is the primary reason logs are collected at all.",
        ["(service timestamps log absent)"],
        ["service timestamps debug datetime msec localtime show-timezone",
         "service timestamps log datetime msec localtime show-timezone"],
    )


@rule("LOG-003", "No NTP server configured",
      "MEDIUM", "Logging & Time", "CIS Cisco IOS 2.3.1")
def check_ntp(cfg: ParsedConfig) -> Finding | None:
    if cfg.has_global(r"^ntp server "):
        return None
    return _finding(
        _r("LOG-003"),
        "No NTP server is configured. Device clocks will drift, and unsynchronised timestamps "
        "make cross-device log correlation unreliable and weaken the evidentiary value of logs.",
        ["(ntp server absent)"],
        ["ntp server 10.0.0.30", "ntp server 10.0.0.31"],
    )


@rule("LOG-004", "NTP authentication is not configured",
      "LOW", "Logging & Time", "CIS Cisco IOS 2.3.2")
def check_ntp_auth(cfg: ParsedConfig) -> Finding | None:
    if not cfg.has_global(r"^ntp server "):
        return None  # LOG-003 already covers the absence of NTP entirely
    if cfg.has_global(r"^ntp authenticate"):
        return None
    return _finding(
        _r("LOG-004"),
        "NTP is configured but not authenticated. Time sources are accepted without verification, "
        "so a spoofed NTP response can shift the device clock and corrupt log correlation.",
        cfg.find_global(r"^ntp server "),
        ["ntp authenticate", "ntp authentication-key 1 md5 <KEY>", "ntp trusted-key 1"],
    )


# ===========================================================================
# CATEGORY: Banner
# ===========================================================================

@rule("BAN-001", "No login banner configured",
      "LOW", "Banner", "CIS Cisco IOS 1.6.1")
def check_banner(cfg: ParsedConfig) -> Finding | None:
    if any(k in cfg.banners for k in ("login", "motd", "exec")):
        return None
    return _finding(
        _r("BAN-001"),
        "No login or MOTD banner is configured. In many jurisdictions an explicit "
        "authorised-use notice is what makes unauthorised access legally actionable.",
        ["(no banner configured)"],
        ["banner login ^", "  Authorised access only. Activity is monitored and logged.", "^"],
    )


# ===========================================================================
# CATEGORY: Interface hygiene
# ===========================================================================

@rule("INT-001", "Unused interfaces are not shut down",
      "MEDIUM", "Interface Hygiene", "CIS Cisco IOS 1.7.1")
def check_unused_interfaces(cfg: ParsedConfig) -> Finding | None:
    offenders: list[str] = []
    for iface in cfg.interfaces:
        if iface.name.lower().startswith(("loopback", "vlan1", "null")):
            continue
        if not iface.is_layer3 and not iface.is_shutdown and not iface.has_description:
            if not iface.has_line(r"switchport (mode|access|trunk)"):
                offenders.append(f"{iface.name}: no address, no description, not shut down")
    if not offenders:
        return None
    return _finding(
        _r("INT-001"),
        "Interfaces with no address, no description, and no shutdown appear to be unused but "
        "remain administratively up. An unused live port is an unmonitored entry point.",
        offenders,
        ["interface <UNUSED-PORT>", " description UNUSED", " shutdown"],
    )


@rule("INT-002", "Directed broadcast not disabled on Layer 3 interfaces",
      "MEDIUM", "Interface Hygiene", "CIS Cisco IOS 2.1.2")
def check_directed_broadcast(cfg: ParsedConfig) -> Finding | None:
    offenders = [
        iface.name for iface in cfg.interfaces
        if iface.is_layer3 and not iface.has_line(r"no ip directed-broadcast")
        and not iface.name.lower().startswith("loopback")
    ]
    if not offenders:
        return None
    return _finding(
        _r("INT-002"),
        "IP directed broadcast is not explicitly disabled on one or more routed interfaces. "
        "It is the mechanism behind smurf-style amplification attacks.",
        [f"{name}: no ip directed-broadcast missing" for name in offenders],
        ["interface <L3-INTERFACE>", " no ip directed-broadcast"],
    )


@rule("INT-003", "Proxy ARP not disabled on Layer 3 interfaces",
      "LOW", "Interface Hygiene", "CIS Cisco IOS 2.1.3")
def check_proxy_arp(cfg: ParsedConfig) -> Finding | None:
    offenders = [
        iface.name for iface in cfg.interfaces
        if iface.is_layer3 and not iface.has_line(r"no ip proxy-arp")
        and not iface.name.lower().startswith("loopback")
    ]
    if not offenders:
        return None
    return _finding(
        _r("INT-003"),
        "Proxy ARP remains enabled on one or more routed interfaces. It can be used to map the "
        "internal address space and, in some designs, to intercept traffic.",
        [f"{name}: no ip proxy-arp missing" for name in offenders],
        ["interface <L3-INTERFACE>", " no ip proxy-arp"],
    )


# ===========================================================================
# Engine
# ===========================================================================

# Fixed display order for categories, roughly most to least security-critical.
# Used to keep the per-category grade row stable across devices.
_CATEGORY_ORDER = [
    "Management Plane",
    "Remote Access",
    "SNMP",
    "Unnecessary Services",
    "Logging & Time",
    "Interface Hygiene",
    "Banner",
]


def score_to_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade. Single source of truth."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


@dataclass
class CategoryScore:
    """A single category's grade, for the SonarQube-style metric row."""

    category: str
    score: int
    grade: str
    failed: int
    total: int

    @property
    def is_clean(self) -> bool:
        return self.failed == 0


@dataclass
class AuditResult:
    """The output of running the full rule set against one device."""

    hostname: str
    findings: list[Finding]
    passed_rules: list[Rule]
    total_rules: int

    @property
    def failed_count(self) -> int:
        return len(self.findings)

    @property
    def passed_count(self) -> int:
        return len(self.passed_rules)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def score(self) -> int:
        """Weighted compliance score, 0-100.

        The denominator is the maximum penalty the full rule set could produce,
        so the score answers: of all the weighted risk this rule set can detect,
        how much has this device avoided?
        """
        max_penalty = sum(SEVERITY_WEIGHT[r.severity] for r in RULES)
        if max_penalty == 0:
            return 100
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return max(0, round(100 * (1 - penalty / max_penalty)))

    def grade(self) -> str:
        return score_to_grade(self.score())

    def findings_sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings_sorted():
            out.setdefault(f.category, []).append(f)
        return out

    def category_scores(self) -> list["CategoryScore"]:
        """Per-category grades, in a fixed display order.

        Each category is scored on its own rules only: the penalty from its
        findings against the maximum penalty its own rules could produce. This
        is what lets the UI show a SonarQube-style row of letter grades, one per
        domain, so a reader sees *where* a device is weak, not only how weak.
        """
        # Group every registered rule by category so a category with zero
        # findings still appears, graded A, rather than silently vanishing.
        rules_by_cat: dict[str, list[Rule]] = {}
        for r in RULES:
            rules_by_cat.setdefault(r.category, []).append(r)

        findings_by_cat: dict[str, list[Finding]] = {}
        for f in self.findings:
            findings_by_cat.setdefault(f.category, []).append(f)

        out: list[CategoryScore] = []
        for category, rules in rules_by_cat.items():
            max_penalty = sum(SEVERITY_WEIGHT[r.severity] for r in rules)
            found = findings_by_cat.get(category, [])
            penalty = sum(SEVERITY_WEIGHT[f.severity] for f in found)
            score = 100 if max_penalty == 0 else max(0, round(100 * (1 - penalty / max_penalty)))
            out.append(
                CategoryScore(
                    category=category,
                    score=score,
                    grade=score_to_grade(score),
                    failed=len(found),
                    total=len(rules),
                )
            )

        order = {c: i for i, c in enumerate(_CATEGORY_ORDER)}
        out.sort(key=lambda cs: order.get(cs.category, 99))
        return out


def run_audit(cfg: ParsedConfig) -> AuditResult:
    """Run every registered rule against a parsed config."""
    findings: list[Finding] = []
    passed: list[Rule] = []

    for r in RULES:
        try:
            result = r.check(cfg)
        except Exception as exc:  # a broken rule must not sink the whole audit
            findings.append(
                Finding(
                    rule_id=r.rule_id,
                    title=f"{r.title} (check could not complete)",
                    severity="LOW",
                    category=r.category,
                    detail=f"The rule raised an error and was not evaluated: {exc}",
                    evidence=[],
                    remediation=[],
                    reference=r.reference,
                )
            )
            continue
        if result is None:
            passed.append(r)
        else:
            findings.append(result)

    return AuditResult(
        hostname=cfg.hostname,
        findings=findings,
        passed_rules=passed,
        total_rules=len(RULES),
    )
