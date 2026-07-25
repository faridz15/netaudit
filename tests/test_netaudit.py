"""
Test suite.

Run with:  pytest -v

The tests that matter most are the false-positive ones. An audit tool that
cries wolf gets ignored, and an ignored tool is worse than no tool because it
creates the appearance of coverage.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from netaudit.drift import compare_configs  # noqa: E402
from netaudit.parser import parse_config  # noqa: E402
from netaudit.report import to_csv, to_markdown, to_remediation_config  # noqa: E402
from netaudit.rules import RULES, run_audit  # noqa: E402

SAMPLES = Path(__file__).parent.parent / "samples"


def sample(name: str) -> str:
    return (SAMPLES / name).read_text()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def test_parses_hostname():
    cfg = parse_config("hostname TEST-RTR-01\n!\n")
    assert cfg.hostname == "TEST-RTR-01"


def test_parses_interface_stanza():
    cfg = parse_config(
        "interface GigabitEthernet0/1\n"
        " description LAN\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        "!\n"
    )
    assert len(cfg.interfaces) == 1
    iface = cfg.interfaces[0]
    assert iface.name == "GigabitEthernet0/1"
    assert iface.has_description
    assert iface.ip_address == "10.0.0.1 255.255.255.0"
    assert iface.is_layer3
    assert not iface.is_shutdown


def test_parses_vty_transport_and_timeout():
    cfg = parse_config(
        "line vty 0 4\n"
        " exec-timeout 10 0\n"
        " access-class MGMT in\n"
        " transport input ssh\n"
        "!\n"
    )
    vty = cfg.vty_blocks()[0]
    assert vty.transport_input == ["ssh"]
    assert vty.exec_timeout == (10, 0)
    assert vty.access_class == "MGMT"


def test_parses_snmp_community_with_acl():
    cfg = parse_config("snmp-server community Str0ngStr1ng RO SNMP-HOSTS\n")
    c = cfg.snmp_communities[0]
    assert c.string == "Str0ngStr1ng"
    assert c.access == "RO"
    assert c.acl == "SNMP-HOSTS"


def test_parses_multiline_banner():
    cfg = parse_config(
        "banner login ^C\n"
        "  Authorised access only.\n"
        "^C\n"
        "!\n"
    )
    assert "login" in cfg.banners
    assert "Authorised" in cfg.banners["login"]


def test_banner_body_does_not_leak_into_global_lines():
    """A banner containing config-like text must not be parsed as configuration."""
    cfg = parse_config(
        "banner motd ^C\n"
        "  ip http server\n"
        "^C\n"
        "hostname REAL-HOST\n"
    )
    assert cfg.hostname == "REAL-HOST"
    assert not cfg.has_global(r"^ip http server")


def test_empty_config_does_not_raise():
    cfg = parse_config("")
    assert cfg.hostname == "unknown"
    assert cfg.interfaces == []


# ---------------------------------------------------------------------------
# Rules — true positives
# ---------------------------------------------------------------------------

def ids(result) -> set:
    return {f.rule_id for f in result.findings}


def test_weak_config_flags_the_big_three():
    result = run_audit(parse_config(sample("branch-router-01.cfg")))
    found = ids(result)
    assert "MGMT-001" in found, "should flag missing enable secret"
    assert "VTY-001" in found, "should flag telnet on vty"
    assert "SNMP-001" in found, "should flag default community string"
    assert result.counts_by_severity()["CRITICAL"] >= 3


def test_hardened_config_is_clean():
    result = run_audit(parse_config(sample("core-switch-01.cfg")))
    assert result.failed_count == 0, f"unexpected findings: {ids(result)}"
    assert result.score() == 100
    assert result.grade() == "A"


def test_scores_are_ordered_correctly():
    weak = run_audit(parse_config(sample("branch-router-01.cfg"))).score()
    drifted = run_audit(parse_config(sample("core-switch-01-drifted.cfg"))).score()
    hardened = run_audit(parse_config(sample("core-switch-01.cfg"))).score()
    assert weak < drifted < hardened


def test_every_finding_carries_remediation():
    result = run_audit(parse_config(sample("branch-router-01.cfg")))
    for f in result.findings:
        assert f.remediation, f"{f.rule_id} has no remediation guidance"
        assert f.detail, f"{f.rule_id} has no detail"


def test_rule_ids_are_unique():
    seen = [r.rule_id for r in RULES]
    assert len(seen) == len(set(seen)), "duplicate rule id registered"


# ---------------------------------------------------------------------------
# Per-category scoring (drives the SonarQube-style grade row)
# ---------------------------------------------------------------------------

def test_category_scores_cover_every_category_even_when_clean():
    """A clean device must still list every category, each graded A."""
    result = run_audit(parse_config(sample("core-switch-01.cfg")))
    scores = result.category_scores()
    categories = {r.category for r in RULES}
    assert {cs.category for cs in scores} == categories
    assert all(cs.grade == "A" and cs.is_clean for cs in scores)


def test_category_scores_localise_weakness():
    """The drifted device is weak in specific domains, strong in others."""
    result = run_audit(parse_config(sample("core-switch-01-drifted.cfg")))
    by_cat = {cs.category: cs for cs in result.category_scores()}
    assert by_cat["Management Plane"].grade == "A"
    assert by_cat["Interface Hygiene"].grade == "A"
    assert by_cat["Remote Access"].failed > 0
    assert by_cat["SNMP"].failed > 0


def test_category_scores_are_ordered_consistently():
    """The grade row order is fixed, so it does not jump around between devices."""
    a = [cs.category for cs in run_audit(parse_config(sample("core-switch-01.cfg"))).category_scores()]
    b = [cs.category for cs in run_audit(parse_config(sample("branch-router-01.cfg"))).category_scores()]
    assert a == b


def test_grade_boundaries():
    from netaudit.rules import score_to_grade
    assert score_to_grade(100) == "A"
    assert score_to_grade(90) == "A"
    assert score_to_grade(89) == "B"
    assert score_to_grade(60) == "D"
    assert score_to_grade(59) == "F"
    assert score_to_grade(0) == "F"


# ---------------------------------------------------------------------------
# Rules — false positives
# ---------------------------------------------------------------------------

def test_aux_with_no_exec_is_not_flagged_for_timeout():
    """`no exec` means no session can start, so exec-timeout is not applicable."""
    cfg = parse_config("line aux 0\n no exec\n transport input none\n!\n")
    result = run_audit(cfg)
    timeouts = [f for f in result.findings if f.rule_id == "VTY-004"]
    assert not timeouts


def test_loopback_not_flagged_for_directed_broadcast():
    cfg = parse_config("interface Loopback0\n ip address 10.255.0.1 255.255.255.255\n!\n")
    result = run_audit(cfg)
    assert "INT-002" not in ids(result)


def test_switchport_not_flagged_as_unused_interface():
    cfg = parse_config(
        "interface GigabitEthernet1/0/2\n"
        " switchport mode access\n"
        " switchport access vlan 20\n"
        "!\n"
    )
    result = run_audit(cfg)
    assert "INT-001" not in ids(result)


def test_ntp_auth_not_flagged_when_ntp_absent_entirely():
    """LOG-003 covers missing NTP. LOG-004 should not also fire and double-count."""
    cfg = parse_config("hostname X\n")
    result = run_audit(cfg)
    assert "LOG-003" in ids(result)
    assert "LOG-004" not in ids(result)


def test_strong_snmp_community_with_acl_passes():
    cfg = parse_config(
        "ip access-list standard SNMP-HOSTS\n permit 10.0.0.20\n!\n"
        "snmp-server community V3ryStr0ngC0mmun1ty RO SNMP-HOSTS\n"
    )
    result = run_audit(cfg)
    found = ids(result)
    assert "SNMP-001" not in found
    assert "SNMP-002" not in found
    assert "SNMP-003" not in found


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------

def test_identical_configs_have_no_drift():
    text = sample("core-switch-01.cfg")
    d = compare_configs(text, text)
    assert d.changes == []
    assert d.score_delta == 0


def test_drift_detects_security_regression():
    d = compare_configs(sample("core-switch-01.cfg"), sample("core-switch-01-drifted.cfg"))
    assert d.score_delta < 0, "score should decline"
    assert len(d.security_changes) > 0
    categories = set(d.by_category().keys())
    assert "Remote access transport" in categories
    assert "SNMP exposure" in categories


def test_drift_ignores_comment_and_blank_noise():
    a = "hostname X\n!\n!\nservice password-encryption\n"
    b = "hostname X\n\n\nservice password-encryption\n"
    d = compare_configs(a, b)
    assert d.changes == []


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def test_markdown_report_contains_score_and_findings():
    result = run_audit(parse_config(sample("branch-router-01.cfg")))
    md = to_markdown(result)
    assert "Compliance score" in md
    assert "BR-JKT-RTR-01" in md
    assert "MGMT-001" in md


def test_csv_has_one_row_per_finding_plus_header():
    result = run_audit(parse_config(sample("branch-router-01.cfg")))
    rows = [r for r in to_csv(result).strip().splitlines() if r.strip()]
    assert len(rows) == result.failed_count + 1


def test_remediation_orders_logging_before_access_restriction():
    """Applying an access-class before AAA and logging exist is how you lock yourself out."""
    result = run_audit(parse_config(sample("branch-router-01.cfg")))
    cfgtext = to_remediation_config(result)
    assert cfgtext.index("Logging & Time") < cfgtext.index("Remote Access")


def test_remediation_is_empty_for_clean_device():
    result = run_audit(parse_config(sample("core-switch-01.cfg")))
    assert "No remediation required" in to_remediation_config(result)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
