# NetAudit

**Cisco IOS configuration compliance auditor with drift detection.**

Upload a `running-config`. Get back a scored compliance report, evidence for every
finding, and a paste-ready remediation block ordered so it will not lock you out of
the device.

```
100/100  A  CR-JKT-SW-01          0 findings  (C0 H0 M0 L0)
 61/100  D  CR-JKT-SW-01          6 findings  (C2 H4 M0 L0)   <- after one troubleshooting session
  4/100  F  BR-JKT-RTR-01        23 findings  (C3 H8 M9 L3)
```

---

## The problem

Network compliance auditing is still largely manual. Checking a fleet of devices
against a hardening baseline means opening configs one at a time and reading them,
which does not scale past a few dozen devices and produces inconsistent results
depending on who does the reading.

The consequence is that most organisations audit periodically rather than
continuously, and configuration drift goes undetected between audits. A device that
passed in January can be materially less secure by March because of changes made
during troubleshooting that nobody reverted.

That last case is the one this tool was built around. The `samples/` directory
contains a hardened switch scoring 100, and the same switch after a single
troubleshooting session in which someone re-enabled Telnet, added a read-write SNMP
community, removed the management ACL, and commented out the syslog destination.
It scores 61. Every one of those changes is individually defensible in the moment
and collectively serious.

---

## What it does

**Audit** — parses a running-config and evaluates it against 25 hardening rules
modelled on the CIS Cisco IOS Benchmark, covering the management plane, remote
access, unnecessary services, SNMP, logging and time, banners, and interface
hygiene.

**Score** — produces a weighted compliance score out of 100. A critical finding
costs more than a cosmetic one, so one serious gap does not score the same as one
missing banner.

**Evidence** — every finding quotes the actual offending configuration lines. No
finding says only that something is wrong without showing where.

**Remediate** — generates a paste-ready IOS block, emitted in dependency order:
logging and authentication before access restrictions, so that if a later command
drops your session you still have a working authentication path and a record of
what changed.

**Detect drift** — compares two snapshots and classifies each change by security
relevance, so an ACL removal surfaces above a reworded interface description.

**Explain** *(optional)* — generates a written briefing aimed at an engineer, a
manager, or an auditor.

---

## Architecture

```
                  ┌─────────────────────────────────────────────┐
  running-config  │  parser.py     deterministic                │
  ──────────────► │                raw text → structured facts  │
                  └────────────────────┬────────────────────────┘
                                       │
                  ┌────────────────────▼────────────────────────┐
                  │  rules.py      deterministic                │
                  │                25 checks → findings + score │
                  └────────────────────┬────────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
   ┌──────────▼─────────┐   ┌──────────▼─────────┐   ┌──────────▼─────────┐
   │  report.py         │   │  drift.py          │   │  llm.py            │
   │  md / csv / config │   │  snapshot compare  │   │  OPTIONAL          │
   │  deterministic     │   │  deterministic     │   │  explains only     │
   └────────────────────┘   └────────────────────┘   └────────────────────┘
```

**The language model never decides whether a device passes, and never executes
anything.** It receives findings the rule engine has already produced and turns them
into prose. Compliance decisions stay in `rules.py`, where they are reproducible,
testable, and explainable to an auditor.

This is deliberate. A compliance verdict has to give the same answer every time it
runs against the same input. That is the one property a language model does not
offer, and it happens to be the only property that matters here. The pattern —
deterministic control layer, model confined to interpretation and planning — is
where network automation practice has landed more broadly.

---

## Quick start

```bash
git clone https://github.com/<your-username>/netaudit.git
cd netaudit

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`, pick a sample from the sidebar, and run an audit.

### Optional: enable the briefing layer

```bash
cp .env.example .env
# add your key, then:
export ANTHROPIC_API_KEY=sk-ant-...
```

Everything except the written briefing works without a key.

---

## Command line

The web app reads one device carefully. The CLI does the other job: many devices,
on a schedule, in a pipeline.

```bash
# Audit one file
python cli.py audit samples/branch-router-01.cfg

# Audit a directory
python cli.py audit configs/

# Export findings for a ticket system
python cli.py audit configs/ --format csv --output findings.csv

# Generate remediation for every device
python cli.py audit configs/ --format remediation --output fix.cfg

# Fail a build if any device scores below 80
python cli.py audit configs/ --fail-under 80

# Compare two snapshots
python cli.py drift baseline.cfg current.cfg
```

Exit codes: `0` all devices met the threshold, `1` at least one did not, `2` bad
input. The `--fail-under` flag is what makes this usable as a CI gate.

---

## Rule set

25 checks across seven categories.

| Category | Rules | Covers |
|---|---|---|
| Management Plane | `MGMT-001` … `MGMT-005` | enable secret, password encryption, AAA, password length, brute-force protection |
| Remote Access | `VTY-001` … `VTY-005` | Telnet, SSH version, access-class, session timeout, AUX port |
| Unnecessary Services | `SVC-001` … `SVC-004` | HTTP server, small servers, CDP, source routing |
| SNMP | `SNMP-001` … `SNMP-003` | default communities, read-write access, source ACL |
| Logging & Time | `LOG-001` … `LOG-004` | syslog destination, timestamps, NTP, NTP authentication |
| Banner | `BAN-001` | authorised-use notice |
| Interface Hygiene | `INT-001` … `INT-003` | unused interfaces, directed broadcast, proxy ARP |

Severity weighting: `CRITICAL` 10 · `HIGH` 6 · `MEDIUM` 3 · `LOW` 1.

### Adding a rule

```python
@rule("MGMT-006", "Local username uses a weak secret type",
      "HIGH", "Management Plane", "CIS Cisco IOS 1.1.4")
def check_username_secret(cfg: ParsedConfig) -> Finding | None:
    offenders = cfg.find_global(r"^username \S+ password ")
    if not offenders:
        return None
    return _finding(
        _r("MGMT-006"),
        "Local accounts use `password` rather than `secret`, storing credentials "
        "with reversible Type 7 encoding.",
        offenders,
        ["no username <NAME> password <PASS>", "username <NAME> secret <STRONG-SECRET>"],
    )
```

The decorator registers it. Nothing else needs to change: scoring, the report, the
CSV export, and the remediation block all pick it up automatically.

---

## Testing

```bash
pytest -v
```

24 tests. The ones worth reading are the false-positive cases —
`test_aux_with_no_exec_is_not_flagged_for_timeout`,
`test_loopback_not_flagged_for_directed_broadcast`,
`test_switchport_not_flagged_as_unused_interface`.

An audit tool that cries wolf gets ignored, and an ignored tool is worse than no
tool, because it produces the appearance of coverage without the substance. Each of
those tests exists because the rule behind it flagged something it should not have
during development.

---

## Scope and limits

Stated plainly, because a compliance tool that overstates its own coverage has the
same problem it is meant to detect.

- **Cisco IOS and IOS-XE syntax only.** NX-OS, IOS-XR, and other vendors are not
  supported. The parser would need a separate grammar for each.
- **Not a certified CIS assessment.** The rule set is modelled on the CIS Cisco IOS
  Benchmark and does not implement it completely or claim certification.
- **Static analysis only.** It reads a configuration file. It does not connect to
  devices, and it cannot see runtime state, installed software versions, or anything
  that is not in the config text.
- **A passing score is not a security guarantee.** It means the device passed these
  25 checks. Architecture, segmentation, patching, and physical security are all out
  of scope and all matter more than most individual findings here.

---

## Roadmap

- NX-OS and IOS-XR parsers
- Fleet dashboard: score trend across many devices over time
- Direct device collection over SSH, read-only
- Custom baseline definitions in YAML, so an organisation can encode its own standard
- Ansible and NAPALM integration for closed-loop remediation with approval gates

---

## Why this exists

I built this while preparing for network engineering roles, after noticing that
almost every lab exercise teaches you to *configure* a device and almost none teach
you to *review* one. Reviewing is what the job actually involves once the network
exists.

The design constraint I set for myself was that a language model could assist but
could not decide. Working through why that constraint matters — and where the line
between the two sits — taught me more than the code did.

**Faridz Ramadhan Kampi** · Telecommunication Engineering, Telkom University
[LinkedIn](https://linkedin.com/in/faridzkampi)

---

## Licence

MIT
