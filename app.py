"""
NetAudit — Cisco IOS configuration compliance auditor.

Streamlit front end. Run with:  streamlit run app.py
"""

from __future__ import annotations

import html
from pathlib import Path

import pandas as pd
import streamlit as st

from netaudit.drift import compare_configs
from netaudit.llm import LLMConfig, explain_findings
from netaudit.parser import parse_config
from netaudit.report import to_csv, to_markdown, to_remediation_config
from netaudit.rules import RULES, run_audit

SAMPLES_DIR = Path(__file__).parent / "samples"

st.set_page_config(
    page_title="NetAudit",
    page_icon="▚",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Styling
#
# Design intent: an operations console, not a dashboard.
#
# Two decisions carry most of the weight. First, colour is spent only where it
# drives action: critical and high get a hue, medium and low are grey. A tool
# that colours all five severities teaches the reader to ignore colour, which
# defeats the point of having it. Second, machine output is monospace and human
# prose is sans, consistently, so you can always tell which is which without
# reading a word.
# ---------------------------------------------------------------------------

CSS = """
<style>
  :root {
    --ink:      #16181D;
    --paper:    #FCFCFB;
    --panel:    #FFFFFF;
    --rule:     #E3E2DD;
    --rule-2:   #F2F1ED;
    --muted:    #71757E;
    --critical: #A32B22;
    --high:     #A9670F;
    --medium:   #6E7480;
    --low:      #9A9EA6;
    --pass:     #2E6B4F;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }

  /* Streamlit resets ------------------------------------------------ */
  .block-container { padding-top: 3rem !important; max-width: 1140px; }
  section[data-testid="stSidebar"] > div { padding-top: 2.6rem; }

  html, body, [class*="css"] { font-family: var(--sans); }
  h1, h2, h3 { font-family: var(--sans) !important; letter-spacing: -0.015em; }

  .page-title {
    font-size: 1.12rem;
    font-weight: 600;
    color: var(--ink);
    letter-spacing: -0.01em;
    margin-bottom: 0.15rem;
  }
  .page-sub {
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 1.05rem;
  }

  /* --- grade rating colours (A-F), SonarQube convention ------------- */
  /* A clean green, sliding through to a saturated red at F. These are the
     only place saturated colour appears in the whole interface. */
  --grade-a: #2E9C5A;
  --grade-b: #8FB414;
  --grade-c: #C99A06;
  --grade-d: #D9760B;
  --grade-e: #C4401E;
  --grade-f: #A32B22;

  /* --- status bar --------------------------------------------------- */
  .statusbar {
    border: 1px solid var(--rule);
    background: var(--panel);
    padding: 1.05rem 1.2rem 0.95rem 1.2rem;
  }
  .sb-top {
    display: flex;
    align-items: center;
    gap: 1.15rem;
  }
  .sb-badge {
    flex: 0 0 auto;
    width: 62px;
    height: 62px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--sans);
    font-size: 2rem;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.02em;
  }
  .sb-badge.g-A { background: var(--grade-a); }
  .sb-badge.g-B { background: var(--grade-b); }
  .sb-badge.g-C { background: var(--grade-c); }
  .sb-badge.g-D { background: var(--grade-d); }
  .sb-badge.g-E { background: var(--grade-e); }
  .sb-badge.g-F { background: var(--grade-f); }

  .sb-idblock { flex: 1 1 auto; min-width: 0; }
  .sb-host {
    font-family: var(--mono);
    font-size: 1.02rem;
    font-weight: 600;
    color: var(--ink);
    letter-spacing: 0.02em;
  }
  .sb-meta {
    font-family: var(--mono);
    font-size: 0.74rem;
    color: var(--muted);
    margin-top: 0.2rem;
  }
  .sb-scoreblock { flex: 0 0 auto; text-align: right; }
  .sb-score {
    font-family: var(--mono);
    font-size: 1.35rem;
    font-weight: 700;
    color: var(--ink);
    line-height: 1;
  }
  .sb-score .den { font-size: 0.78rem; font-weight: 400; color: var(--muted); }
  .sb-scorelabel {
    font-family: var(--mono);
    font-size: 0.62rem;
    letter-spacing: 0.13em;
    color: var(--low);
    text-transform: uppercase;
    margin-top: 0.25rem;
  }

  /* --- category rating row (SonarQube metric strip) ----------------- */
  .catrow {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
    gap: 0;
    border: 1px solid var(--rule);
    border-top: none;
    background: var(--panel);
  }
  .catcell {
    padding: 0.7rem 0.6rem 0.65rem 0.85rem;
    border-right: 1px solid var(--rule-2);
    display: flex;
    align-items: center;
    gap: 0.55rem;
  }
  .catcell:last-child { border-right: none; }
  .cat-badge {
    flex: 0 0 auto;
    width: 26px;
    height: 26px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--sans);
    font-size: 0.86rem;
    font-weight: 700;
    color: #fff;
  }
  .cat-badge.g-A { background: var(--grade-a); }
  .cat-badge.g-B { background: var(--grade-b); }
  .cat-badge.g-C { background: var(--grade-c); }
  .cat-badge.g-D { background: var(--grade-d); }
  .cat-badge.g-E { background: var(--grade-e); }
  .cat-badge.g-F { background: var(--grade-f); }
  .cat-text { min-width: 0; }
  .cat-name {
    font-size: 0.72rem;
    font-weight: 600;
    color: var(--ink);
    line-height: 1.15;
  }
  .cat-sub {
    font-family: var(--mono);
    font-size: 0.63rem;
    color: var(--muted);
    margin-top: 0.1rem;
  }

  /* --- category heading --------------------------------------------- */
  .cat-head {
    font-family: var(--mono);
    font-size: 0.68rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--rule);
    padding-bottom: 0.34rem;
    margin: 1.7rem 0 0.9rem 0;
  }

  /* --- finding ------------------------------------------------------- */
  .finding {
    border-left: 2px solid var(--rule);
    padding: 0 0 0 0.9rem;
    margin: 0 0 1.35rem 0;
  }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high     { border-left-color: var(--high); }
  .finding.medium   { border-left-color: var(--medium); }
  .finding.low      { border-left-color: var(--low); }

  .f-head {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
    flex-wrap: wrap;
    margin-bottom: 0.3rem;
  }
  .f-sev {
    font-family: var(--mono);
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.13em;
  }
  .f-sev.critical { color: var(--critical); }
  .f-sev.high     { color: var(--high); }
  .f-sev.medium   { color: var(--medium); }
  .f-sev.low      { color: var(--low); }
  .f-id {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
  }
  .f-title {
    font-size: 0.92rem;
    font-weight: 600;
    color: var(--ink);
  }
  .f-ref {
    font-family: var(--mono);
    font-size: 0.67rem;
    color: var(--low);
    margin-left: auto;
  }
  .f-detail {
    font-size: 0.855rem;
    line-height: 1.6;
    color: #3B3F47;
    margin-bottom: 0.6rem;
    max-width: 78ch;
  }

  .f-blocklabel {
    font-family: var(--mono);
    font-size: 0.6rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--low);
    margin-bottom: 0.2rem;
  }
  .f-evidence, .f-remediation {
    font-family: var(--mono);
    font-size: 0.755rem;
    line-height: 1.6;
    padding: 0.5rem 0.7rem;
    white-space: pre-wrap;
    overflow-x: auto;
    margin-bottom: 0.6rem;
  }
  .f-evidence   { background: var(--rule-2); color: #4A4E56; }
  .f-remediation{ background: var(--ink); color: #DFE1E4; }
  .f-remediation .cmt { color: #767C88; }

  /* --- coverage list (clean state) ------------------------------------ */
  .cov-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 0 1.6rem;
  }
  .cov-row {
    font-family: var(--mono);
    font-size: 0.735rem;
    color: var(--muted);
    padding: 0.22rem 0;
    border-bottom: 1px solid var(--rule-2);
    display: flex;
    gap: 0.55rem;
  }
  .cov-row .tick { color: var(--pass); }
  .cov-row .rid { color: var(--low); min-width: 4.7rem; }
  .cov-row .rt { color: #4A4E56; }

  .notice {
    border-left: 2px solid var(--pass);
    background: var(--rule-2);
    padding: 0.6rem 0.9rem;
    font-size: 0.86rem;
    color: #3B3F47;
    margin-bottom: 1.2rem;
  }

  /* --- drift ---------------------------------------------------------- */
  .drift-cat {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 1.15rem 0 0.35rem 0;
  }
  .drift-row {
    font-family: var(--mono);
    font-size: 0.755rem;
    padding: 0.26rem 0.7rem;
    margin-bottom: 1px;
    border-left: 2px solid var(--rule);
    background: var(--rule-2);
    white-space: pre-wrap;
  }
  .drift-row.added   { border-left-color: var(--pass); }
  .drift-row.removed { border-left-color: var(--critical); }
  .drift-sign { font-weight: 700; margin-right: 0.5rem; color: var(--muted); }
  .drift-row.added .drift-sign   { color: var(--pass); }
  .drift-row.removed .drift-sign { color: var(--critical); }

  .empty-state {
    border: 1px dashed var(--rule);
    padding: 2rem;
    text-align: center;
    color: var(--muted);
    font-size: 0.86rem;
  }

  /* --- sidebar -------------------------------------------------------- */
  .sb-brand {
    font-family: var(--mono);
    font-size: 0.86rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: var(--ink);
  }
  .sb-brand-sub {
    font-size: 0.73rem;
    color: var(--muted);
    line-height: 1.45;
    margin-top: 0.3rem;
  }

  button[data-baseweb="tab"] { font-size: 0.86rem !important; }
</style>
"""

st.markdown(CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def esc(s: str) -> str:
    return html.escape(str(s))


def render_remediation_html(lines: list[str]) -> str:
    out = []
    for ln in lines:
        if ln.strip().startswith("!"):
            out.append(f'<span class="cmt">{esc(ln)}</span>')
        else:
            out.append(esc(ln))
    return "\n".join(out)


def render_statusbar(result) -> None:
    """SonarQube-style status: a circular overall grade, device identity, the
    numeric score, and a row of per-category grade badges beneath.

    The category row is the point. A single overall grade tells you a device is
    weak; the row tells you *where*, which is the first thing an engineer needs
    before touching anything.
    """
    grade = result.grade()
    counts = result.counts_by_severity()

    # top band: badge + identity + score
    st.markdown(
        f"""
        <div class="statusbar">
          <div class="sb-top">
            <div class="sb-badge g-{grade}">{grade}</div>
            <div class="sb-idblock">
              <div class="sb-host">{esc(result.hostname)}</div>
              <div class="sb-meta">{result.total_rules} checks &middot; {result.passed_count} passed &middot; {result.failed_count} failed &middot; {counts['CRITICAL']} critical &middot; {counts['HIGH']} high</div>
            </div>
            <div class="sb-scoreblock">
              <div class="sb-score">{result.score()}<span class="den">/100</span></div>
              <div class="sb-scorelabel">compliance</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # category rating row
    cells = []
    for cs in result.category_scores():
        sub = "clean" if cs.is_clean else f"{cs.failed}/{cs.total} failed"
        cells.append(
            f'<div class="catcell">'
            f'<div class="cat-badge g-{cs.grade}">{cs.grade}</div>'
            f'<div class="cat-text">'
            f'<div class="cat-name">{esc(cs.category)}</div>'
            f'<div class="cat-sub">{sub}</div>'
            f'</div></div>'
        )
    st.markdown(f'<div class="catrow">{"".join(cells)}</div>', unsafe_allow_html=True)


def render_finding(f) -> None:
    sev = f.severity.lower()
    parts = [f'<div class="finding {sev}">', '<div class="f-head">']
    parts.append(f'<span class="f-sev {sev}">{esc(f.severity)}</span>')
    parts.append(f'<span class="f-id">{esc(f.rule_id)}</span>')
    parts.append(f'<span class="f-title">{esc(f.title)}</span>')
    if f.reference:
        parts.append(f'<span class="f-ref">{esc(f.reference)}</span>')
    parts.append("</div>")
    parts.append(f'<div class="f-detail">{esc(f.detail)}</div>')

    if f.evidence:
        parts.append('<div class="f-blocklabel">Found in configuration</div>')
        parts.append(f'<div class="f-evidence">{esc(chr(10).join(f.evidence))}</div>')

    if f.remediation:
        parts.append('<div class="f-blocklabel">Remediation</div>')
        parts.append(f'<div class="f-remediation">{render_remediation_html(f.remediation)}</div>')

    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def render_clean_state(result) -> None:
    """Shown when nothing failed.

    A green box saying "all clear" is not evidence of anything. Listing what was
    actually checked is, and it uses the space the box would have wasted.
    """
    st.markdown(
        '<div class="notice">No findings. This device passed every check in the rule set. '
        'The checks that ran are listed below.</div>',
        unsafe_allow_html=True,
    )
    rows = "".join(
        f'<div class="cov-row"><span class="tick">&#10003;</span>'
        f'<span class="rid">{esc(r.rule_id)}</span>'
        f'<span class="rt">{esc(r.title)}</span></div>'
        for r in sorted(result.passed_rules, key=lambda x: x.rule_id)
    )
    st.markdown(f'<div class="cov-grid">{rows}</div>', unsafe_allow_html=True)


def load_sample(name: str) -> str:
    path = SAMPLES_DIR / name
    return path.read_text() if path.exists() else ""


def read_upload(uploaded) -> str:
    return uploaded.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        f'<div class="sb-brand">NETAUDIT</div>'
        f'<div class="sb-brand-sub">Checks a Cisco IOS running-config against '
        f'{len(RULES)} hardening rules modelled on the CIS Cisco IOS Benchmark.</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    mode = st.radio("Task", ["Audit one device", "Compare two snapshots"])

    st.divider()

    sample_files = sorted(p.name for p in SAMPLES_DIR.glob("*.cfg")) if SAMPLES_DIR.exists() else []

    if mode == "Audit one device":
        source = st.radio("Configuration source", ["Use a sample", "Upload a file", "Paste text"])
        config_text = ""

        if source == "Upload a file":
            up = st.file_uploader("running-config", type=["cfg", "txt", "conf", "config"])
            if up:
                config_text = read_upload(up)
        elif source == "Paste text":
            config_text = st.text_area("Paste running-config", height=240,
                                       placeholder="hostname ROUTER-01\n...")
        else:
            if sample_files:
                pick = st.selectbox("Sample", sample_files)
                config_text = load_sample(pick)
            else:
                st.warning("No sample files found in samples/.")

    else:
        st.caption("A is the known-good baseline. B is the device as it stands now.")
        src = st.radio("Source", ["Use samples", "Upload files"])
        baseline_text = current_text = ""

        if src == "Upload files":
            a = st.file_uploader("A — baseline", type=["cfg", "txt", "conf", "config"], key="a")
            b = st.file_uploader("B — current", type=["cfg", "txt", "conf", "config"], key="b")
            if a:
                baseline_text = read_upload(a)
            if b:
                current_text = read_upload(b)
        else:
            if sample_files:
                pa = st.selectbox("A — baseline", sample_files, index=0)
                default_b = min(len(sample_files) - 1, 1)
                pb = st.selectbox("B — current", sample_files, index=default_b)
                baseline_text = load_sample(pa)
                current_text = load_sample(pb)
            else:
                st.warning("No sample files found in samples/.")

    st.divider()
    llm_cfg = LLMConfig.from_env()
    if llm_cfg.is_available:
        st.caption("**Briefing layer** — connected.")
        audience = st.selectbox("Write briefing for", ["engineer", "manager", "auditor"])
    else:
        st.caption(
            "**Briefing layer** — off. Set `ANTHROPIC_API_KEY` to enable. "
            "Every result is produced without it."
        )
        audience = "engineer"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if mode == "Audit one device":
    st.markdown('<div class="page-title">Configuration compliance audit</div>',
                unsafe_allow_html=True)
    st.markdown(
        f'<div class="page-sub">Static analysis of a Cisco IOS running-config against '
        f'{len(RULES)} hardening rules.</div>',
        unsafe_allow_html=True,
    )

    if not config_text.strip():
        st.markdown(
            '<div class="empty-state">Choose a configuration in the sidebar to run an audit.</div>',
            unsafe_allow_html=True,
        )
        st.stop()

    cfg = parse_config(config_text)
    result = run_audit(cfg)

    render_statusbar(result)
    st.write("")

    tab_findings, tab_device, tab_export = st.tabs(["Findings", "Device", "Export"])

    with tab_findings:
        if result.failed_count == 0:
            render_clean_state(result)
        else:
            for category, findings in result.by_category().items():
                st.markdown(f'<div class="cat-head">{esc(category)}</div>', unsafe_allow_html=True)
                for f in findings:
                    render_finding(f)

            with st.expander(f"Checks passed ({result.passed_count})"):
                st.dataframe(
                    pd.DataFrame(
                        [
                            {"Rule": r.rule_id, "Check": r.title,
                             "Severity": r.severity, "Category": r.category,
                             "Reference": r.reference}
                            for r in sorted(result.passed_rules, key=lambda x: x.rule_id)
                        ]
                    ),
                    use_container_width=True, hide_index=True,
                )

        if llm_cfg.is_available and result.failed_count:
            st.divider()
            if st.button("Write remediation briefing"):
                with st.spinner("Writing…"):
                    st.markdown(explain_findings(result, audience, llm_cfg))

    with tab_device:
        s = cfg.summary()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Config lines", s["total_lines"])
        c2.metric("Interfaces", s["interfaces"])
        c3.metric("Shut down", s["interfaces_shutdown"])
        c4.metric("ACLs", s["acls"])

        st.markdown('<div class="cat-head">Interfaces</div>', unsafe_allow_html=True)
        if cfg.interfaces:
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Interface": i.name,
                         "IP": i.ip_address or "—",
                         "Description": "yes" if i.has_description else "—",
                         "Shutdown": "yes" if i.is_shutdown else "—"}
                        for i in cfg.interfaces
                    ]
                ),
                use_container_width=True, hide_index=True,
            )
        else:
            st.caption("No interfaces parsed.")

        st.markdown('<div class="cat-head">Management lines</div>', unsafe_allow_html=True)
        if cfg.line_blocks:
            st.dataframe(
                pd.DataFrame(
                    [
                        {"Line": f"line {b.name}",
                         "Type": b.kind,
                         "Transport in": " ".join(b.transport_input) or "—",
                         "Timeout": f"{b.exec_timeout[0]}m {b.exec_timeout[1]}s" if b.exec_timeout else "—",
                         "Access-class": b.access_class or "—"}
                        for b in cfg.line_blocks
                    ]
                ),
                use_container_width=True, hide_index=True,
            )
        else:
            st.caption("No management lines parsed.")

    with tab_export:
        host = result.hostname
        c1, c2, c3 = st.columns(3)
        c1.download_button("Audit report (.md)", to_markdown(result),
                           file_name=f"{host}-audit.md", mime="text/markdown",
                           use_container_width=True)
        c2.download_button("Findings (.csv)", to_csv(result),
                           file_name=f"{host}-findings.csv", mime="text/csv",
                           use_container_width=True)
        c3.download_button("Remediation (.cfg)", to_remediation_config(result),
                           file_name=f"{host}-remediation.cfg", mime="text/plain",
                           use_container_width=True)
        st.markdown('<div class="cat-head">Remediation preview</div>', unsafe_allow_html=True)
        st.code(to_remediation_config(result), language="text")

else:
    st.markdown('<div class="page-title">Configuration drift</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="page-sub">Compares two snapshots of a device and ranks each change '
        'by security relevance.</div>',
        unsafe_allow_html=True,
    )

    if not baseline_text.strip() or not current_text.strip():
        st.markdown(
            '<div class="empty-state">Choose two snapshots in the sidebar to compare them.</div>',
            unsafe_allow_html=True,
        )
        st.stop()

    drift = compare_configs(baseline_text, current_text)

    c1, c2, c3 = st.columns(3)
    c1.metric("Baseline", f"{drift.baseline_score}/100")
    c2.metric("Current", f"{drift.current_score}/100", delta=drift.score_delta)
    c3.metric("Security-relevant changes", len(drift.security_changes))

    st.markdown(f'<div class="page-sub">{esc(drift.summary_line())}</div>', unsafe_allow_html=True)

    if not drift.changes:
        st.markdown('<div class="notice">The two snapshots are identical.</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown('<div class="cat-head">Security-relevant changes</div>', unsafe_allow_html=True)
        if not drift.security_changes:
            st.markdown('<div class="notice">Nothing security-relevant changed.</div>',
                        unsafe_allow_html=True)
        else:
            for category, changes in drift.by_category().items():
                st.markdown(f'<div class="drift-cat">{esc(category)}</div>', unsafe_allow_html=True)
                for ch in changes:
                    sign = "+" if ch.action == "added" else "−"
                    st.markdown(
                        f'<div class="drift-row {ch.action}">'
                        f'<span class="drift-sign">{sign}</span>{esc(ch.line.strip())}</div>',
                        unsafe_allow_html=True,
                    )

        with st.expander(f"Other changes ({len(drift.routine_changes)})"):
            for ch in drift.routine_changes:
                sign = "+" if ch.action == "added" else "−"
                st.markdown(
                    f'<div class="drift-row">'
                    f'<span class="drift-sign">{sign}</span>{esc(ch.line.strip())}</div>',
                    unsafe_allow_html=True,
                )
