"""Read-only Streamlit console for FORACE."""
from datetime import datetime, timezone
import html
from pathlib import Path
import re

import pandas as pd
import altair as alt
import streamlit as st

from forace.dashboard_data import (
    filter_findings, get_audit_status, get_audit_summary, get_baseline_status,
    get_database_status, get_monitor_status, load_audit_events,
    load_evaluation_results, load_file_inventory, load_findings, sort_findings,
)
from forace.paths import (
    DEFAULT_BASELINE_PATH, DEFAULT_KEY_PATH, DEFAULT_SIGNATURE_PATH,
    PROJECT_ROOT, default_database_path, project_path,
)


PAGES = [
    ("Overview", "nav_overview", "◈"),
    ("Security Findings", "nav_security_findings", "⌕"),
    ("File Integrity", "nav_file_integrity", "▤"),
    ("Audit & Verification", "nav_audit_and_verification", "✓"),
    ("Evaluation", "nav_evaluation", "▥"),
    ("Demo / About", "nav_demo_about", "ⓘ"),
]

CSS = """
<style>
:root {
  color-scheme: dark;
  --iw-bg: #0a111d;
  --iw-side: #0d1725;
  --iw-surface: #111e2e;
  --iw-surface-raised: #17263a;
  --iw-line: #26384d;
  --iw-text: #e9f0f8;
  --iw-muted: #9aacc0;
  --iw-teal: #55c9bd;
  --iw-blue: #8abaff;
  --iw-green: #61d1a0;
  --iw-amber: #efbd62;
  --iw-red: #f17c85;
}

.stApp { background: var(--iw-bg); color: var(--iw-text); }
[data-testid="stHeader"] { background: var(--iw-bg); }
[data-testid="stSidebar"] { background: var(--iw-side); border-right: 1px solid var(--iw-line); }
.block-container { max-width: 1580px; padding: 1.65rem clamp(1rem, 2.4vw, 2.4rem) 3rem; }
div[data-testid="stHorizontalBlock"] { align-items: stretch; gap: 1rem; }
div[data-testid="column"] { min-width: 0; }

h1, h2, h3 { color: var(--iw-text); letter-spacing: -.025em; }
h1 { font-size: clamp(1.75rem, 2.25vw, 2.25rem); line-height: 1.12; }
h2 { font-size: 1.42rem; }
h3 { font-size: 1.14rem; }
[data-testid="stCaptionContainer"], .iw-muted { color: var(--iw-muted); }
[data-testid="stMarkdownContainer"] h4 { margin: 1.25rem 0 .65rem; font-size: .98rem; color: #d8e5f2; letter-spacing: -.01em; }

[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: var(--iw-muted); }
[data-testid="stSidebar"] [data-testid="stButton"] > button {
  min-height: 2.7rem; padding: .5rem .75rem; border: 1px solid transparent;
  border-radius: 8px; text-align: left; color: #c4d0de; background: transparent;
  transition: background-color .12s ease, border-color .12s ease, color .12s ease;
}
[data-testid="stSidebar"] [data-testid="stButton"] > button:hover {
  background: var(--iw-surface-raised); border-color: var(--iw-line); color: var(--iw-text);
}
[data-testid="stSidebar"] [data-testid="stButton"] > button[kind="primary"] {
  background: #153440; border-color: #28626b; color: #edffff;
}
div[data-testid="stButton"] > button:focus-visible,
[data-testid="stSidebar"] button:focus-visible,
div[data-testid="stTextInput"] input:focus-visible {
  outline: 2px solid var(--iw-teal); outline-offset: 2px;
}

[data-testid="stMetric"] {
  box-sizing: border-box; width: 100%; min-width: 0; min-height: 108px;
  padding: 15px 17px; border: 1px solid var(--iw-line); border-radius: 11px;
  background: var(--iw-surface); box-shadow: 0 4px 14px rgba(0, 0, 0, .12);
}
[data-testid="stMetricLabel"] { color: var(--iw-muted); }
[data-testid="stMetricLabel"] > div { white-space: normal !important; line-height: 1.3; }
[data-testid="stMetricValue"] { color: var(--iw-text); }
[data-testid="stMetricValue"] > div {
  white-space: normal !important; overflow-wrap: anywhere; line-height: 1.15;
  font-size: clamp(1.15rem, 1.6vw, 1.65rem);
}

div[data-testid="stDataFrame"] {
  box-sizing: border-box; width: 100%; max-width: 100%;
  border: 1px solid var(--iw-line); border-radius: 9px; overflow: auto;
  background: var(--iw-surface);
}
div[data-testid="stExpander"] {
  border: 1px solid var(--iw-line); border-radius: 9px; background: var(--iw-surface);
}
div[data-testid="stTextInput"] input,
div[data-testid="stSelectbox"] [data-baseweb="select"] > div,
div[data-testid="stMultiSelect"] [data-baseweb="select"] > div {
  background: var(--iw-surface); color: var(--iw-text); border-color: var(--iw-line);
}
div[data-testid="stButton"] > button { border: 1px solid var(--iw-line); border-radius: 8px; min-height: 2.55rem; }
div[data-testid="stButton"] > button[kind="primary"] { background: #153c45; border-color: #27636a; color: #e9ffff; }

.iw-brand { color: var(--iw-text); font-size: 1.08rem; font-weight: 760; letter-spacing: -.025em; }
.iw-brand span { color: var(--iw-teal); }
.iw-kicker { color: var(--iw-teal); font-size: .68rem; font-weight: 750; letter-spacing: .15em; text-transform: uppercase; }
.iw-page-head { margin: .25rem 0 1.1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--iw-line); }
.iw-page-sub { margin-top: -.55rem; color: var(--iw-muted); line-height: 1.5; }
.iw-status {
  box-sizing: border-box; height: 100%; min-height: 112px; padding: 14px 16px;
  border: 1px solid var(--iw-line); border-left: 3px solid var(--iw-blue);
  border-radius: 9px; background: var(--iw-surface);
}
.iw-status-title { color: var(--iw-muted); font-size: .69rem; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.iw-status-value { margin: .38rem 0; color: var(--iw-text); font-size: .96rem; font-weight: 780; }
.iw-status-message { color: var(--iw-muted); font-size: .77rem; line-height: 1.45; overflow-wrap: anywhere; }
.iw-tone-good { border-left-color: var(--iw-green); }
.iw-tone-warn { border-left-color: var(--iw-amber); }
.iw-tone-bad { border-left-color: var(--iw-red); }
.iw-tone-info { border-left-color: var(--iw-blue); }
.iw-tone-good .iw-status-value { color: var(--iw-green); }
.iw-tone-warn .iw-status-value { color: var(--iw-amber); }
.iw-tone-bad .iw-status-value { color: var(--iw-red); }
.iw-tone-info .iw-status-value { color: var(--iw-blue); }
.iw-severity-critical { color: var(--iw-red); font-weight: 750; }
.iw-severity-high { color: #f2a47e; font-weight: 750; }
.iw-severity-medium { color: var(--iw-amber); font-weight: 750; }
.iw-severity-low { color: var(--iw-blue); font-weight: 750; }
.iw-badge { display: inline-block; padding: 3px 8px; border: 1px solid currentColor; border-radius: 5px; font-size: .7rem; font-weight: 750; letter-spacing: .05em; }
.iw-badge-critical { color: var(--iw-red); }
.iw-badge-high { color: #f2a47e; }
.iw-badge-medium { color: var(--iw-amber); }
.iw-badge-low { color: var(--iw-blue); }
.iw-architecture { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .75rem; margin: .8rem 0 1rem; }
.iw-architecture-step { min-width: 0; padding: 15px; border: 1px solid var(--iw-line); border-radius: 10px; background: var(--iw-surface); }
.iw-architecture-index { color: var(--iw-teal); font-size: .68rem; font-weight: 750; letter-spacing: .12em; }
.iw-architecture-title { margin: .55rem 0 .35rem; color: var(--iw-text); font-size: .9rem; font-weight: 720; }
.iw-architecture-copy { color: var(--iw-muted); font-size: .75rem; line-height: 1.45; }
.iw-severity-strip { display: flex; flex-wrap: wrap; gap: .55rem; margin: .8rem 0; }
.iw-severity-chip { padding: 5px 9px; border: 1px solid var(--iw-line); border-radius: 6px; background: var(--iw-surface); font-size: .75rem; }
.iw-severity-chip strong { margin-left: .3rem; color: var(--iw-text); }

@media (max-width: 1100px) {
  .block-container { padding-right: 1.25rem; padding-left: 1.25rem; }
  div[data-testid="stHorizontalBlock"] { flex-wrap: wrap !important; }
  div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {
    flex: 1 1 calc(50% - .5rem) !important; min-width: calc(50% - .5rem) !important;
  }
  .iw-architecture { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 680px) {
  .block-container { padding: 1rem .85rem 2rem; }
  h1 { font-size: 1.65rem; }
  div[data-testid="stHorizontalBlock"] { gap: .7rem; }
  div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {
    flex: 1 1 100% !important; min-width: 100% !important; max-width: 100% !important;
  }
  .iw-architecture { grid-template-columns: 1fr; }
  .iw-status { min-height: 0; }
}
</style>
"""

def _project_path(value: str | Path) -> str:
    return str(project_path(value))


def _default_paths() -> dict[str, str]:
    try:
        database = str(default_database_path())
    except ValueError:
        database = ""
    return {
        "db": database,        "baseline": _project_path(DEFAULT_BASELINE_PATH),
        "key": _project_path(DEFAULT_KEY_PATH),
        "signature": _project_path(DEFAULT_SIGNATURE_PATH),
        "monitor": _project_path("data/monitor_status.json"),
        "evaluation": _project_path("results.csv"),
        "root": _project_path("lab"),
    }


def _status_card(title, status, message, icon="•"):
    tones = {"verified": "good", "valid": "good", "available": "good", "running": "good",
             "failed": "bad", "invalid": "bad", "error": "bad", "missing": "warn",
             "empty": "warn", "not_running": "info", "unavailable": "info"}
    shown = {"verified": "VERIFIED", "valid": "VALID", "available": "AVAILABLE",
             "running": "RUNNING", "failed": "FAILED", "invalid": "INVALID",
             "error": "ERROR", "missing": "MISSING", "empty": "EMPTY",
             "not_running": "NOT RUNNING", "unavailable": "UNAVAILABLE"}.get(status, status.upper())
    tone = tones.get(status, "info")
    st.markdown(
        f'<div class="iw-status iw-tone-{tone}"><div class="iw-status-title">{html.escape(icon)} &nbsp;{html.escape(title)}</div>'
        f'<div class="iw-status-value">{html.escape(shown)}</div>'
        f'<div class="iw-status-message">{html.escape(message)}</div></div>', unsafe_allow_html=True)


def _page_header(title, subtitle, section):
    st.markdown(f'<div class="iw-kicker">{html.escape(section)}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<div class="iw-page-sub iw-page-head">{html.escape(subtitle)}</div>', unsafe_allow_html=True)


def _severity_counts(findings):
    return {level: sum(row.get("severity") == level for row in findings)
            for level in ("Critical", "High", "Medium", "Low")}


def _clear_finding_filters():
    st.session_state["iw_findings_search"] = ""
    st.session_state["iw_findings_severity"] = []
    st.session_state["iw_findings_sort"] = "Newest first"


def _status_bundle(db_path, baseline_path, key_path, signature_path, monitor_path):
    return {
        "database": get_database_status(db_path),
        "baseline": get_baseline_status(baseline_path, key_path, signature_path),
        "audit": get_audit_status(db_path),
        "monitor": get_monitor_status(monitor_path),
    }


def _render_health_summary(bundle, paths):
    cards = (("baseline", "Baseline HMAC", "⌑"), ("audit", "Audit SHA-256 chain", "⌁"),
             ("database", "SQLite database", "▤"), ("monitor", "Filesystem monitoring", "◉"))
    cols = st.columns(4)
    for col, (key, title, icon) in zip(cols, cards):
        with col:
            state = bundle[key]
            _status_card(title, state["status"], state["message"], icon)

    baseline = bundle["baseline"]
    availability = lambda key: "AVAILABLE" if baseline[key] else "MISSING"
    st.caption(
        f"Baseline file: {availability('baseline_available')} · "
        f"HMAC key file: {availability('key_available')} · "
        f"Detached signature: {availability('signature_available')} · "
        f"Selected baseline: {paths['baseline']} · key contents are never displayed"
    )
    if baseline["status"] != "verified":
        st.warning(
            "This baseline is not trusted for comparison because authentication failed. For an "
            "existing baseline, restore its matching key from a protected backup. If the original "
            "key is unavailable, review the lab and deliberately create a new baseline and key "
            "through the authorized initialization flow; dashboard refreshes never replace trust files."
        )

    if bundle["audit"]["status"] == "empty":
        st.info("EMPTY · no audit records exist yet; this is not a verified chain.")

    monitor_error = bundle["monitor"].get("last_error")
    if monitor_error:
        st.warning(f"Monitoring is live, but the latest scan reported an error: {monitor_error}")


def _render_severity_strip(findings):
    counts = _severity_counts(findings)
    levels = ("Critical", "High", "Medium", "Low")
    chips = "".join(
        f'<span class="iw-severity-chip iw-severity-{level.casefold()}">{level}<strong>{counts[level]}</strong></span>'
        for level in levels
    )
    st.markdown(f'<div class="iw-severity-strip">{chips}</div>', unsafe_allow_html=True)


def _render_monitored_files_summary(paths):
    st.markdown("#### Monitored files")
    try:
        inventory = load_file_inventory(paths["root"], paths["baseline"], paths["key"], paths["signature"])
    except (OSError, ValueError) as error:
        st.warning(f"File summary unavailable: {error}")
        return

    rows = inventory["files"]
    states = [row["integrity_state"] for row in rows]
    changed = sum(state in {"Added", "Modified", "Deleted", "Permission changed", "Ownership changed"}
                  for state in states)
    summary = {
        "Files scanned": len(rows),
        "Verified": states.count("Unchanged"),
        "Changes": changed,
        "Unverified": states.count("Unverified"),
    }
    st.caption(f"Current inventory · {inventory['root_directory']} · baseline {inventory['baseline_status'].upper()}")
    cols = st.columns(4)
    for col, (label, value) in zip(cols, summary.items()):
        col.metric(label, value)
    inaccessible = states.count("Inaccessible")
    if inaccessible:
        st.caption(f"{inaccessible} file(s) could not be read and remain marked Inaccessible.")
    elif not rows:
        st.info("No regular files were found in the selected monitored directory.")


def _sidebar(paths, statuses):
    st.sidebar.markdown('<div class="iw-brand">◈ &nbsp;FORACE</div>', unsafe_allow_html=True)
    st.sidebar.caption("File Integrity Monitoring Console")
    st.sidebar.markdown("**WORKSPACE**")

    for label, key, icon in PAGES:
        st.sidebar.button(
    		f"{icon}  {label}",
    		key=key,
    		type="primary" if st.session_state.get("iw_page", "Overview") == label else "secondary",
    		width="stretch",
    		on_click=lambda selected_page=label: st.session_state.update({"iw_page": selected_page}),
	)

    st.sidebar.markdown("**SYSTEM STATUS**")
    for name, state in (("Database", statuses["database"]), ("Baseline", statuses["baseline"]),
                        ("Audit chain", statuses["audit"]), ("Monitoring", statuses["monitor"])):
        status = state["status"]
        marker = "●" if status in {"available", "verified", "valid", "running"} else "○"
        st.sidebar.caption(f"{marker}  {name} · {status.replace('_', ' ').upper()}")
    with st.sidebar.expander("Data source paths", expanded=False):
        st.text_input("SQLite database", value=paths["db"], key="iw_db_path")
        st.text_input("Baseline JSON", value=paths["baseline"], key="iw_baseline_path")
        st.text_input("HMAC key file", value=paths["key"], key="iw_key_path", type="password")
        st.text_input("Detached signature", value=paths["signature"], key="iw_signature_path")
        st.text_input("Monitor status file", value=paths["monitor"], key="iw_monitor_path")
        st.text_input("Evaluation CSV", value=paths["evaluation"], key="iw_evaluation_path")
        st.caption(f"Monitored directory (fixed to project lab/): {paths['root']}")


def render_overview(bundle, findings, audit_events, loaded, paths):
    _page_header("FORACE", "File Integrity Monitoring & Security Change Intelligence.", "SECURITY OVERVIEW")
    st.caption(f"Dashboard refreshed {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} · monitoring {bundle['monitor']['status'].replace('_', ' ')}")
    _render_health_summary(bundle, paths)
    st.markdown("#### Findings summary")
    counts = _severity_counts(findings)
    metrics = st.columns(5)
    metrics[0].metric("Total findings", loaded["count"] if loaded["status"] == "available" else "—")
    for col, severity in zip(metrics[1:], counts):
        col.metric(severity, counts[severity])
    if loaded["status"] != "available":
        st.info("Findings and activity summaries are unavailable until the selected database can be read.")
    elif not findings:
        st.info("No findings are stored yet. Once monitoring records a change, severity and rule analytics will appear here.")
    else:
        _render_severity_strip(findings)
    left, right = st.columns([1, 1])
    with left:
        st.markdown("#### Severity distribution")
        if findings:
            severity_data = pd.DataFrame({"Severity": list(counts), "Findings": list(counts.values())})
            st.bar_chart(severity_data, x="Findings", y="Severity", horizontal=True,
                         color="#4cc9bd", height=220)
        else:
            st.caption("Severity analytics will appear when findings are recorded.")
    with right:
        st.markdown("#### Rule activity")
        rules = pd.Series([row.get("rule_id") for row in findings if row.get("rule_id")]).value_counts().sort_index()
        if rules.empty:
            st.caption("Rule activity will appear when security findings are recorded.")
        else:
            rules_frame = rules.rename_axis("Rule").reset_index(name="Findings")
            st.bar_chart(rules_frame, x="Findings", y="Rule", horizontal=True,
                         color="#83b6ff", height=220)
    left, right = st.columns([1, 1])
    with left:
        st.markdown("#### Security event timeline")
        if findings:
            frame = pd.DataFrame(findings)
            frame["day"] = pd.to_datetime(frame["timestamp_utc"], utc=True, errors="coerce").dt.floor("D")
            timeline = frame.dropna(subset=["day"]).groupby("day").size().rename("Findings").reset_index()
            st.area_chart(timeline, x="day", y="Findings", color="#4cc9bd", height=190)
        else:
            st.caption("No security events to plot yet.")
    with right:
        st.markdown("#### Recent findings")
        if findings:
            recent = pd.DataFrame(findings[:5])[ ["timestamp_utc", "severity", "file_path", "change_type", "rule_id"] ]
            recent.columns = ["Timestamp (UTC)", "Severity", "File path", "Change", "Rule"]
            st.dataframe(recent, width="stretch", hide_index=True, column_config={
                "Timestamp (UTC)": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
                "File path": st.column_config.TextColumn(width="medium"),
                "Change": st.column_config.TextColumn(width="medium"),
            })
        else:
            st.caption("No recent findings.")
    st.markdown("#### Recent audit activity")
    if audit_events["status"] != "available":
        st.info(audit_events["message"])
    elif audit_events["events"]:
        st.dataframe(pd.DataFrame([{"Timestamp (UTC)": e["timestamp_utc"], "Event": e["event_type"], "Summary": e["summary"]}
                                   for e in audit_events["events"][:6]]), width="stretch", hide_index=True)
    else:
        st.caption("Audit is EMPTY: no records have been written yet.")
    _render_monitored_files_summary(paths)
    st.markdown("#### Quick insights")
    insight_cols = st.columns(4)
    rule_counts = pd.Series([row.get("rule_id") for row in findings if row.get("rule_id")]).value_counts()
    file_counts = pd.Series([row.get("file_path") for row in findings if row.get("file_path")]).value_counts()
    latest = findings[0] if findings else None
    insight_cols[0].metric("Most triggered rule", rule_counts.index[0] if not rule_counts.empty else "—")
    insight_cols[1].metric("Most affected file", file_counts.index[0] if not file_counts.empty else "—")
    insight_cols[2].metric("Latest security event", latest.get("timestamp_utc", "—") if latest else "—")
    insight_cols[3].metric("Monitoring", bundle["monitor"]["status"].replace("_", " ").upper())


def render_findings(loaded):
    _page_header("Security Findings", "Investigate detected file changes and their security implications.", "DETECTION & RESPONSE")
    st.caption("Stored SQLite findings with rule, severity, explanation and ATT&CK context.")
    if loaded["status"] != "available":
        st.warning(loaded["message"])
    elif loaded["findings"]:
        _render_severity_strip(loaded["findings"])
    c1, c2, c3, c4 = st.columns([2.2, 1.2, 1.25, .8])
    with c1:
        query = st.text_input("Search findings", placeholder="File path, rule, technique, explanation…", key="iw_findings_search")
    with c2:
        severities = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=[], key="iw_findings_severity")
    with c3:
        order = st.selectbox("Sort by", ["Newest first", "Oldest first", "Severity", "File path"], key="iw_findings_sort")
    with c4:
        st.markdown(" ")
        st.button("Clear filters", key="iw_clear_findings", width="stretch", on_click=_clear_finding_filters)
    visible = sort_findings(filter_findings(loaded["findings"], query, severities), order)
    st.caption(f"Showing {len(visible)} of {loaded['count']} stored findings")
    if not visible:
        if loaded["status"] != "available":
            st.info("Finding records cannot be listed until the selected database is available.")
        elif loaded["findings"]:
            st.info("No findings match these filters. Adjust search or severity, or use Clear filters to restore the full list.")
        else:
            st.info("No findings have been recorded yet. The database is available for future monitored events.")
        return
    cols = ["timestamp_utc", "severity", "file_path", "change_type", "rule_id"]
    frame = pd.DataFrame([{k: row.get(k) for k in cols} for row in visible])
    frame.columns = ["Timestamp (UTC)", "Severity", "File path", "Change type", "Rule ID"]
    st.dataframe(frame, width="stretch", hide_index=True, column_config={
        "Timestamp (UTC)": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
        "Severity": st.column_config.TextColumn(width="small"),
        "File path": st.column_config.TextColumn(width="medium"),
        "Change type": st.column_config.TextColumn(width="medium"),
    })
    st.markdown("#### Finding details")
    for index, finding in enumerate(visible):
        heading = f"{finding.get('severity') or 'Unclassified'} · {finding.get('rule_id') or finding.get('change_type')} · {finding.get('file_path')}"
        with st.expander(heading, expanded=(index == 0)):
            severity = finding.get("severity") or "Unclassified"
            badge_tone = severity.casefold() if severity.casefold() in {"critical", "high", "medium", "low"} else "low"
            st.markdown(f'<span class="iw-badge iw-badge-{badge_tone}">{html.escape(severity.upper())}</span>', unsafe_allow_html=True)
            st.write(f"**What changed:** {finding.get('change_type') or 'Not recorded'}")
            st.write(f"**Why it matters:** {finding.get('explanation') or 'No explanation was stored.'}")
            st.write(f"**Rule:** {finding.get('rule_id') or 'Unmapped'} · **Severity:** {finding.get('severity') or 'Unclassified'}")
            if finding.get("attack_id"):
                technique = finding["attack_id"]
                if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                    st.markdown(f"**MITRE ATT&CK:** [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)")
                else:
                    st.write(f"**MITRE ATT&CK:** {technique}")
            st.caption(f"Finding record {finding.get('id')} · {finding.get('timestamp_utc')}")


def render_file_integrity(root, baseline_path, key_path, signature_path):
    _page_header("File Integrity", "Explore the monitored sandbox and compare it with its authenticated baseline.", "FILESYSTEM INVENTORY")
    try:
        inventory = load_file_inventory(root, baseline_path, key_path, signature_path)
    except (OSError, ValueError) as error:
        st.error(f"File inventory unavailable: {error}")
        return
    if inventory["baseline_status"] == "verified":
        st.success(f"Baseline authenticated for {inventory['root_directory']}")
    else:
        st.warning(f"Baseline comparison unavailable · {inventory['baseline_message']}. Current files are shown as Unverified.")
    rows = inventory["files"]
    if not rows:
        st.info(f"No regular files were found in {inventory['root_directory']}.")
        return
    state_values = sorted({row["integrity_state"] for row in rows})
    c1, c2 = st.columns([2, 1])
    query = c1.text_input("Search file paths", placeholder="Filter the inventory", key="iw_file_search")
    selected = c2.multiselect("Integrity state", state_values, default=state_values, key="iw_file_states")
    visible = [row for row in rows if query.casefold() in row["file_path"].casefold() and row["integrity_state"] in selected]
    st.caption(f"{len(visible)} of {len(rows)} files · root {inventory['root_directory']} · full SHA-256 is available in each file's details.")
    if not visible:
        st.info("No files match the current search and integrity filters.")
        return
    frame = pd.DataFrame([{k: row[k] for k in ("file_path", "integrity_state", "size", "modified_utc")} for row in visible])
    frame.columns = ["File path", "Integrity state", "Size (bytes)", "Modified (UTC)"]
    st.dataframe(frame, width="stretch", hide_index=True, column_config={
        "File path": st.column_config.TextColumn(width="large"),
        "Integrity state": st.column_config.TextColumn(width="small"),
        "Size (bytes)": st.column_config.NumberColumn(format="%d", width="small"),
        "Modified (UTC)": st.column_config.TextColumn(width="medium"),
    })
    st.markdown("#### File details")
    for index, row in enumerate(visible):
        with st.expander(f"{row['integrity_state']} · {row['file_path']}", expanded=(index == 0)):
            if isinstance(row["details"], dict):
                st.markdown("**File path**")
                st.code(row["file_path"], language=None)
                digest = row["details"].get("sha256")
                st.markdown("**SHA-256**")
                st.code(digest or "—", language=None)
                st.caption(
                    f"Size {row['size']} bytes · mode {row['permissions']} · "
                    f"UID {row['uid']} · GID {row['gid']} · mtime {row['modified_utc']}"
                )
            else:
                st.warning(f"File could not be scanned: {row['details']}")


def render_audit(paths, bundle):
    _page_header("Audit & Verification", "Inspect baseline trust, audit-chain integrity and local storage health.", "TRUST & EVIDENCE")
    if st.button("Re-check status", key="iw_recheck", type="primary"):
        st.rerun()
    baseline = bundle["baseline"]
    audit = bundle["audit"]
    db = bundle["database"]
    summary = get_audit_summary(paths["db"])
    checked_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    _render_health_summary(bundle, paths)
    with st.container(border=True):
        st.markdown("#### Baseline trust artifacts")
        artifact_cols = st.columns(4)
        artifact_cols[0].metric("Baseline file", "AVAILABLE" if baseline["baseline_available"] else "MISSING")
        artifact_cols[1].metric("HMAC key", "AVAILABLE" if baseline["key_available"] else "MISSING")
        artifact_cols[2].metric("Detached signature", "AVAILABLE" if baseline["signature_available"] else "MISSING")
        artifact_cols[3].metric("Authentication", baseline["status"].upper())
        st.caption(f"Checked {checked_at} · key contents are never displayed.")

    with st.container(border=True):
        st.markdown("#### Audit chain")
        a, b, c = st.columns(3)
        a.metric("Audit records", summary["count"] if summary["status"] == "available" else "—")
        b.metric("First record", summary["first_timestamp"] or "—")
        c.metric("Latest record", summary["latest_timestamp"] or "—")
        if audit["status"] == "invalid":
            st.error(f"INVALID · first integrity failure at record {audit.get('record_id')}: {audit['message']}")
        elif audit["status"] == "error":            st.error(f"UNAVAILABLE · {audit['message']}")
        elif audit["status"] == "valid":
            st.success(f"VALID · checked {audit.get('records_checked', 0)} records. Genesis record is present.")

    with st.container(border=True):
        st.markdown("#### Database")
        st.write(f"Accessibility: **{db['status'].upper()}** · findings: **{db.get('finding_count', '—')}** · audit records: **{summary['count'] if summary['status'] == 'available' else '—'}**")

    with st.expander("What verification means and its limits"):
        st.write("HMAC-SHA256 authenticates the exact baseline bytes using a protected secret key. The audit log links each record to its predecessor with SHA-256, so edits or removals can be detected during verification. This is tamper-evident storage, not tamper-proof storage; protect the database and keep independent backups.")



def render_evaluation(evaluation):
    _page_header(
        "Detection Performance & Evaluation",
        "Measured scenario results for smart and hash-only detection.",
        "EVALUATION",
    )

    if evaluation["status"] != "available":
        st.warning(evaluation["message"])
        return

    metrics = evaluation["metrics"]

    st.markdown("#### Detection performance")
    a, b, c = st.columns(3)
    a.metric("Smart detection rate", f"{metrics['detection_rate']:.1%}")
    b.metric("False-positive rate", f"{metrics['false_positive_rate']:.1%}")
    c.metric("False-negative rate", f"{metrics['false_negative_rate']:.1%}")

    d, e, f = st.columns(3)
    d.metric("Attack scenarios", metrics["total_attack_scenarios"])
    e.metric("Attacks detected", metrics["successfully_detected_attack_scenarios"])
    f.metric("Benign scenarios", metrics["total_benign_scenarios"])

    st.caption(
        "Rates are calculated from the scenarios in the selected results CSV. "
        "Synthetic scenarios are useful for repeatable checks; they do not "
        "establish real-world detection performance."
    )

    # Chart 1: Smart vs. hash-only detection
    st.markdown("#### Smart vs. hash-only")

    comparison = pd.DataFrame({
        "Mode": ["Smart", "Hash-only"],
        "Detection rate": [
            metrics["detection_rate"],
            metrics["hash_only_attack_detection_rate"],
        ],
    })

    comparison_chart = (
        alt.Chart(comparison)
        .mark_bar(color="#55c9bd", cornerRadiusEnd=5)
        .encode(
            x=alt.X(
                "Detection rate:Q",
                axis=alt.Axis(format="%", title="Detection rate"),
                scale=alt.Scale(domain=[0, 1]),
            ),
            y=alt.Y("Mode:N", title=None, sort=None),
            tooltip=[
                alt.Tooltip("Mode:N"),
                alt.Tooltip("Detection rate:Q", format=".1%"),
            ],
        )
        .properties(height=130)
    )

    st.altair_chart(comparison_chart, width="stretch")

    # Chart 2: Detection and false-positive rates
    st.markdown("#### Detection and false-positive rates")

    benign_count = metrics["total_benign_scenarios"]
    hash_fp_rate = (
        metrics["hash_only_benign_alert_scenarios"] / benign_count
        if benign_count else 0.0
    )

    rates = pd.DataFrame({
        "Measure": [
            "Smart detection",
            "Hash-only detection",
            "Smart false positives",
            "Hash-only false positives",
        ],
        "Rate": [
            metrics["detection_rate"],
            metrics["hash_only_attack_detection_rate"],
            metrics["false_positive_rate"],
            hash_fp_rate,
        ],
    })

    rates_chart = (
        alt.Chart(rates)
        .mark_bar(color="#83b6ff", cornerRadiusEnd=5)
        .encode(
            x=alt.X(
                "Rate:Q",
                axis=alt.Axis(format="%", title="Rate"),
                scale=alt.Scale(domain=[0, 1]),
            ),
            y=alt.Y("Measure:N", title=None, sort=None),
            tooltip=[
                alt.Tooltip("Measure:N"),
                alt.Tooltip("Rate:Q", format=".1%"),
            ],
        )
        .properties(height=190)
    )

    st.altair_chart(rates_chart, width="stretch")

    # Rule coverage table
    st.markdown("#### Rule coverage")

    coverage = pd.DataFrame([
        {"Rule": rule, **data}
        for rule, data in metrics["rule_wise_coverage"].items()
    ])

    if not coverage.empty:
        if "coverage" in coverage.columns:
            coverage["coverage"] = coverage["coverage"].map(
                lambda value: f"{value:.0%}"
                if isinstance(value, (int, float))
                else value
            )

        st.dataframe(
            coverage,
            width="stretch",
            hide_index=True,
            column_config={
                "Rule": st.column_config.TextColumn("Rule", width="small"),
                "scenarios": st.column_config.NumberColumn("Scenarios", width="small"),
                "detected": st.column_config.NumberColumn("Detected", width="small"),
                "missed": st.column_config.NumberColumn("Missed", width="small"),
                "coverage": st.column_config.TextColumn("Coverage", width="small"),
            },
        )
    else:
        st.info("No rule coverage data is available.")

    # Benign scenario table
    st.markdown("#### Benign scenario results")

    benign = [
        row for row in evaluation["rows"]
        if row["category"] == "benign"
    ]

    benign_frame = pd.DataFrame(benign)

    if not benign_frame.empty:
        st.dataframe(
            benign_frame,
            width="stretch",
            hide_index=True,
            column_config={
                "scenario_id": st.column_config.TextColumn("Scenario", width="small"),
                "category": st.column_config.TextColumn("Category", width="small"),
                "description": st.column_config.TextColumn("Description", width="large"),
                "expected_rule_id": st.column_config.TextColumn("Expected rule", width="small"),
                "smart_expected_rule_detected": st.column_config.CheckboxColumn(
                    "Smart detection", width="small"
                ),
                "smart_finding_count": st.column_config.NumberColumn(
                    "Finding count", width="small"
                ),
            },
        )
    else:
        st.info("No benign scenario results are available.")
    # Attack scenario outcomes
    with st.expander("Attack scenario outcomes"):
        attacks = [
            row for row in evaluation["rows"]
            if row["category"] == "attack"
        ]

        attacks_frame = pd.DataFrame(attacks)

        if not attacks_frame.empty:
            st.dataframe(
                attacks_frame,
                width="stretch",
                hide_index=True,
            )
        else:
            st.info("No attack scenario results are available.")

    with st.expander("Methodology and limits"):
        st.write(
            "Each CSV row is one recorded scenario. Detection rate is detected "
            "attack scenarios divided by attack scenarios; false-positive rate "
            "is benign scenarios that produced alerts divided by benign scenarios; "
            "false-negative rate is missed attack scenarios divided by attack "
            "scenarios. Results depend on the small controlled scenario set, "
            "current rules and labels."
        )



def render_demo():
    _page_header("Project Overview", "A local, explainable file integrity monitor for controlled security labs.", "DEMO / ABOUT")
    problem, objectives = st.columns(2)
    with problem:
        st.markdown("#### Problem")
        st.write("A hash can prove a file changed, but it does not explain whether a configuration change creates risk. Analysts need the affected file, the specific change, and its security meaning in one place.")
    with objectives:
        st.markdown("#### Project objectives")
        st.write("FORACE combines SHA-256 inventory, authenticated baselines, semantic rules, and MITRE ATT&CK context to make changes easier to investigate without hiding uncertainty.")

    st.markdown("#### Security architecture")
    stages = (
        ("01", "Inventory", "Read lab files and record hashes and metadata."),
        ("02", "Authenticate", "Verify exact baseline bytes with HMAC-SHA256."),
        ("03", "Analyze", "Classify configuration changes with semantic rules."),
        ("04", "Monitoring", "Combine Watchdog events and periodic reconciliation."),
        ("05", "Investigate", "Review explanations, ATT&CK context, and audit evidence."),
    )
    diagram = "".join(
        f'<div class="iw-architecture-step"><div class="iw-architecture-index">{number}</div>'
        f'<div class="iw-architecture-title">{title}</div><div class="iw-architecture-copy">{copy}</div></div>'
        for number, title, copy in stages
    )
    st.markdown(f'<div class="iw-architecture">{diagram}</div>', unsafe_allow_html=True)

    st.markdown("#### Technical components")
    st.caption("Python · Streamlit · SQLite · Watchdog · SHA-256 · HMAC-SHA256 · PyYAML · Pandas · MITRE ATT&CK mapping")

    st.markdown("#### Repeatable demonstration")
    with st.container(border=True):
        st.code("""# Run the isolated demonstration; source lab files are copied, not modified
python demo.py

# Retain a temporary workspace so its database and trust files can be loaded in the dashboard
python demo.py --keep

# Read-only baseline comparison and audit-chain verification
python -m forace verify --lab lab
python -m forace verify-log
python -m forace report

# Dashboard
streamlit run dashboard.py""", language="bash")
    st.info("Each installation uses its own authenticated trust anchor under data/. Personal recovery bundles from the original development environment are not included in this repository.")
    st.markdown("#### Limitations")
    st.write("Each installation creates its own authenticated baseline and trust anchor. The audit chain is tamper-evident, not tamper-proof. Protect the database and keep independent backups. Evaluation results come from a small synthetic scenario set and are not real-world performance claims.")
    st.caption("Demo commands use the existing isolated workflow. The dashboard only reads selected records and files.")


def main():
    st.set_page_config(page_title="FORACE", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    st.markdown(CSS, unsafe_allow_html=True)
    paths = _default_paths()
    if "iw_page" not in st.session_state:
        st.session_state["iw_page"] = "Overview"
    db_selection = st.session_state.get("iw_db_path", paths["db"])
    db_path = _project_path(db_selection)
    baseline_path = _project_path(st.session_state.get("iw_baseline_path", paths["baseline"]))
    key_path = _project_path(st.session_state.get("iw_key_path", paths["key"]))
    signature_path = _project_path(st.session_state.get("iw_signature_path", paths["signature"]))
    monitor_path = _project_path(st.session_state.get("iw_monitor_path", paths["monitor"]))
    evaluation_path = _project_path(st.session_state.get("iw_evaluation_path", paths["evaluation"]))
    root_path = paths["root"]
    paths = {"db": db_path, "baseline": baseline_path, "key": key_path, "signature": signature_path,
             "monitor": monitor_path, "evaluation": evaluation_path, "root": root_path}
    bundle = _status_bundle(db_path, baseline_path, key_path, signature_path, monitor_path)
    _sidebar(paths, bundle)
    # Sidebar widgets are rendered after this run's reads; values take effect on the next rerun.
    page = st.session_state.get("iw_page", "Overview")
    loaded = load_findings(db_path)
    findings = loaded["findings"]
    if page == "Overview":
        render_overview(bundle, findings, load_audit_events(db_path), loaded, paths)
    elif page == "Security Findings":
        render_findings(loaded)
    elif page == "File Integrity":
        render_file_integrity(root_path, baseline_path, key_path, signature_path)
    elif page == "Audit & Verification":
        render_audit(paths, bundle)
    elif page == "Evaluation":
        render_evaluation(load_evaluation_results(evaluation_path))
    else:
        render_demo()