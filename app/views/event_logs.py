"""Event Logs and Audit Trail view for Agent Firewall."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import pandas as pd
import streamlit as st

from app.components import badge_label, render_metric_card, verdict_badge


def get_all_benchmark_events(repo_root: Path) -> list[dict[str, Any]]:
    """Extract flattened event logs from the benchmark results."""
    results_dir = repo_root / "benchmarks" / "results"
    all_events = []

    # Try latest stage1 run
    p = results_dir / "latest_scripted_stage1.json"
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
                trials = d.get("attack_trials", []) + d.get("benign_trials", [])
                for t in trials:
                    scen_id = t.get("scenario_id", "Unknown")
                    for ev in t.get("trace", []):
                        ev_copy = dict(ev)
                        ev_copy["scenario_id"] = scen_id
                        all_events.append(ev_copy)
        except Exception:
            pass

    return all_events


def render_event_logs() -> None:
    """Render the searchable audit event log viewer."""
    st.markdown("### 📜 Real-Time Security Event & Audit Trail")
    st.caption("Search, filter, and inspect granular firewall interception events, decisions, and argument provenance records.")

    repo_root = Path(__file__).resolve().parents[2]

    # Check if there is an active session run
    session_events: list[dict[str, Any]] = []
    if "single_run" in st.session_state:
        scen, res, _ = st.session_state["single_run"]
        for ev in res.trace.events:
            ev_copy = dict(ev)
            ev_copy["scenario_id"] = scen.id
            session_events.append(ev_copy)

    # Use session events if available, or fall back to benchmark events
    source_label = "Active Interactive Session Run" if session_events else "Historical Benchmark Run (latest_scripted_stage1)"
    events_pool = session_events if session_events else get_all_benchmark_events(repo_root)

    c1, c2, c3, c4 = st.columns(4)
    total_ev = len(events_pool)
    tool_calls_cnt = sum(1 for e in events_pool if e.get("type") == "tool_call")
    decisions_cnt = sum(1 for e in events_pool if e.get("type") == "decision")
    blocks_cnt = sum(1 for e in events_pool if e.get("verdict") == "BLOCK")

    with c1:
        render_metric_card("Total Events", total_ev, f"Source: {source_label}", "#0297DE")
    with c2:
        render_metric_card("Tool Invocations", tool_calls_cnt, "Intercepted Calls", "#00D2FF")
    with c3:
        render_metric_card("Firewall Decisions", decisions_cnt, "Evaluated by Policy", "#38BDF8")
    with c4:
        render_metric_card("Blocked Threats", blocks_cnt, "Interceptions", "#EF4444")

    st.markdown("---")

    # Filter Controls
    col_f1, col_f2, col_f3 = st.columns([1.5, 1.5, 3])
    with col_f1:
        event_types = ["ALL", "tool_call", "decision", "segment", "tool_result", "approval", "final"]
        selected_type = st.selectbox("Filter by Event Type", event_types)
    with col_f2:
        verdict_filter = st.selectbox("Filter by Verdict", ["ALL", "ALLOW", "BLOCK", "ASK"])
    with col_f3:
        search_query = st.text_input("Search Logs", placeholder="e.g. read_webpage, send_email, recipe, evil.example...")

    # Apply filters
    filtered = events_pool
    if selected_type != "ALL":
        filtered = [e for e in filtered if e.get("type") == selected_type]
    if verdict_filter != "ALL":
        filtered = [e for e in filtered if e.get("verdict") == verdict_filter]
    if search_query:
        q = search_query.lower()
        filtered = [e for e in filtered if q in json.dumps(e).lower()]

    st.markdown(f"**Showing {len(filtered)} matching events**")

    # Tabular preview
    if filtered:
        rows = []
        for e in filtered[:100]:  # Limit preview to 100 rows for performance
            rows.append({
                "Scenario": e.get("scenario_id", "-"),
                "Type": e.get("type", "-"),
                "Name / Tool": e.get("name", e.get("rule_id", "-")),
                "Verdict / Label": e.get("verdict", e.get("label", "-")),
                "Details": e.get("reason", e.get("text", str(e.get("args", "-"))))[:60] + "...",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # Granular event expander
        st.markdown("#### 🔬 Detailed Event Records")
        for i, ev in enumerate(filtered[:20]):
            etype = ev.get("type", "unknown")
            header_str = f"[{ev.get('scenario_id', 'Session')}] {etype.upper()}"
            if "name" in ev:
                header_str += f" - {ev['name']}"
            if "verdict" in ev:
                header_str += f" -> {ev['verdict']}"

            with st.expander(header_str):
                st.json(ev)
    else:
        st.info("No logs match the current filter criteria.")
