"""Reusable cybersecurity UI components for Agent Firewall."""
from __future__ import annotations

import json
from typing import Any
import streamlit as st


def render_metric_card(
    title: str,
    value: str | int | float,
    caption: str = "",
    accent_color: str = "#0297DE",
) -> None:
    """Render a styled metric card."""
    st.markdown(
        f"""
        <div class="metric-box" style="border-top-color: {accent_color};">
            <div class="metric-title">{title}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-caption" style="color: {accent_color};">{caption}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def badge_label(label: str) -> str:
    """Format label badge (trusted vs untrusted)."""
    lbl = str(label).lower()
    if lbl == "trusted":
        return '<span class="badge-trusted">🟢 TRUSTED</span>'
    elif lbl == "untrusted":
        return '<span class="badge-untrusted">🔴 UNTRUSTED</span>'
    return f'<span class="badge-trusted">{lbl.upper()}</span>'


def verdict_badge(verdict: str) -> str:
    """Format verdict badge (ALLOW, ASK, BLOCK)."""
    v = str(verdict).upper()
    if v == "ALLOW":
        return '<span class="badge-allow">✓ ALLOW</span>'
    elif v == "BLOCK":
        return '<span class="badge-block">✕ BLOCK</span>'
    elif v == "ASK":
        return '<span class="badge-ask">⚠ ASK</span>'
    return f'<span class="badge-allow">{v}</span>'


def render_trace_timeline(events: list[dict[str, Any]]) -> None:
    """Render execution timeline with provenance and decisions."""
    if not events:
        st.info("No events in execution trace.")
        return

    st.markdown("### 🔍 Execution & Taint Timeline")

    for i, ev in enumerate(events):
        etype = ev.get("type", "unknown")

        if etype == "segment":
            lbl = ev.get("label", "trusted")
            src = ev.get("source", "unknown")
            text = ev.get("text", "")
            seg_id = ev.get("id", f"s{i+1}")
            badge = badge_label(lbl)
            
            with st.container():
                st.markdown(
                    f"""
                    <div class="cyber-card" style="padding: 0.8rem 1rem; border-left: 3px solid {'#10B981' if lbl == 'trusted' else '#EF4444'};">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                            <div>{badge} <strong style="color: #94A3B8; font-size: 0.82rem; margin-left: 8px;">Source: <code>{src}</code> ({seg_id})</strong></div>
                        </div>
                        <div style="font-family: monospace; font-size: 0.88rem; color: #E2E8F0; white-space: pre-wrap; word-break: break-word;">{text}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        elif etype == "tool_call":
            name = ev.get("name", "")
            call_id = ev.get("call_id", f"call_{i}")
            args = ev.get("args", {})
            args_pretty = json.dumps(args, indent=2)

            with st.container():
                st.markdown(
                    f"""
                    <div class="cyber-card" style="padding: 0.8rem 1rem; border-left: 3px solid #0297DE;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                            <div><strong style="color: #0297DE;">🛠️ TOOL CALL:</strong> <code style="font-size: 0.95rem; font-weight: bold;">{name}</code></div>
                            <span style="font-size: 0.75rem; color: #64748B;">ID: {call_id}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                with st.expander(f"View Arguments for {name}"):
                    st.code(args_pretty, language="json")

        elif etype == "decision":
            verdict = ev.get("verdict", "")
            rule_id = ev.get("rule_id", "")
            reason = ev.get("reason", "")
            tainted_by = ev.get("tainted_by", [])
            v_badge = verdict_badge(verdict)

            color = "#0297DE" if verdict == "ALLOW" else ("#EF4444" if verdict == "BLOCK" else "#F59E0B")
            
            with st.container():
                st.markdown(
                    f"""
                    <div class="cyber-card" style="padding: 0.8rem 1rem; border-left: 3px solid {color}; background: #0A1B27;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                            <div><strong>FIREWALL DECISION:</strong> {v_badge}</div>
                            <span style="font-size: 0.75rem; color: #94A3B8;">Rule: <code>{rule_id}</code></span>
                        </div>
                        <div style="font-size: 0.9rem; color: #F1F5F9; margin-top: 4px;"><strong>Reason:</strong> {reason}</div>
                        {'<div style="font-size: 0.8rem; color: #F87171; margin-top: 4px;"><strong>Tainted by:</strong> ' + ", ".join(tainted_by) + '</div>' if tainted_by else ''}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        elif etype == "approval":
            approved = ev.get("approved")
            status = "APPROVED BY USER" if approved else "DENIED BY USER"
            color = "#10B981" if approved else "#EF4444"
            st.markdown(
                f"""
                <div style="margin: 0.4rem 0 0.8rem 1.5rem; font-size: 0.85rem; color: {color};">
                    👤 <strong>Human-in-the-Loop Approval:</strong> {status}
                </div>
                """,
                unsafe_allow_html=True,
            )

        elif etype == "tool_result":
            ok = ev.get("ok", True)
            src = ev.get("source", "tool")
            res_lbl = ev.get("label", "trusted")
            text = ev.get("text", "")
            status_text = "SUCCESS" if ok else "ERROR/INTERCEPTED"
            color = "#10B981" if ok else "#EF4444"

            with st.expander(f"Tool Output [{status_text}] from {src} ({res_lbl})", expanded=not ok):
                st.markdown(f"**Output Label Assigned:** {badge_label(res_lbl)}", unsafe_allow_html=True)
                st.code(text if text else "(empty)", language="text")

        elif etype == "final":
            final_text = ev.get("text", "")
            st.markdown(
                f"""
                <div class="cyber-card" style="border-left: 3px solid #38BDF8; background: #07131B;">
                    <div style="color: #38BDF8; font-weight: 600; margin-bottom: 0.4rem;">🏁 FINAL AGENT RESPONSE</div>
                    <div style="font-size: 0.95rem; color: #F1F5F9;">{final_text}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_sandbox_state_panels(state: dict[str, Any]) -> None:
    """Render state cards for outbox, filesystem, shell, and network."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div class="cyber-card">
                <div style="font-weight: 600; color: #0297DE; margin-bottom: 0.5rem;">📧 Outbox (Exfiltration Check)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        outbox = state.get("outbox", [])
        if outbox:
            st.warning(f"🚨 {len(outbox)} outgoing emails intercepted / logged")
            st.json(outbox)
        else:
            st.success("✓ Outbox clean: No unauthorized emails sent")

        st.markdown(
            """
            <div class="cyber-card" style="margin-top: 1rem;">
                <div style="font-weight: 600; color: #0297DE; margin-bottom: 0.5rem;">💻 Shell Command Execution</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        shell = state.get("shell_log", [])
        if shell:
            st.error(f"🚨 {len(shell)} shell command(s) executed!")
            st.code("\n".join(shell), language="bash")
        else:
            st.success("✓ Zero shell executions permitted")

    with col2:
        st.markdown(
            """
            <div class="cyber-card">
                <div style="font-weight: 600; color: #0297DE; margin-bottom: 0.5rem;">📁 File System Modifications</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        written = state.get("written", [])
        deleted = state.get("deleted", [])

        if written:
            st.info(f"Files written: {len(written)}")
            for w in written:
                st.caption(f"Written: `{w.get('path')}`")
        else:
            st.caption("No files written.")

        if deleted:
            st.error(f"Files deleted: {deleted}")
        else:
            st.caption("No files deleted.")

        st.markdown(
            """
            <div class="cyber-card" style="margin-top: 1rem;">
                <div style="font-weight: 600; color: #0297DE; margin-bottom: 0.5rem;">🌐 Outbound HTTP Requests</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        http_log = state.get("http_log", [])
        if http_log:
            st.warning(f"{len(http_log)} HTTP requests logged")
            st.json(http_log)
        else:
            st.success("✓ No outbound HTTP POST exfiltrations")
