"""High-density, DX-grade UI components for Agent Firewall."""
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
    """Render a compact, high-precision metric card with JetBrains Mono numbers."""
    st.markdown(
        f"""
        <div class="metric-card-dx" style="border-top-color: {accent_color};">
            <div class="metric-micro-label">
                <span>{title}</span>
                <span style="display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: {accent_color}; opacity: 0.8;"></span>
            </div>
            <div class="metric-value-large mono-metric">{value}</div>
            <div class="metric-delta-sub" style="color: {accent_color};">
                {caption}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def badge_label(label: str) -> str:
    """Format trust label with refined status pill."""
    lbl = str(label).lower()
    if lbl == "trusted":
        return '<span class="status-pill pill-trusted">● TRUSTED</span>'
    elif lbl == "untrusted":
        return '<span class="status-pill pill-untrusted">▲ UNTRUSTED</span>'
    return f'<span class="status-pill pill-trusted">{lbl.upper()}</span>'


def verdict_badge(verdict: str) -> str:
    """Format firewall verdict with high-precision pill."""
    v = str(verdict).upper()
    if v == "ALLOW":
        return '<span class="status-pill pill-allow">✓ ALLOW</span>'
    elif v == "BLOCK":
        return '<span class="status-pill pill-block">✕ BLOCK</span>'
    elif v == "ASK":
        return '<span class="status-pill pill-ask">⚠ ASK</span>'
    return f'<span class="status-pill pill-allow">{v}</span>'


def render_trace_timeline(events: list[dict[str, Any]]) -> None:
    """Render dense execution timeline with data provenance and decisions."""
    if not events:
        st.info("No events in execution trace.")
        return

    st.markdown("### 🔍 Execution & Taint Trace")

    for i, ev in enumerate(events):
        etype = ev.get("type", "unknown")

        if etype == "segment":
            lbl = ev.get("label", "trusted")
            src = ev.get("source", "unknown")
            text = ev.get("text", "")
            seg_id = ev.get("id", f"s{i+1}")
            badge = badge_label(lbl)
            accent_border = "#10B981" if lbl == "trusted" else "#EF4444"

            st.markdown(
                f"""
                <div class="obsidian-card" style="border-left: 2px solid {accent_border}; padding: 0.75rem 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                        <div>
                            {badge}
                            <span class="mono-metric" style="color: #64748B; font-size: 11px; margin-left: 8px;">
                                SOURCE: <code>{src}</code> ({seg_id})
                            </span>
                        </div>
                    </div>
                    <div class="mono-metric" style="font-size: 0.82rem; color: #E2E8F0; white-space: pre-wrap; word-break: break-word;">{text}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        elif etype == "tool_call":
            name = ev.get("name", "")
            call_id = ev.get("call_id", f"call_{i}")
            args = ev.get("args", {})
            args_pretty = json.dumps(args, indent=2)

            st.markdown(
                f"""
                <div class="obsidian-card" style="border-left: 2px solid #0297DE; padding: 0.75rem 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span class="mono-metric" style="color: #0297DE; font-size: 11px; font-weight: 700; text-transform: uppercase;">TOOL INVOCATION:</span>
                            <span class="mono-metric" style="font-size: 0.92rem; font-weight: 600; color: #F8FAFC; margin-left: 6px;">{name}</span>
                        </div>
                        <span class="mono-metric" style="font-size: 10px; color: #64748B;">{call_id}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            with st.expander(f"View Arguments: {name}"):
                st.code(args_pretty, language="json")

        elif etype == "decision":
            verdict = ev.get("verdict", "")
            rule_id = ev.get("rule_id", "")
            reason = ev.get("reason", "")
            tainted_by = ev.get("tainted_by", [])
            v_badge = verdict_badge(verdict)

            accent = "#0297DE" if verdict == "ALLOW" else ("#EF4444" if verdict == "BLOCK" else "#F59E0B")

            st.markdown(
                f"""
                <div class="obsidian-card" style="border-left: 2px solid {accent}; background: #060E15; padding: 0.75rem 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="metric-micro-label" style="margin-bottom: 0;">DECISION</span>
                            {v_badge}
                        </div>
                        <span class="mono-metric" style="font-size: 10px; color: #64748B;">RULE: <code>{rule_id}</code></span>
                    </div>
                    <div style="font-size: 0.85rem; color: #E2E8F0; margin-top: 4px;">{reason}</div>
                    {'<div class="mono-metric" style="font-size: 11px; color: #F87171; margin-top: 5px;">TAINT ROOTS: ' + ", ".join(tainted_by) + '</div>' if tainted_by else ''}
                </div>
                """,
                unsafe_allow_html=True,
            )

        elif etype == "approval":
            approved = ev.get("approved")
            status = "APPROVED" if approved else "DENIED"
            color = "#10B981" if approved else "#EF4444"
            st.markdown(
                f"""
                <div class="mono-metric" style="margin: 0.3rem 0 0.6rem 1.2rem; font-size: 11px; color: {color};">
                    ↳ USER APPROVAL INTERCEPT: <strong>{status}</strong>
                </div>
                """,
                unsafe_allow_html=True,
            )

        elif etype == "tool_result":
            ok = ev.get("ok", True)
            src = ev.get("source", "tool")
            res_lbl = ev.get("label", "trusted")
            text = ev.get("text", "")
            status_text = "EXIT_SUCCESS" if ok else "INTERCEPTED"

            with st.expander(f"Result [{status_text}] via {src} ({res_lbl})", expanded=not ok):
                st.markdown(f"**Output Label Assigned:** {badge_label(res_lbl)}", unsafe_allow_html=True)
                st.code(text if text else "(empty)", language="text")

        elif etype == "final":
            final_text = ev.get("text", "")
            st.markdown(
                f"""
                <div class="obsidian-card" style="border-left: 2px solid #00D2FF; background: #04090F; padding: 0.85rem 1rem;">
                    <div class="metric-micro-label" style="color: #00D2FF;">FINAL AGENT RESPONSE</div>
                    <div style="font-size: 0.9rem; color: #F1F5F9; line-height: 1.5;">{final_text}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_sandbox_state_panels(state: dict[str, Any]) -> None:
    """Render partitioned micro-border cards for outbox and sandbox logs."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div class="obsidian-card" style="padding: 0.75rem 1rem; margin-bottom: 0.5rem;">
                <div class="metric-micro-label">OUTBOX / EXFILTRATION CHANNEL</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        outbox = state.get("outbox", [])
        if outbox:
            st.error(f"🚨 {len(outbox)} outgoing emails logged")
            st.json(outbox)
        else:
            st.markdown(
                '<div class="mono-metric" style="font-size: 12px; color: #10B981; padding: 0.3rem 0.5rem;">✓ OUTBOX_CLEAN (Zero exfiltration)</div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            """
            <div class="obsidian-card" style="padding: 0.75rem 1rem; margin-top: 0.8rem; margin-bottom: 0.5rem;">
                <div class="metric-micro-label">SYSTEM SHELL LOG</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        shell = state.get("shell_log", [])
        if shell:
            st.error(f"🚨 {len(shell)} shell command(s) executed!")
            st.code("\n".join(shell), language="bash")
        else:
            st.markdown(
                '<div class="mono-metric" style="font-size: 12px; color: #10B981; padding: 0.3rem 0.5rem;">✓ ZERO_SHELL_EXECUTIONS</div>',
                unsafe_allow_html=True,
            )

    with col2:
        st.markdown(
            """
            <div class="obsidian-card" style="padding: 0.75rem 1rem; margin-bottom: 0.5rem;">
                <div class="metric-micro-label">SANDBOX FILE MUTATIONS</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        written = state.get("written", [])
        deleted = state.get("deleted", [])

        if written:
            for w in written:
                st.caption(f"Written: `{w.get('path')}`")
        else:
            st.markdown(
                '<div class="mono-metric" style="font-size: 12px; color: #64748B; padding: 0.3rem 0.5rem;">NO_FILES_MUTATED</div>',
                unsafe_allow_html=True,
            )

        if deleted:
            st.error(f"Files deleted: {deleted}")

        st.markdown(
            """
            <div class="obsidian-card" style="padding: 0.75rem 1rem; margin-top: 0.8rem; margin-bottom: 0.5rem;">
                <div class="metric-micro-label">HTTP OUTBOUND TELEMETRY</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        http_log = state.get("http_log", [])
        if http_log:
            st.warning(f"{len(http_log)} HTTP requests logged")
            st.json(http_log)
        else:
            st.markdown(
                '<div class="mono-metric" style="font-size: 12px; color: #10B981; padding: 0.3rem 0.5rem;">✓ ZERO_EXTERNAL_POSTS</div>',
                unsafe_allow_html=True,
            )
