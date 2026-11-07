"""Agent Monitoring view for Agent Firewall (Obsidian DX Aesthetic)."""
from __future__ import annotations

import os
from pathlib import Path
import pandas as pd
import streamlit as st
import yaml

from app.components import render_metric_card


def render_agent_monitoring(selected_agent: str, firewall_mode: str) -> None:
    """Render agent runtime monitoring, health status, and tool telemetry."""
    st.markdown("### 🤖 Agent Runtime & Tool Telemetry")
    st.caption("Inspect active execution harness instances, tool permission tiers, and sandbox interception boundaries.")

    repo_root = Path(__file__).resolve().parents[2]
    policy_path = repo_root / "policies" / "default.yaml"
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_data = yaml.safe_load(f)

    # 1. Architecture Indicators
    c1, c2, c3 = st.columns(3)
    llm_configured = bool(os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY") and os.getenv("LLM_MODEL"))

    with c1:
        render_metric_card(
            title="Active Engine",
            value=selected_agent.upper(),
            caption="Deterministic Scripted Harness",
            accent_color="#0297DE",
        )
    with c2:
        render_metric_card(
            title="External LLM Link",
            value="ACTIVE" if llm_configured else "LOCAL_MOCK",
            caption=os.getenv("LLM_MODEL", "Regex Harness") if llm_configured else "Zero API Leaks",
            accent_color="#10B981" if llm_configured else "#64748B",
        )
    with c3:
        total_tools = len(policy_data.get("tools", {}))
        render_metric_card(
            title="Protected Tools",
            value=f"{total_tools} Tools",
            caption="Sandboxed Intercepts",
            accent_color="#00D2FF",
        )

    st.markdown("---")

    # 2. Registered Agent Implementations
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(
            """
            <div class="obsidian-card" style="border-top: 2px solid #0297DE;">
                <div class="metric-micro-label" style="color: #0297DE;">HARNESS 01</div>
                <div style="font-weight: 600; color: #F8FAFC; font-size: 1rem; margin-bottom: 0.35rem;">
                    Deterministic Scripted Agent (<code>scripted</code>)
                </div>
                <p style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 0.5rem;">
                    Pattern-matching harness simulating both benign multi-step workflows and untrusted prompt injection hijacks.
                </p>
                <div class="mono-metric" style="font-size: 11px; color: #CBD5E1; line-height: 1.6;">
                    • REPRODUCIBILITY: 100% deterministic<br>
                    • LATENCY: &lt; 5ms per run<br>
                    • NETWORK EXPOSURE: Strictly offline / local sandbox
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_b:
        st.markdown(
            f"""
            <div class="obsidian-card" style="border-top: 2px solid {'#10B981' if llm_configured else '#475569'};">
                <div class="metric-micro-label" style="color: {'#10B981' if llm_configured else '#64748B'};">HARNESS 02</div>
                <div style="font-weight: 600; color: #F8FAFC; font-size: 1rem; margin-bottom: 0.35rem;">
                    OpenAI-Compatible Model Agent (<code>llm</code>)
                </div>
                <p style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 0.5rem;">
                    Live LLM agent with structured function calling schema support (OpenRouter / NVIDIA NIM / OpenAI).
                </p>
                <div class="mono-metric" style="font-size: 11px; color: #CBD5E1; line-height: 1.6;">
                    • ENDPOINT: <code>{os.getenv('LLM_BASE_URL', 'Not configured')}</code><br>
                    • MODEL: <code>{os.getenv('LLM_MODEL', 'None')}</code><br>
                    • DISK CACHING: SHA-256 hashed in <code>benchmarks/cache/</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # 3. Tool Ecosystem & Permission Tiers
    st.markdown(
        """
        <div class="metric-micro-label" style="margin-bottom: 0.5rem;">
            TOOL ECOSYSTEM & SECURITY TIERS
        </div>
        """,
        unsafe_allow_html=True,
    )

    tools = policy_data.get("tools", {})
    tool_rows = []
    for name, rule in tools.items():
        tier = rule.get("tier", "unknown")
        tainted_action = rule.get("tainted", "ask")
        out_lbl = rule.get("output_label", "trusted")
        sens_args = ", ".join(rule.get("sensitive_args", [])) or "None"
        prov_override = rule.get("provenance_override", True)

        tool_rows.append({
            "TOOL": name,
            "TIER": tier.upper(),
            "WHEN TAINTED": tainted_action.upper(),
            "OUTPUT LABEL": out_lbl.upper(),
            "SENSITIVE ARGS": sens_args,
            "OVERRIDE": "ALLOWED" if prov_override else "DISABLED",
        })

    st.dataframe(pd.DataFrame(tool_rows), use_container_width=True, hide_index=True)
