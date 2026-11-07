"""Agent Monitoring view for Agent Firewall."""
from __future__ import annotations

import os
from pathlib import Path
import pandas as pd
import streamlit as st
import yaml

from app.components import render_metric_card


def render_agent_monitoring(selected_agent: str, firewall_mode: str) -> None:
    """Render agent runtime monitoring, health status, and tool telemetry."""
    st.markdown("### 🤖 Agent System & Tool Architecture Monitoring")
    st.caption("Inspect running AI agent instances, active tool registries, permission tiers, and live execution telemetry.")

    repo_root = Path(__file__).resolve().parents[2]
    policy_path = repo_root / "policies" / "default.yaml"
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_data = yaml.safe_load(f)

    # 1. Agent Architecture & Identifiers
    c1, c2, c3 = st.columns(3)

    llm_configured = bool(os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY") and os.getenv("LLM_MODEL"))
    with c1:
        render_metric_card(
            title="Active Agent Harness",
            value=selected_agent.upper(),
            caption="Deterministic Scripted vs LLM",
            accent_color="#0297DE",
        )
    with c2:
        render_metric_card(
            title="LLM API Status",
            value="CONNECTED" if llm_configured else "LOCAL HARNESS",
            caption=os.getenv("LLM_MODEL", "Regex Test Harness") if llm_configured else "Scripted Agent Active",
            accent_color="#10B981" if llm_configured else "#38BDF8",
        )
    with c3:
        total_tools = len(policy_data.get("tools", {}))
        render_metric_card(
            title="Monitored Tools",
            value=f"{total_tools} Tools",
            caption="Sandboxed & Guard-Checked",
            accent_color="#00D2FF",
        )

    st.markdown("---")

    # 2. Agent Runtime Profiles
    st.markdown("#### 🔍 Registered Agent Implementations")
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown(
            """
            <div class="cyber-card" style="border-top: 3px solid #0297DE;">
                <div style="font-weight: 600; color: #0297DE; font-size: 1.1rem; margin-bottom: 0.4rem;">
                    1. Deterministic Scripted Agent (<code>scripted</code>)
                </div>
                <p style="font-size: 0.88rem; color: #94A3B8;">
                    Uses deterministic pattern matching and regular expressions to simulate prompt injection vulnerabilities and legitimate multi-step workflows.
                </p>
                <ul style="font-size: 0.85rem; color: #CBD5E1;">
                    <li><strong>Reproducibility:</strong> 100% deterministic evaluation across benchmarks</li>
                    <li><strong>Safety:</strong> Zero third-party API exposure or external network leaks</li>
                    <li><strong>Execution speed:</strong> Instantaneous (< 5ms per run)</li>
                    <li><strong>Attack coverage:</strong> Exercises all 24 prompt-injection attack vectors</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_b:
        st.markdown(
            f"""
            <div class="cyber-card" style="border-top: 3px solid {'#10B981' if llm_configured else '#64748B'};">
                <div style="font-weight: 600; color: {'#10B981' if llm_configured else '#94A3B8'}; font-size: 1.1rem; margin-bottom: 0.4rem;">
                    2. Real OpenAI-Compatible Agent (<code>llm</code>)
                </div>
                <p style="font-size: 0.88rem; color: #94A3B8;">
                    Connects directly to OpenAI, OpenRouter, or NVIDIA NIM endpoints using function calling schemas.
                </p>
                <ul style="font-size: 0.85rem; color: #CBD5E1;">
                    <li><strong>Provider:</strong> <code>{os.getenv('LLM_BASE_URL', 'Not configured')}</code></li>
                    <li><strong>Model:</strong> <code>{os.getenv('LLM_MODEL', 'None')}</code></li>
                    <li><strong>Request Budget:</strong> {os.getenv('LLM_MAX_REQUESTS', '40')} maximum calls</li>
                    <li><strong>Caching:</strong> SHA256 hashed disk caching in <code>benchmarks/cache/</code></li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # 3. Tool Ecosystem & Permission Tiers
    st.markdown("#### 🛠️ Tool Ecosystem & Protection Tiers")
    st.caption("Every tool invocation is intercepted by the Guard before reaching the sandbox.")

    tools = policy_data.get("tools", {})
    tool_rows = []
    for name, rule in tools.items():
        tier = rule.get("tier", "unknown")
        tainted_action = rule.get("tainted", "ask")
        out_lbl = rule.get("output_label", "trusted")
        sens_args = ", ".join(rule.get("sensitive_args", [])) or "None"
        prov_override = rule.get("provenance_override", True)

        tool_rows.append({
            "Tool Name": name,
            "Security Tier": tier.upper(),
            "When Tainted": tainted_action.upper(),
            "Output Trust Label": out_lbl.upper(),
            "Sensitive Args": sens_args,
            "Stage 2 Override": "Allowed" if prov_override else "Forbidden",
        })

    st.dataframe(pd.DataFrame(tool_rows), use_container_width=True, hide_index=True)

    # 4. Agent Step Loop Visualization
    st.markdown("#### 🔄 Agent-Firewall-Sandbox Data Flow")
    st.markdown(
        """
        ```
        [User Prompt] (TRUSTED)
              │
              ▼
        ┌──────────────┐      Tool Call      ┌──────────────┐     Policy     ┌──────────────┐
        │   AI Agent   │ ──────────────────> │    Guard     │ ─────────────> │ Policy Rules │
        │ (LLM/Script) │                     │ (Intercept)  │                │ default.yaml │
        └──────────────┘                     └──────────────┘                └──────────────┘
              ▲                                     │
              │                               ALLOW │ BLOCK / ASK
              │                                     ▼
        ┌──────────────┐      Labeled Output ┌──────────────┐
        │ Tainted      │ <────────────────── │ Safe Sandbox │
        │ Context      │                     │ (Fake Tools) │
        └──────────────┘                     └──────────────┘
        ```
        """
    )
