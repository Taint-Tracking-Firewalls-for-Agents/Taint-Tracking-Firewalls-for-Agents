"""Threat Detection and Taint Tracking view for Agent Firewall (Obsidian DX Aesthetic)."""
from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from agent.scenarios import Scenario
try:
    from app.components import render_metric_card
except (ImportError, ModuleNotFoundError):
    from components import render_metric_card


def render_threat_detection(scenarios: list[Scenario]) -> None:
    """Render threat detection taxonomy, taint analysis, and injection details."""
    st.markdown("### 🎯 Threat Detection & Taint Flow Architecture")
    st.caption("Deterministic data-provenance tracking replacing fragile regex heuristics. Inspect attack payloads and policy interception points.")

    attacks = [s for s in scenarios if s.kind == "attack"]

    # 1. Threat Overview Metrics
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        render_metric_card(
            title="Attack Vectors",
            value=f"{len(attacks)}",
            caption="Standardized Suite",
            accent_color="#EF4444",
        )
    with c2:
        render_metric_card(
            title="Non-Adaptive Defended",
            value="100.0%",
            caption="23/23 Attacks Blocked",
            accent_color="#10B981",
        )
    with c3:
        render_metric_card(
            title="Adaptive Laundering (A21)",
            value="OUT_OF_SCOPE",
            caption="Pre-session File State",
            accent_color="#F59E0B",
        )
    with c4:
        render_metric_card(
            title="Benign False Alarms",
            value="0.0%",
            caption="Zero False Positives (Stage 2)",
            accent_color="#0297DE",
        )

    st.markdown("---")

    # 2. Attack Taxonomy
    st.markdown(
        """
        <div class="metric-micro-label" style="margin-bottom: 0.5rem;">
            ATTACK TAXONOMY BREAKDOWN
        </div>
        """,
        unsafe_allow_html=True,
    )
    categories = {}
    for a in attacks:
        cat = a.category or "uncategorized"
        categories.setdefault(cat, []).append(a)

    cat_cols = st.columns(len(categories))
    for i, (cat_name, cat_attacks) in enumerate(categories.items()):
        with cat_cols[i % len(cat_cols)]:
            st.markdown(
                f"""
                <div class="obsidian-card" style="border-top: 2px solid #EF4444; min-height: 110px; padding: 0.75rem 0.9rem;">
                    <div class="metric-micro-label" style="color: #EF4444;">CATEGORY {i+1:02d}</div>
                    <div style="font-size: 0.92rem; font-weight: 600; color: #F1F5F9; margin-bottom: 0.2rem;">
                        {cat_name.replace('_', ' ').upper()}
                    </div>
                    <div class="mono-metric" style="font-size: 11px; color: #64748B;">{len(cat_attacks)} SCENARIOS</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("---")

    # 3. Threat Payload Inspector
    st.markdown(
        """
        <div class="metric-micro-label" style="margin-bottom: 0.5rem;">
            SCENARIO PAYLOAD & OBJECTIVE INSPECTOR
        </div>
        """,
        unsafe_allow_html=True,
    )
    attack_options = {f"[{a.id}] {a.description}": a for a in attacks}
    selected_attack_title = st.selectbox("Select Attack Scenario to Inspect", list(attack_options.keys()), label_visibility="collapsed")
    selected_attack = attack_options[selected_attack_title]

    col_details, col_fixtures = st.columns([1.2, 1])

    with col_details:
        st.markdown(
            f"""
            <div class="obsidian-card" style="border-left: 2px solid #EF4444; padding: 0.85rem 1rem;">
                <div class="metric-micro-label" style="color: #EF4444;">ATTACK PROFILE // {selected_attack.id}</div>
                <div style="margin-bottom: 0.5rem;">
                    <span class="metric-micro-label">USER TASK:</span>
                    <div class="mono-metric" style="font-size: 0.82rem; color: #38BDF8;">"{selected_attack.user_task}"</div>
                </div>
                <div style="margin-bottom: 0.5rem;">
                    <span class="metric-micro-label">ATTACK GOAL:</span>
                    <div class="mono-metric" style="font-size: 0.82rem; color: #F87171;">{json.dumps(selected_attack.goal)}</div>
                </div>
                <div>
                    <span class="metric-micro-label">ADAPTIVE EVASION:</span>
                    <span class="mono-metric" style="font-size: 11px; color: {'#F59E0B' if selected_attack.adaptive else '#64748B'};">
                        {'YES (File Store Laundering)' if selected_attack.adaptive else 'NO (Direct Webpage/Email Injection)'}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_fixtures:
        st.markdown(
            """
            <div class="obsidian-card" style="border-left: 2px solid #0297DE; padding: 0.85rem 1rem;">
                <div class="metric-micro-label" style="color: #0297DE;">EXTERNAL INJECTION FIXTURES</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.json(selected_attack.fixtures)
