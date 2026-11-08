"""Settings and Firewall Policy Configuration view for Agent Firewall (Obsidian DX Aesthetic)."""
from __future__ import annotations

import os
from pathlib import Path
import streamlit as st
import yaml

from app.components import render_metric_card


def render_settings(current_mode: str) -> None:
    """Render firewall settings, policy rules, and configuration controls."""
    st.markdown("### ⚙️ Firewall Policy Engine & Defense Configuration")
    st.caption("Active enforcement policies, two-stage evaluation mechanics, and false-positive recovery controls.")

    repo_root = Path(__file__).resolve().parents[2]
    policy_path = repo_root / "policies" / "default.yaml"
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_raw = f.read()
        policy_data = yaml.safe_load(policy_raw)

    # 1. Enforcement Overview
    c1, c2, c3 = st.columns(3)
    with c1:
        render_metric_card(
            title="Active Mode",
            value=current_mode.upper(),
            caption="Sidebar Switcher",
            accent_color="#0297DE",
        )
    with c2:
        render_metric_card(
            title="Default Action",
            value=policy_data.get("default", "ask").upper(),
            caption="Unlisted Tool Fallback",
            accent_color="#F59E0B",
        )
    with c3:
        render_metric_card(
            title="Policy File",
            value="default.yaml",
            caption="policies/default.yaml",
            accent_color="#00D2FF",
        )

    st.markdown("---")

    # 2. Two-Stage Policy Evaluation Engine
    st.markdown(
        """
        <div class="metric-micro-label" style="margin-bottom: 0.5rem;">
            TWO-STAGE EVALUATION ENGINE
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown(
            """
            <div class="obsidian-card" style="border-top: 2px solid #F59E0B; height: 100%;">
                <div class="metric-micro-label" style="color: #F59E0B;">STAGE 01 // CONSERVATIVE</div>
                <div style="font-weight: 600; color: #F8FAFC; font-size: 1rem; margin-bottom: 0.35rem;">
                    Strict Taint Blocking
                </div>
                <p style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 0.5rem;">
                    If the context is tainted by <em>any</em> untrusted segment, sensitive actions with <code>tainted: block</code> or <code>tainted: ask</code> are immediately halted.
                </p>
                <div class="mono-metric" style="font-size: 11px; color: #CBD5E1; line-height: 1.6; background: #030609; padding: 0.5rem; border-radius: 4px;">
                    • ATTACKS STOPPED: 23/23 (0.0% ASR)<br>
                    • BENIGN UTILITY: 8/12 (66.7%)<br>
                    • FALSE BLOCKS: 4 (Tasks reading web before sending email)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_s2:
        st.markdown(
            """
            <div class="obsidian-card" style="border-top: 2px solid #10B981; height: 100%;">
                <div class="metric-micro-label" style="color: #10B981;">STAGE 02 // RECOMMENDED</div>
                <div style="font-weight: 600; color: #F8FAFC; font-size: 1rem; margin-bottom: 0.35rem;">
                    Argument Provenance Override
                </div>
                <p style="font-size: 0.82rem; color: #94A3B8; margin-bottom: 0.5rem;">
                    Same attack defense, but checks if every <code>sensitive_arg</code> (recipient, URL, filepath) originated directly from trusted user input.
                </p>
                <div class="mono-metric" style="font-size: 11px; color: #34D399; line-height: 1.6; background: #030609; padding: 0.5rem; border-radius: 4px;">
                    • ATTACKS STOPPED: 23/23 (0.0% ASR)<br>
                    • BENIGN UTILITY: 12/12 (100.0%)<br>
                    • FALSE BLOCKS: 0 (Zero benign friction)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # 3. Critical Safety Overrides
    st.markdown(
        """
        <div class="obsidian-card" style="border-left: 2px solid #EF4444; padding: 0.85rem 1rem;">
            <div class="metric-micro-label" style="color: #EF4444;">HARDENED PRIVILEGED TOOLS // PROVENANCE_OVERRIDE: FALSE</div>
            <p style="font-size: 0.84rem; color: #E2E8F0; margin-bottom: 0.4rem;">
                Certain high-consequence system tools must <strong>never</strong> execute in tainted context under any circumstances, even if parameters appear in user text:
            </p>
            <div class="mono-metric" style="font-size: 11px; color: #F87171;">
                • <code>run_shell</code> (Arbitrary host shell command execution)<br>
                • <code>delete_file</code> (Destructive filesystem deletion)
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("📄 View Active YAML Ruleset (policies/default.yaml)"):
        st.code(policy_raw, language="yaml")
