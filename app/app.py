"""Agent Firewall interactive Streamlit cybersecurity platform."""
from __future__ import annotations

import os
from pathlib import Path
import sys

# Ensure src/ is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import streamlit as st

from agent.scenarios import Scenario, load_scenarios
from app.styles import apply_theme
from app.views.agent_monitoring import render_agent_monitoring
from app.views.dashboard import render_dashboard
from app.views.event_logs import render_event_logs
from app.views.settings import render_settings
from app.views.threat_detection import render_threat_detection


@st.cache_data
def get_all_scenarios() -> tuple[list[Scenario], list[Scenario]]:
    """Load and cache benchmark attack and benign scenario definitions."""
    repo_root = Path(__file__).resolve().parents[1]
    attacks = load_scenarios(repo_root / "benchmarks" / "attacks")
    benign = load_scenarios(repo_root / "benchmarks" / "benign")
    return attacks, benign


def main() -> None:
    """Streamlit application main entrypoint."""
    st.set_page_config(
        page_title="Agent Firewall | AI Data Provenance Defense",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply Midnight Black (#02070A) and Electric Blue (#0297DE) theme
    apply_theme()

    # Top Brand Bar
    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #142E42; padding-bottom: 0.8rem; margin-bottom: 1.2rem;">
            <div>
                <span style="font-size: 1.6rem; font-weight: 800; color: #F1F5F9; letter-spacing: -0.02em;">
                    🛡️ AGENT<span style="color: #0297DE;">FIREWALL</span>
                </span>
                <span style="margin-left: 12px; font-size: 0.8rem; color: #00D2FF; background: rgba(2, 151, 222, 0.15); border: 1px solid #0297DE; padding: 2px 8px; border-radius: 4px; font-weight: 600;">
                    AI RUNTIME TAINT TRACKING
                </span>
            </div>
            <div style="font-size: 0.82rem; color: #94A3B8;">
                Evaluation Track: <strong style="color: #F1F5F9;">Guardian Tools & Usable Security</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar Navigation & Controls
    st.sidebar.markdown(
        """
        <div style="margin-bottom: 1rem;">
            <div style="font-size: 0.75rem; text-transform: uppercase; color: #0297DE; font-weight: 700; letter-spacing: 0.08em;">
                Navigation
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    nav_pages = [
        "📊 Executive Dashboard",
        "🤖 Agent Monitoring",
        "🎯 Threat Detection",
        "📜 Event Logs",
        "⚙️ Settings & Policy",
    ]
    selected_page = st.sidebar.radio("View", nav_pages, index=0, label_visibility="collapsed")

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        """
        <div style="font-size: 0.75rem; text-transform: uppercase; color: #0297DE; font-weight: 700; letter-spacing: 0.08em; margin-bottom: 0.5rem;">
            Firewall Configuration
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Firewall Mode Selection
    firewall_mode = st.sidebar.selectbox(
        "Firewall Mode",
        ["stage2", "stage1", "off"],
        index=0,
        help=(
            "stage2: Taint tracking + Argument Provenance Override (Recommended, 0% ASR, 100% Utility)\n"
            "stage1: Conservative Taint Blocking (0% ASR, 66.7% Utility due to false positives)\n"
            "off: Firewall Disabled (100% Attack Success Rate)"
        ),
    )

    # Agent Engine Selection
    llm_enabled = bool(
        os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY") and os.getenv("LLM_MODEL")
    )
    agent_options = ["scripted"]
    if llm_enabled:
        agent_options.append("llm")

    selected_agent = st.sidebar.selectbox(
        "Agent Engine",
        agent_options,
        index=0,
        help="Deterministic regex harness or live LLM chat completions API",
    )

    if llm_enabled:
        st.sidebar.caption(f"Model: `{os.getenv('LLM_MODEL')}`")
    else:
        st.sidebar.caption("LLM disabled (configure `.env` to enable live LLM)")

    # Sidebar Status Card
    st.sidebar.markdown("---")
    mode_desc = {
        "stage2": "ACTIVE (Stage 2: Provenance Override)",
        "stage1": "ACTIVE (Stage 1: Strict Taint)",
        "off": "DISABLED (Passthrough)",
    }
    mode_color = "#10B981" if firewall_mode == "stage2" else ("#F59E0B" if firewall_mode == "stage1" else "#EF4444")

    st.sidebar.markdown(
        f"""
        <div style="background: #0A1B27; border: 1px solid #142E42; border-left: 3px solid {mode_color}; padding: 0.8rem; border-radius: 6px;">
            <div style="font-size: 0.72rem; text-transform: uppercase; color: #94A3B8; font-weight: bold;">Defense Status</div>
            <div style="font-size: 0.88rem; font-weight: 700; color: {mode_color}; margin-top: 2px;">{mode_desc[firewall_mode]}</div>
            <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 4px;">Engine: <code>{selected_agent}</code></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Scenarios loading
    attacks, benign = get_all_scenarios()
    all_scenarios = attacks + benign

    # View Routing
    if selected_page == "📊 Executive Dashboard":
        render_dashboard(all_scenarios, selected_agent, firewall_mode)
    elif selected_page == "🤖 Agent Monitoring":
        render_agent_monitoring(selected_agent, firewall_mode)
    elif selected_page == "🎯 Threat Detection":
        render_threat_detection(all_scenarios)
    elif selected_page == "📜 Event Logs":
        render_event_logs()
    elif selected_page == "⚙️ Settings & Policy":
        render_settings(firewall_mode)


if __name__ == "__main__":
    main()
