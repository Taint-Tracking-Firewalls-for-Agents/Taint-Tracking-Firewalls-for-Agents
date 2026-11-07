"""Agent Firewall interactive Streamlit cybersecurity platform (Obsidian Dark Mode)."""
from __future__ import annotations

import os
from pathlib import Path
import sys

# Ensure repository root and src/ are on sys.path, and clean up conflicting script dir
_repo_root = Path(__file__).resolve().parents[1]
_app_dir = Path(__file__).resolve().parent

sys.path = [p for p in sys.path if Path(p).resolve() != _app_dir]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
if str(_repo_root / "src") not in sys.path:
    sys.path.insert(0, str(_repo_root / "src"))

if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
    del sys.modules["app"]

import streamlit as st

from agent.scenarios import Scenario, load_scenarios
from app.styles import apply_theme
from app.views.agent_monitoring import render_agent_monitoring
from app.views.break_it import render_break_it
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
        page_title="Agent Firewall // AI Data Provenance Defense",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply Obsidian Dark Mode (#02070A) & JetBrains Mono typography system
    apply_theme()

    # Top Brand Bar - Linear / Bloomberg Terminal aesthetic
    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.07); padding-bottom: 0.75rem; margin-bottom: 1.25rem;">
            <div style="display: flex; align-items: center; gap: 12px;">
                <span style="font-size: 1.35rem; font-weight: 700; color: #F8FAFC; letter-spacing: -0.03em;">
                    AGENT<span style="color: #0297DE;">FIREWALL</span>
                </span>
                <span class="mono-metric" style="font-size: 10px; color: #0297DE; background: rgba(2, 151, 222, 0.08); border: 1px solid rgba(2, 151, 222, 0.25); padding: 2px 7px; border-radius: 4px; font-weight: 600;">
                    DATA_PROVENANCE // TAINT_TRACKING
                </span>
            </div>
            <div class="mono-metric" style="font-size: 11px; color: #64748B;">
                TRACK: <span style="color: #E2E8F0; font-weight: 600;">GUARDIAN TOOLS & USABLE SECURITY</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar Navigation & Controls
    st.sidebar.markdown(
        """
        <div class="metric-micro-label" style="margin-top: 0.5rem; margin-bottom: 0.5rem;">
            NAVIGATION
        </div>
        """,
        unsafe_allow_html=True,
    )

    nav_pages = [
        "📊 Executive Dashboard",
        "🤖 Agent Monitoring",
        "🎯 Threat Detection",
        "💥 Break It (Red Team)",
        "📜 Event Logs",
        "⚙️ Settings & Policy",
    ]
    selected_page = st.sidebar.radio("View", nav_pages, index=0, label_visibility="collapsed")

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        """
        <div class="metric-micro-label" style="margin-bottom: 0.5rem;">
            DEFENSE PARAMETERS
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Firewall Mode Selection
    firewall_mode = st.sidebar.selectbox(
        "Enforcement Mode",
        ["stage2", "stage1", "off"],
        index=0,
        help=(
            "stage2: Taint tracking + Argument Provenance Override (Recommended, 0% ASR, 100% Utility)\n"
            "stage1: Strict Taint Blocking (0% ASR, 66.7% Utility)\n"
            "off: Firewall Disabled (100% ASR)"
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
        st.sidebar.markdown(
            '<div class="mono-metric" style="font-size: 10px; color: #64748B; margin-top: 4px;">ENGINE: SCRIPTED_DETERMINISTIC</div>',
            unsafe_allow_html=True,
        )

    # Sidebar Status Card
    st.sidebar.markdown("---")
    mode_desc = {
        "stage2": "ACTIVE (PROVENANCE OVERRIDE)",
        "stage1": "ACTIVE (STRICT TAINT)",
        "off": "PASSTHROUGH (OFF)",
    }
    mode_color = "#10B981" if firewall_mode == "stage2" else ("#F59E0B" if firewall_mode == "stage1" else "#EF4444")

    st.sidebar.markdown(
        f"""
        <div class="obsidian-card" style="border-left: 2px solid {mode_color}; padding: 0.75rem 0.9rem; margin-top: 0.5rem;">
            <div class="metric-micro-label" style="margin-bottom: 2px;">GUARD STATUS</div>
            <div class="mono-metric" style="font-size: 11px; font-weight: 700; color: {mode_color};">{mode_desc[firewall_mode]}</div>
            <div class="mono-metric" style="font-size: 10px; color: #64748B; margin-top: 4px;">TARGET: {selected_agent.upper()}</div>
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
    elif selected_page == "💥 Break It (Red Team)":
        render_break_it(all_scenarios, firewall_mode)
    elif selected_page == "📜 Event Logs":
        render_event_logs()
    elif selected_page == "⚙️ Settings & Policy":
        render_settings(firewall_mode)


if __name__ == "__main__":
    main()
