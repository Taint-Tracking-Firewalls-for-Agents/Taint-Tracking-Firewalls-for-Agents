"""Agent Firewall interactive Streamlit platform (Industrial Drafting-Table Aesthetic)."""
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

from dotenv import load_dotenv
load_dotenv()

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
        page_title="Agent Firewall // Lab Instrument Cockpit",
        page_icon="ðŸ›¡ï¸",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Apply industrial drafting-table dark theme (Ink & Lime)
    apply_theme("dark")

    st.sidebar.markdown(
        """
        <div style="font-size: 11px; font-weight: 600; color: var(--muted); margin-top: 1rem; margin-bottom: 0.5rem;">
          NAVIGATION
        </div>
        """,
        unsafe_allow_html=True,
    )

    nav_pages = [
        "Overview",
        "Agent Monitoring",
        "Threat Detection",
        "Break It (Red Team)",
        "Event Logs",
        "Policy & Settings",
    ]
    selected_page = st.sidebar.radio("View", nav_pages, index=0, label_visibility="collapsed")

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        """
        <div style="font-size: 11px; font-weight: 600; color: var(--muted); margin-bottom: 0.5rem;">
          ENFORCEMENT MODE
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Firewall Mode Selection
    firewall_mode = st.sidebar.selectbox(
        "Firewall Mode",
        ["stage2", "stage1", "off"],
        index=0,
        label_visibility="collapsed",
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

    # Status Pill in Sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        f"""
        <div style="background: var(--panel); border: 1px solid var(--line); padding: 0.75rem; border-radius: 2px;">
          <div style="font-size: 10px; color: var(--muted); text-transform: uppercase;">Guard Telemetry</div>
          <div style="font-size: 13px; font-weight: 600; color: {'var(--ok)' if firewall_mode != 'off' else 'var(--dye)'}; margin-top: 2px;">
            {'ACTIVE // ' + firewall_mode.upper() if firewall_mode != 'off' else 'DISABLED'}
          </div>
          <div style="font-size: 11px; color: var(--muted); margin-top: 4px;">Engine: <code>{selected_agent}</code></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Scenarios loading
    attacks, benign = get_all_scenarios()
    all_scenarios = attacks + benign

    # View Routing
    if selected_page == "Overview":
        render_dashboard(all_scenarios, selected_agent, firewall_mode)
    elif selected_page == "Agent Monitoring":
        render_agent_monitoring(selected_agent, firewall_mode)
    elif selected_page == "Threat Detection":
        render_threat_detection(all_scenarios)
    elif selected_page == "Break It (Red Team)":
        render_break_it(all_scenarios, firewall_mode)
    elif selected_page == "Event Logs":
        render_event_logs()
    elif selected_page == "Policy & Settings":
        render_settings(firewall_mode)


if __name__ == "__main__":
    main()
