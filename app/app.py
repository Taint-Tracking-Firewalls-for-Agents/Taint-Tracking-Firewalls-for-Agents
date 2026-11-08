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

# Clean up stale agent modules on reload
for mod in list(sys.modules.keys()):
    if mod.startswith(('agent.', 'firewall.')):
        del sys.modules[mod]

from dotenv import load_dotenv
load_dotenv()

import streamlit as st

from agent.scenarios import Scenario, load_scenarios
from app.styles import apply_theme
from app.views.agent_monitoring import render_agent_monitoring
from app.views.break_it import render_break_it
from app.views.dashboard import render_dashboard
from app.views.live_inbox import render_live_inbox
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
        "Live Email Inbox",
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

    # Ensure environment variables from repo root .env are loaded
    load_dotenv(_repo_root / ".env", override=True)

    # If running on Streamlit Community Cloud, load from st.secrets
    try:
        if hasattr(st, "secrets"):
            for k in ["LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL", "EMAIL_ACCOUNT", "EMAIL_APP_PASSWORD"]:
                if k in st.secrets and not os.getenv(k):
                    os.environ[k] = str(st.secrets[k])
    except Exception:
        pass

    if not os.getenv("LLM_BASE_URL"):
        os.environ["LLM_BASE_URL"] = "https://openrouter.ai/api/v1"
    if not os.getenv("LLM_MODEL"):
        os.environ["LLM_MODEL"] = "nvidia/nemotron-3.5-super-vl:free"

    # Agent Engine Selection: show both if LLM key configured, otherwise scripted with quick setup hint
    llm_ready = bool(os.getenv("LLM_API_KEY"))
    agent_options = ["scripted", "llm"] if llm_ready else ["scripted"]

    selected_agent = st.sidebar.selectbox(
        "Agent Engine",
        agent_options,
        index=0,
        help="Deterministic scripted harness or live Nemotron LLM completions API",
    )
    if not llm_ready:
        st.sidebar.caption("💡 To enable live Nemotron LLM: add `LLM_API_KEY` to `.env` or Streamlit Secrets.")

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
    elif selected_page == "Live Email Inbox":
        render_live_inbox(selected_agent, firewall_mode)
    elif selected_page == "Event Logs":
        render_event_logs()
    elif selected_page == "Policy & Settings":
        render_settings(firewall_mode)


if __name__ == "__main__":
    main()
