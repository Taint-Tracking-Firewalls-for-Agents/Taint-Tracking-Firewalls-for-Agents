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
    # Developed By Section (Project Collaborators)
    st.sidebar.markdown("---")
    st.sidebar.markdown(
        """
        <div style="background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--trust); padding: 0.85rem 1rem; border-radius: 2px; margin-top: 0.5rem;">
          <div style="font-size: 10px; font-weight: 700; letter-spacing: 0.08em; color: var(--muted); text-transform: uppercase; margin-bottom: 0.6rem;">
            🛡️ DEVELOPED BY
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.55rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 12px; font-weight: 600; color: var(--ink);">Mohan Mallempudi</span>
              <a href="https://github.com/mohanmallempudi" target="_blank" rel="noopener noreferrer" 
                 style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-family: 'Martian Mono', monospace; color: var(--trust); text-decoration: none; padding: 2px 6px; background: rgba(89, 166, 255, 0.08); border: 1px solid rgba(89, 166, 255, 0.25); border-radius: 2px;">
                <svg height="12" width="12" viewBox="0 0 16 16" fill="currentColor" style="vertical-align: middle;">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                <span>@mohanmallempudi</span>
              </a>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 12px; font-weight: 600; color: var(--ink);">AVKD1279</span>
              <a href="https://github.com/AVKD1279" target="_blank" rel="noopener noreferrer" 
                 style="display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-family: 'Martian Mono', monospace; color: var(--trust); text-decoration: none; padding: 2px 6px; background: rgba(89, 166, 255, 0.08); border: 1px solid rgba(89, 166, 255, 0.25); border-radius: 2px;">
                <svg height="12" width="12" viewBox="0 0 16 16" fill="currentColor" style="vertical-align: middle;">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                <span>@AVKD1279</span>
              </a>
            </div>
          </div>
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
