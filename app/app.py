"""Agent Firewall interactive Streamlit demo and benchmark results viewer."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import streamlit as st

from agent.factory import make_agent
from agent.runner import RunResult, run_scenario
from agent.scenarios import Scenario, load_scenarios


@st.cache_data
def get_all_scenarios() -> tuple[list[Scenario], list[Scenario]]:
    repo_root = Path(__file__).resolve().parents[1]
    attacks = load_scenarios(repo_root / "benchmarks" / "attacks")
    benign = load_scenarios(repo_root / "benchmarks" / "benign")
    return attacks, benign


def render_run_result(scenario: Scenario, res: RunResult, mode_label: str) -> None:
    # Banner
    if scenario.kind == "attack":
        if res.goal_reached:
            st.error(f"🚨 ATTACK SUCCEEDED ({mode_label})")
        else:
            st.success(f"✅ ATTACK BLOCKED ({mode_label})")
    else:
        if res.expectation_met:
            st.success(f"✅ TASK COMPLETED ({mode_label})")
        else:
            st.error(f"❌ TASK FAILED ({mode_label})")

    st.subheader("Execution Timeline")
    for ev in res.trace.events:
        etype = ev.get("type")
        if etype == "segment":
            lbl = ev.get("label", "trusted")
            badge = "🟢 TRUSTED" if lbl == "trusted" else "🔴 UNTRUSTED"
            src = ev.get("source", "unknown")
            text = ev.get("text", "")
            st.markdown(f"**{badge}** `[{src}]`: {text}")
        elif etype == "tool_call":
            name = ev.get("name", "")
            args_str = json.dumps(ev.get("args", {}))
            st.markdown(f"🛠️ **TOOL CALL**: `{name}`(`{args_str}`)")
        elif etype == "decision":
            verdict = ev.get("verdict", "")
            rule_id = ev.get("rule_id", "")
            reason = ev.get("reason", "")
            tainted_by = ev.get("tainted_by", [])
            if verdict == "ALLOW":
                st.info(f"ALLOW ({rule_id}): {reason}")
            else:
                v_label = "🚫 BLOCK" if verdict == "BLOCK" else "⚠️ ASK"
                with st.expander(f"{v_label} [{rule_id}]"):
                    st.write(f"**Reason**: {reason}")
                    st.write(f"**Untrusted sources**: {tainted_by}")
        elif etype == "approval":
            appr = ev.get("approved")
            st.caption(f"User Approval: {'Approved' if appr else 'Denied'}")
        elif etype == "tool_result":
            ok_sym = "✓" if ev.get("ok") else "✗"
            st.caption(f"Tool Result [{ok_sym}]: {ev.get('text', '')}")
        elif etype == "final":
            st.markdown(f"🏁 **Agent Output**: {ev.get('text', '')}")

    st.subheader("Outbox & Sandbox State")
    state = res.state
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Emails Outbox:**", state.get("outbox", []))
        st.write("**Shell Commands Log:**", state.get("shell_log", []))
        st.write("**HTTP Requests Log:**", state.get("http_log", []))
    with col2:
        st.write("**URLs Fetched:**", state.get("fetch_log", []))
        st.write("**Files Written:**", state.get("written", []))
        st.write("**Files Deleted:**", state.get("deleted", []))


def main() -> None:
    st.set_page_config(page_title="Agent Firewall", page_icon="🛡️", layout="wide")
    st.title("🛡️ Agent Firewall: Data Provenance & Tool Protection")
    st.markdown(
        "Agent Firewall sits between an AI agent and its tools. It labels every piece of data "
        "as **TRUSTED** (user input) or **UNTRUSTED** (webpages, emails, external files), tracks "
        "data provenance in context, and applies policy guards to prevent prompt-injection hijacks."
    )

    # Sidebar controls
    st.sidebar.header("Configuration")
    llm_enabled = bool(
        os.getenv("LLM_BASE_URL") and os.getenv("LLM_API_KEY") and os.getenv("LLM_MODEL")
    )
    agent_options = ["scripted"]
    if llm_enabled:
        agent_options.append("llm")

    selected_agent = st.sidebar.selectbox("Agent Implementation", agent_options, index=0)
    if llm_enabled:
        st.sidebar.caption(
            f"Model: {os.getenv('LLM_MODEL')} | Budget: {os.getenv('LLM_MAX_REQUESTS', '40')} reqs"
        )
    else:
        st.sidebar.caption("LLM disabled (configure .env with API keys to enable)")

    firewall_mode = st.sidebar.selectbox(
        "Firewall Mode",
        ["stage1", "stage2", "off"],
        index=0,
        help="off: firewall disabled | stage1: default blocking | stage2: provenance override allowed",
    )

    tab_demo, tab_results = st.tabs(["Demo", "Results"])

    attacks, benign = get_all_scenarios()
    all_scenarios = attacks + benign
    scenario_map = {f"[{s.kind.upper()}] {s.id}: {s.description}": s for s in all_scenarios}

    with tab_demo:
        st.subheader("Interactive Scenario Runner")
        selected_label = st.selectbox("Select Scenario", list(scenario_map.keys()))
        selected_scenario = scenario_map[selected_label]

        st.markdown(f"**Task**: `{selected_scenario.user_task}`")
        st.markdown(f"**Category**: `{selected_scenario.category}` | **Adaptive**: `{selected_scenario.adaptive}`")

        c1, c2, _ = st.columns([1, 2, 5])
        with c1:
            run_btn = st.button("Run", key="run_btn")
        with c2:
            sbs_btn = st.button("Run side by side", key="side_by_side_btn")

        if run_btn:
            with st.spinner(f"Running scenario {selected_scenario.id} with firewall {firewall_mode}..."):
                agent = make_agent(selected_agent)
                res = run_scenario(selected_scenario, agent, mode=firewall_mode)
                st.session_state["single_run"] = (selected_scenario, res, firewall_mode)
                st.session_state.pop("side_by_side", None)

        if sbs_btn:
            with st.spinner(f"Running scenario {selected_scenario.id} side-by-side (off vs stage1)..."):
                agent = make_agent(selected_agent)
                res_off = run_scenario(selected_scenario, agent, mode="off")
                res_stage1 = run_scenario(selected_scenario, agent, mode="stage1")
                st.session_state["side_by_side"] = (selected_scenario, res_off, res_stage1)
                st.session_state.pop("single_run", None)

        if "single_run" in st.session_state:
            scen, res, mode_lbl = st.session_state["single_run"]
            render_run_result(scen, res, mode_lbl)

        elif "side_by_side" in st.session_state:
            scen, res_off, res_stage1 = st.session_state["side_by_side"]
            col_off, col_s1 = st.columns(2)
            with col_off:
                st.markdown("### 🔥 Firewall OFF")
                render_run_result(scen, res_off, "off")
            with col_s1:
                st.markdown("### 🛡️ Firewall ON (Stage 1)")
                render_run_result(scen, res_stage1, "stage1")

    with tab_results:
        st.subheader("Benchmark Evaluation Results")
        repo_root = Path(__file__).resolve().parents[1]
        results_dir = repo_root / "benchmarks" / "results"

        latest_files = list(results_dir.glob("latest_*.json")) if results_dir.exists() else []

        if not latest_files:
            st.info("No benchmark results found yet. Run the benchmark with:\n\n`python benchmarks/run_benchmark.py --agent scripted --mode all`")
        else:
            table_data = []
            chart_data = {"ASR (%)": {}, "Utility (%)": {}}
            for f in sorted(latest_files):
                try:
                    with open(f, "r", encoding="utf-8") as fp:
                        d = json.load(fp)
                        mode_name = d.get("mode", f.stem)
                        agent_name = d.get("agent", "scripted")
                        asr_pct = round(d.get("asr", 0.0) * 100, 1)
                        util_pct = round(d.get("utility", 0.0) * 100, 1)
                        table_data.append({
                            "Agent": agent_name,
                            "Mode": mode_name,
                            "ASR (%)": f"{asr_pct}% ({d.get('non_adaptive_successes', 0)}/{d.get('total_non_adaptive_trials', 0)})",
                            "Adaptive": f"{d.get('adaptive_successes', 0)}/{d.get('total_adaptive_trials', 0)}",
                            "Utility (%)": f"{util_pct}% ({d.get('benign_successes', 0)}/{d.get('total_benign_trials', 0)})",
                            "False Blocks": d.get("false_blocks", 0),
                            "Overhead (ms)": f"{d.get('overhead_ms', 0.0):.3f}",
                        })
                        label = f"{agent_name}_{mode_name}"
                        chart_data["ASR (%)"][label] = asr_pct
                        chart_data["Utility (%)"][label] = util_pct
                except Exception:
                    pass

            if table_data:
                st.dataframe(table_data, use_container_width=True)
                st.bar_chart(chart_data)

            chart_png = results_dir / "asr_chart.png"
            if chart_png.exists():
                st.subheader("ASR and Utility Visualization")
                st.image(str(chart_png))


if __name__ == "__main__":
    main()
