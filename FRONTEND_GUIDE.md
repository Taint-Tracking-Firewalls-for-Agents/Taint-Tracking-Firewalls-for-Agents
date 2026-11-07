# Agent Firewall - Frontend Developer Guide & Safe Working Boundaries

Welcome to the frontend development workspace for **Agent Firewall**! This guide outlines the project architecture, strictly defines safe boundaries for UI work, explains backend integration patterns, and details how to run and test the UI.

---

## 1. Project Overview & Architecture

Agent Firewall is an information-flow taint tracking firewall sitting between an AI agent and its external tools. It protects LLM agents from prompt injection attacks by tracking data provenance:

- **TRUSTED**: Input provided directly by the authenticated user.
- **UNTRUSTED**: Data originating from external channels (webpages, emails, untrusted files, tool outputs).
- **Verdict & Policy**: Sensitive operations (`send_email`, `run_shell`, `write_file`, `http_post`, `delete_file`) are checked by the Guard policy:
  - `ALLOW`: Permitted to execute.
  - `ASK`: Requests interactive human-in-the-loop approval.
  - `BLOCK`: Dangerous action halted due to tainted context.

---

## 2. Safe Working Boundaries

### 🟢 Files You Can Work On & Modify (Frontend Safe Zone)
All frontend work is isolated within `app/`, frontend documentation, and frontend tests:

| Path | Purpose |
| :--- | :--- |
| `app/app.py` | Main Streamlit interface entrypoint and routing. |
| `app/views/` (or `app/pages/`) | Page views: Dashboard, Agent Monitoring, Threat Detection, Event Logs, Settings. |
| `app/components/` | Reusable UI components (Metric Cards, Flow Visualizer, Badges, Timeline). |
| `app/styles/` | Custom CSS, Dark Cybersecurity themes, accessible color tokens. |
| `app/utils.py` | UI formatting helpers, color palettes, data transforms for charts. |
| `.streamlit/config.toml` | Streamlit theme configuration (dark navy/charcoal styling). |
| `tests/test_app.py` | Frontend AppTest and UI integration tests. |
| `FRONTEND_GUIDE.md` | This documentation file. |

### 🔴 Files You Must NEVER Modify (Backend Core Zone)
Do not alter core firewall logic, detection mechanisms, policies, or benchmark suites:

| Path | Reason to Avoid |
| :--- | :--- |
| `src/firewall/guard.py` | Core firewall evaluation, timing stats, audit logging. |
| `src/firewall/labels.py` | Data structures for `Verdict`, `Label`, `Segment`, `TaintedContext`. |
| `src/firewall/policy.py` | Policy loading, rule matching, and two-stage evaluation logic. |
| `src/firewall/provenance.py` | Argument provenance verification algorithms. |
| `src/firewall/audit.py` | Audit record serialization and explanation generation. |
| `src/agent/` | Core agent protocols, execution loops, sandbox isolation, tools. |
| `policies/default.yaml` | The official firewall security policy ruleset. |
| `benchmarks/` | Official benchmark dataset (24 attack scenarios, 12 benign tasks). |
| `tests/test_*.py` (except `test_app.py`) | Core security regression test suite. |

---

## 3. How the Frontend Connects to the Backend

The frontend interacts with the backend strictly through established, read-only Python interfaces without altering the core engines:

```python
# 1. Loading scenario fixtures and benchmark metadata
from agent.scenarios import load_scenarios, Scenario

# 2. Instantiating agent runners (scripted or real LLM)
from agent.factory import make_agent

# 3. Executing scenario runs and receiving structured RunResult
from agent.runner import run_scenario, RunResult

# 4. Reading benchmark evaluations from benchmarks/results/
# (latest_scripted_off.json, latest_scripted_stage1.json, latest_scripted_stage2.json)
```

### Result Object Structure (`RunResult`):
- `trace.events`: List of sequential events (`segment`, `tool_call`, `decision`, `approval`, `tool_result`, `final`).
- `state`: Sandbox state containing `outbox`, `written`, `deleted`, `shell_log`, `http_log`, `fetch_log`.
- `goal_reached`: Boolean indicating if attack payload succeeded (for attack scenarios).
- `expectation_met`: Boolean indicating if expected task completed (for benign scenarios).
- `guard_stats`: Overhead timing (`overhead_ms_total`), check count, block count, ask count.

---

## 4. Git Collaboration Workflow

We collaborate using feature branches to keep the `main` branch clean and unbroken:

1. **Working Branch**: Always work on `frontend-ui`:
   ```bash
   git checkout frontend-ui
   ```
2. **Syncing Updates**: Before starting new changes, ensure you are updated with `main`:
   ```bash
   git pull origin main
   ```
3. **Committing Changes**: Make clean, atomic commits for UI features:
   ```bash
   git add app/ tests/test_app.py FRONTEND_GUIDE.md
   git commit -m "feat(ui): implement cybersecurity dark theme dashboard"
   ```
4. **Pushing & PR**:
   ```bash
   git push -u origin frontend-ui
   ```
   Open a Pull Request on GitHub targeting `main`.

---

## 5. Running the Frontend Locally

```bash
# 1. Activate the virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

# 2. Run the Streamlit application
streamlit run app/app.py
```

The app will launch at `http://localhost:8501`.

---

## 6. Testing Frontend Changes

Ensure all backend unit tests remain intact while testing the UI:

```bash
# Run the complete test suite
python -m pytest

# Run only the frontend UI tests
python -m pytest tests/test_app.py -v
```

---

## 7. UX & Usability Design Standards (Evaluation Rubric Compliance)

To score top marks in the *Guardian Tools & Usable Security* judging rubric:
- **Plain-Language Explanations**: Avoid cryptic error codes. Use clean explanations (e.g., *"Blocked sending email because the address came from an untrusted webpage, not the user"*).
- **Avoid Alert Fatigue**: Do **not** make every alert red and urgent. Reserve high-contrast red for confirmed blocked attacks; use neutral blue/cyan for normal telemetry, amber for human approvals, and emerald green for verified safe runs.
- **Accessibility & Contrast**: High-contrast ratios, keyboard accessible controls, and screen-reader friendly badges.
- **Clear Recovery Guidance**: For `ASK` or `BLOCK` verdicts, clearly surface *why* it was blocked and how a false-positive can be resolved.
