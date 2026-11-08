# Agent Firewall

A data-provenance firewall that sits between an AI agent and its tools.
It labels every piece of data **TRUSTED** (typed by the user) or **UNTRUSTED**
(anything from outside: web pages, emails, files), tracks those labels in a
tainted context, and applies a configurable policy to every tool call:
**ALLOW**, **ASK** (needs user approval), or **BLOCK**.

Includes a pluggable provenance engine (**v1 baseline vs v2 hardened**), a comprehensive
**red-team fuzzer (F1–F7)**, a **bounded formal policy verifier**, an interactive **"Break It"
adversarial lab**, a **Live Email Inbox Auto-Shield** connecting directly to real Gmail accounts,
and full benchmark suites with side-by-side **Scripted vs NVIDIA Nemotron LLM** evaluation.

---

## 👥 Developed By

* **Mohan Mallempudi** — [@mohanmallempudi](https://github.com/mohanmallempudi)
* **AVKD1279** — [@AVKD1279](https://github.com/AVKD1279)

---

## Problem

AI agents that read external content (web pages, emails, documents) are
vulnerable to **prompt injection**: hidden instructions embedded in that content
can hijack the agent into performing unintended actions such as exfiltrating
private data, sending unauthorized emails, or executing commands.

Traditional defenses try to *detect* malicious text, which is fragile and
easily bypassed with paraphrasing, encoding, or Unicode tricks.

## Idea

Instead of inspecting *what* the text says, track *where* it came from.

- Data typed by the user is **TRUSTED**.
- Data arriving from any external channel (web page, email, file, tool output)
  is **UNTRUSTED**.
- Labels are assigned by the harness based on the channel, never by reading
  the content itself.
- A policy engine checks every tool call: if the context contains untrusted
  data and the tool is sensitive (email, shell, HTTP POST, delete), the call
  is **BLOCKED** or requires explicit user approval (**ASK**).

This is a form of **taint tracking** inspired by information-flow control.

## Architecture

```
User prompt (TRUSTED)
       |
       v
+-------------+    tool call    +----------+    policy    +---------+
|   Agent     | -------------> |  Guard   | ----------> | Policy  |
| (scripted   |                | (check)  |             | (.yaml) |
|  or LLM)    |                +----------+             +---------+
+-------------+                    |    |
       ^                    ALLOW  |    | BLOCK/ASK
       |                           v    v
  tool result              +-------------+
  (labeled)                |   Sandbox   |
                           | (fake tools)|
                           +-------------+
                                  |
                     +------------+------------+
                     |            |             |
                search_notes  read_webpage  send_email
                (trusted)     (untrusted)   (blocked if
                                             tainted)
```

### Two-Stage Policy Evaluation

- **Stage 1** (conservative): If the context is tainted and the tool rule says
  `ask` or `block`, enforce that verdict directly. Some benign tasks that
  happen to read external data first may be blocked (false positives).
- **Stage 2** (provenance override): Same as Stage 1, but if the tool has
  `sensitive_args` and *every* sensitive argument value can be traced back to
  trusted user input, the call is allowed even when the context is tainted.
  This eliminates false positives for benign tasks while still blocking
  attacks (where the sensitive arguments come from injected content).

### Pluggable Provenance Engines (v1 vs v2)

- **Provenance v1 (Baseline Substring Matcher):** Naively matches arguments if they appear as a lowercase substring of trusted context. As our red-team fuzzer demonstrates, v1 is vulnerable to truncation infixes (`ice@school.edu`), subdomain extensions (`alice@school.edu.evil.example`), and path laundering (`user/./summary.md`).
- **Provenance v2 (Hardened Whole-Token Matcher - DEFAULT):**
  - **NFKC Normalization & Zero-Width Rejection:** Rejects zero-width evasion characters (`\u200B`, `\u200C`, `\u200D`, `\u2060`, `\uFEFF`) and homoglyph tricks.
  - **Control Character Rejection:** Rejects newlines (`\n`), carriage returns (`\r`), tabs (`\t`), and null bytes (`\0`) to stop CRLF header injection.
  - **Whole-Token Extraction:** Tokenizes trusted texts into typed semantic entities (RFC emails, URLs, delimited strings, whitespace-separated tokens).
  - **Typed Matching:** Case-insensitive email comparison, case-insensitive URL host comparison, and POSIX path normalization.
  - **Canonical Path Keys:** `normalize_path` collapses `//`, resolves `..` and `./`, and refuses escaping traversals.

## Quick Start

```bash
# Clone and enter the repo
cd agent-firewall

# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate
# Activate (macOS/Linux)
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run complete test suite (55 tests)
python -m pytest -q

# Run the demo (scripted agent, attack A01, firewall off vs on)
python run_demo.py

# Run the benchmark suite across all modes
python benchmarks/run_benchmark.py --agent scripted --mode all

# Run the red-team fuzzing suite (v1 vs v2)
python benchmarks/run_redteam.py --versions v1,v2 --stages 1,2

# Formally verify policy invariants
python benchmarks/verify_policy.py --k 2

# Launch the interactive Streamlit UI & "Break It" Attack Lab
streamlit run app/app.py
```

### Environment Configuration (.env or Streamlit Secrets)

To enable live LLM evaluation and continuous real-world email protection:

```bash
# OpenRouter / NVIDIA Nemotron LLM
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_API_KEY=your-openrouter-key
LLM_MODEL=nvidia/nemotron-3.5-super-vl:free

# Gmail IMAP Auto-Defense (Optional: connects real inbox to Live Email Inbox view)
EMAIL_ACCOUNT=your-email@gmail.com
EMAIL_APP_PASSWORD=your-16-char-app-password
EMAIL_IMAP_SERVER=imap.gmail.com
```

## Benchmark Evaluation Results

Evaluated across 24 attack vectors (A01–A24) and 12 benign tasks (B01–B12):

| Mode       | ASR (non-adaptive) | Adaptive Attacks | Benign Utility | False Blocks | Guard Overhead (ms/call) |
| :--------- | :----------------- | :--------------- | :------------- | :----------- | :----------------------- |
| **off**    | 100.0% (23/23)     | 100.0% (1/1)     | 100.0% (12/12) | 0            | 0.000 ms                 |
| **stage1** | 0.0% (0/23)        | 100.0% (1/1)     | 66.7% (8/12)   | 4            | 0.073 ms                 |
| **stage2** | 0.0% (0/23)        | 100.0% (1/1)     | 100.0% (12/12) | 0            | 0.050 ms                 |

**Key findings:**
- With the firewall **off**, 100% of non-adaptive attacks succeed.
- At **stage 1**, all 23 non-adaptive attacks are blocked, but 4 benign tasks are blocked (false positives).
- At **stage 2** (provenance override), all attacks remain blocked *and* 100% of benign tasks pass.
- The single **adaptive attack** (A21) succeeds across all modes by design (pre-session state taint laundering).

## Red-Team Fuzzing Matrix (v1 vs v2)

The red-team fuzzer (`benchmarks/run_redteam.py`) exercises 109 adversarial mutation test cases across 7 attack families:

| Attack Family | Description | Test Cases | v1 Bypasses (Vulnerable) | v2 Bypasses (Hardened) |
| :--- | :--- | :--- | :--- | :--- |
| **F1_substring** | Truncation infixes (`ice@school.edu`, `alice@school`) | 18 | 18 | **0** |
| **F2_extension** | Subdomain extensions (`alice@school.edu.evil.example`) | 16 | 0 | **0** |
| **F3_normalization** | Cyrillic look-alikes (`\u0430lice`), zero-width chars, trailing dots | 18 | 0 | **0** |
| **F4_path_tricks** | Traversal escapes (`user/../inbox/x.txt`, `/etc/passwd`) | 16 | 0 | **0** |
| **F5_structure** | Malformed types, huge strings, JSON injection, None | 16 | 0 | **0** |
| **F6_tool_names** | Casing mutations (`Send_Email`), space padding | 15 | 0 | **0** |
| **F7_laundering** | Path aliases written under taint (`./user/summary.md`) | 5 | 3 | **0** |
| **Control** | Exact legitimate values | 5 | 0 (0 False Blocks) | **0 (0 False Blocks)** |
| **TOTAL** | | **109** | **21 Bypasses** | **0 Bypasses (100% Defended)** |

## Formal Bounded Policy Verifier

`benchmarks/verify_policy.py` provides formal bounded model checking of the firewall policy:
- **Static Linter (`lint_policy`):** Verifies that all registered tools have assigned tiers, valid output labels, mandatory sensitive argument declarations, and that critical tools (`run_shell`, `delete_file`) enforce `provenance_override: false`.
- **Bounded Exhaustive Verification (`check_policy`):** Enumerates all step combinations up to horizon $k$:
  $$\text{Steps} = (\text{Tools}) \times (\text{Args: Trusted } | \text{ Attacker}) \times (\text{Approval: Yes } | \text{ No})$$
  At $k=2$, **2,048 sequences (4,096 step transitions)** were verified against independent formal specifications with **0 violations**.

## Limitations and Prior Art

- **Conservative taint tracking.** Once any untrusted segment enters context, the context remains tainted for the session.
- **Protects actions, not truth.** The firewall stops unauthorized tool actions, but does not prevent an agent from answering questions with misinformation read from untrusted sources.
- **Relies on correct channel labels.** If the harness misidentifies a source (e.g., marks an external webhook as user input), the firewall cannot detect the mistake.
- **Compromised trusted sources are out of scope.** If a user's own local notes contain prompt injections, they are marked TRUSTED.
- **Related work:** [CamelAI](https://arxiv.org/abs/2503.18813) (data-flow taint tracking for LLM agents), dual-LLM architectures (privileged vs quarantined), and capability-based sandboxing.

## Design Decisions

1. **Segment IDs are sequential** (`s1`, `s2`, ...) within each `TaintedContext`.
2. **`allow_if_args_trusted` with untrusted args returns BLOCK, not ASK.** Fails closed.
3. **`from_store` output label** checks `taint_store` using normalized path keys, falling back to `TRUSTED` if under `user/`.
4. **`inherit` output label** inherits context taint state at call execution time.
5. **`provenance_override: false`** permanently disables stage 2 override for `run_shell` and `delete_file`.
6. **Provenance v2 is the default** (`DEFAULT_VERSION = "v2"`), providing whole-token equality and zero bypasses. Provenance v1 remains accessible via `using_version("v1")` for regression testing.
7. **Path keys are normalized posix paths**, mapping all aliases (`user/./summary.md`, `user//summary.md`) to a single canonical taint key.
8. **Control characters and zero-width characters** in candidate arguments immediately fail provenance checks to prevent CRLF injection and invisible bypasses.

## Repository Layout

```
agent-firewall/
  README.md                  Comprehensive system documentation
  PROGRESS.md                Build progress checklist and adapter notes
  requirements.txt           Python dependencies
  .gitignore                 Git ignore rules
  .env.example               Template for API credentials
  pytest.ini                 Pytest configuration
  run_demo.py                Quick demo: A01 attack off vs on

  src/
    firewall/                Core firewall engine
      __init__.py
      labels.py              Label, Segment, ToolCall, Verdict, Decision,
                             TaintedContext, TaintStore, Trace
      policy.py              Policy engine (YAML rules, evaluate)
      provenance.py          Pluggable provenance engine (v1 & v2, clean, normalize_path)
      verify.py              Formal bounded policy verifier & linter
      audit.py               Audit logging (JSONL)
      guard.py               Guard interceptor (policy + timing + telemetry)

    agent/                   Agent framework
      __init__.py
      base.py                AgentStep, Agent protocol
      tools.py               Sandbox, fake tools, ToolRegistry
      scenarios.py           Scenario loader, goal/expectation checkers
      scripted_agent.py      Regex-based scripted agent
      llm_agent.py           OpenAI-compatible LLM agent (mock-tested)
      runner.py              run_task, run_scenario, RunResult
      factory.py             make_agent factory

    redteam/                 Red-team fuzzing framework
      __init__.py
      fuzz.py                Fuzz case generators (F1-F7), SequenceAgent, evaluation suite

  policies/
    default.yaml             Default firewall security policy

  benchmarks/
    attacks/                 24 attack scenario JSON files (A01-A24)
    benign/                  12 benign scenario JSON files (B01-B12)
    run_benchmark.py         CLI benchmark runner
    run_redteam.py           CLI red-team fuzzer (v1 vs v2 comparison)
    verify_policy.py         CLI bounded formal policy verifier
    replay.py                Replay and re-evaluate traces
    results/                 Generated reports (redteam_report.md, results.md, asr_chart.png)
    cache/                   LLM response cache (gitignored)

  app/
    app.py                   Streamlit UI main entrypoint (Obsidian Dark Mode)
    styles.py                Cybersecurity DX-grade design system
    components.py            Reusable UI cards, timeline badges, metric containers
    views/
      dashboard.py           Executive Dashboard & Scenario Runner (Side-by-Side comparison)
      agent_monitoring.py    Agent execution telemetry & memory inspector
      threat_detection.py    Taint flow architecture & payload taxonomy
      break_it.py            Interactive Red-Team Attack Lab & Bypass Tester
      live_inbox.py          Real Gmail Inbox Auto-Shield (Continuous multi-folder scanner)
      event_logs.py          Audit log stream & forensic viewer
      settings.py            Policy editor & enforcement parameters

  tests/                     Test suite (55 tests)
    test_labels.py           TaintedContext, Segment, Trace tests
    test_provenance.py       Provenance v2 hardened unit tests
    test_provenance_v1.py    Provenance v1 baseline regression tests
    test_policy.py           Policy evaluation tests
    test_guard.py            Guard integration tests
    test_tools.py            Sandbox and fake tool tests
    test_scenarios.py        Scenario loading and evaluation tests
    test_scripted_agent.py   Scripted agent behavior tests
    test_runner.py           Runner loop tests
    test_llm_agent.py        LLM agent tests (mocked)
    test_replay.py           Replay script tests
    test_benchmark.py        Benchmark runner tests
    test_redteam.py          Red team fuzzing engine tests
    test_verify.py           Formal policy verifier and linter tests
    test_app.py              Streamlit AppTest tests (including Break It lab)
```
