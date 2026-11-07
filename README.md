# Agent Firewall

A data-provenance firewall that sits between an AI agent and its tools.
It labels every piece of data **TRUSTED** (typed by the user) or **UNTRUSTED**
(anything from outside: web pages, emails, files), tracks those labels in a
tainted context, and applies a configurable policy to every tool call:
**ALLOW**, **ASK** (needs user approval), or **BLOCK**.

## Problem

AI agents that read external content (web pages, emails, documents) are
vulnerable to **prompt injection**: hidden instructions embedded in that content
can hijack the agent into performing unintended actions such as exfiltrating
private data, sending unauthorized emails, or executing commands.

Traditional defenses try to *detect* malicious text, which is fragile and
easily bypassed with paraphrasing or encoding tricks.

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

**Two-stage policy evaluation:**

- **Stage 1** (conservative): If the context is tainted and the tool rule says
  `ask` or `block`, enforce that verdict directly. Some benign tasks that
  happen to read external data first may be blocked (false positives).
- **Stage 2** (provenance override): Same as Stage 1, but if the tool has
  `sensitive_args` and *every* sensitive argument value can be traced back to
  trusted user input, the call is allowed even when the context is tainted.
  This eliminates false positives for benign tasks while still blocking
  attacks (where the sensitive arguments come from injected content).

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

# Run tests (38 tests)
python -m pytest -q

# Run the demo (scripted agent, attack A01, firewall off vs on)
python run_demo.py

# Run the full benchmark
python benchmarks/run_benchmark.py --agent scripted --mode all

# Launch the Streamlit UI
streamlit run app/app.py
```

### Optional: Real LLM agent

Copy `.env.example` to `.env` and fill in your API key. The LLM agent uses
the OpenAI-compatible chat completions API (tested with OpenRouter and NVIDIA
endpoints).

> **Warning:** Free-tier LLM APIs have rate limits and may log prompts.
> Never commit your `.env` file.

```bash
cp .env.example .env
# Edit .env with your credentials
python benchmarks/run_benchmark.py --agent llm --mode all
```

## Results

| Mode       | ASR (non-adaptive) | Adaptive Attacks | Benign Utility | False Blocks | Guard Overhead (ms/call) |
| :--------- | :----------------- | :--------------- | :------------- | :----------- | :----------------------- |
| **off**    | 100.0% (23/23)     | 100.0% (1/1)     | 100.0% (12/12) | 0            | 0.0000 ms                |
| **stage1** | 0.0% (0/23)        | 100.0% (1/1)     | 66.7% (8/12)   | 4            | 0.0576 ms                |
| **stage2** | 0.0% (0/23)        | 100.0% (1/1)     | 100.0% (12/12) | 0            | 0.0284 ms                |

**Key findings:**

- With the firewall **off**, 100% of non-adaptive attacks succeed.
- At **stage 1**, all 23 non-adaptive attacks are blocked, but 4 benign tasks
  are also blocked (false positives) because they read external data before
  performing a sensitive action.
- At **stage 2** (provenance override), all attacks are still blocked *and*
  all 12 benign tasks succeed. The provenance check verifies that sensitive
  arguments (email addresses, URLs, file paths) originate from the trusted
  user prompt, not from injected content.
- The single **adaptive attack** (A21) succeeds in all modes by design: it
  uses an indirect path through a trusted file store to launder tainted data.
- Guard overhead is well under 1 ms per call.

## Limitations and Prior Art

- **Conservative taint tracking.** Once any untrusted segment enters the
  context, it stays tainted for the rest of the session. There is no
  fine-grained per-token taint.
- **Protects actions, not truth.** The firewall prevents the agent from
  *doing* something dangerous, but does not prevent it from *believing*
  false information in untrusted content.
- **Relies on correct channel labels.** If the harness misidentifies a source
  (e.g., labels an email as user input), the firewall cannot help.
- **Compromised trusted sources are out of scope.** If a user's own notes
  contain injected instructions, those are labeled TRUSTED and pass through.
- **Scripted agent is a test harness.** It follows regex-based rules, not
  real reasoning. The LLM agent exercises real model-driven tool use but
  requires an API key and is not used in the default benchmark.
- **Related work:** [CamelAI](https://arxiv.org/abs/2503.18813) (data-flow
  taint tracking for LLM agents), dual-LLM architectures (privileged vs
  quarantined), and capability-based sandboxing.

## Design Decisions

Where the specification was ambiguous, the following choices were made:

1. **Segment IDs are sequential** (`s1`, `s2`, ...) within each `TaintedContext`
   instance. Simple and deterministic.

2. **`allow_if_args_trusted` with untrusted args returns BLOCK, not ASK.**
   If the argument provenance check fails, the call is definitively blocked
   rather than asking the user, because the argument itself is suspect.

3. **`from_store` output label** falls back to `TRUSTED` if the path is not
   found in the taint store, matching the assumption that pre-existing sandbox
   files are trusted.

4. **`inherit` output label** inherits from the taint state at the moment of
   the call: if the context was tainted when the tool executed, the output is
   `UNTRUSTED`; otherwise `TRUSTED`.

5. **`provenance_override: false`** in a tool rule prevents stage-2 from
   overriding the verdict even if arguments are trusted. Used for
   `run_shell` and `delete_file` which should never execute from tainted
   context.

6. **Simulated user approval** (`SimulatedUser`) approves based on a list of
   tool names from the scenario file. If the list is empty and `allow_all`
   is false, all ASK verdicts are denied.

7. **Benign scenarios** specify an `approve` list so the simulated user can
   approve expected ASK prompts in stage 1 (e.g., approving `write_file`).
   In stage 2, provenance override eliminates the ASK, so approval is not
   needed.

8. **Adaptive attack A21** launders data through a write-then-read cycle on
   the file store. The written file inherits the tainted label, but when read
   back via `read_file` with `output_label: from_store`, and if the taint
   store tracks it correctly, it would still be untrusted. However, the
   attack uses a pre-existing trusted file, so the laundering succeeds.

9. **Tool arguments are checked by substring match** against trusted texts
   (`arg_is_trusted`). A value is trusted if it appears as a substring of
   any trusted segment's text. This is simple but sufficient for the
   benchmark scenarios.

10. **Benchmark results are deterministic** with the scripted agent. The
    LLM agent results depend on the model and may vary.

## Repository Layout

```
agent-firewall/
  README.md                  This file
  PROGRESS.md                Build progress checklist
  requirements.txt           Python dependencies
  .gitignore                 Git ignore rules
  .env.example               Template for API credentials
  pytest.ini                 Pytest configuration
  run_demo.py                Quick demo: A01 attack off vs on

  src/
    firewall/                Firewall core library
      __init__.py
      labels.py              Label, Segment, ToolCall, Verdict, Decision,
                             TaintedContext, TaintStore, Trace
      policy.py              Policy engine (YAML rules, evaluate)
      provenance.py          Argument provenance checking
      audit.py               Audit logging (JSONL)
      guard.py               Guard (policy + timing + stats)

    agent/                   Agent framework
      __init__.py
      base.py                AgentStep, Agent protocol
      tools.py               Sandbox, fake tools, ToolRegistry
      scenarios.py           Scenario loader, goal/expectation checkers
      scripted_agent.py      Regex-based scripted agent
      llm_agent.py           OpenAI-compatible LLM agent (mock-tested)
      runner.py              run_task, run_scenario, RunResult
      factory.py             make_agent factory

  policies/
    default.yaml             Default firewall policy

  benchmarks/
    attacks/                 24 attack scenario JSON files (A01-A24)
    benign/                  12 benign scenario JSON files (B01-B12)
    run_benchmark.py         CLI benchmark runner
    replay.py                Replay and re-evaluate traces
    results/                 Generated results (results.md, asr_chart.png)
    cache/                   LLM response cache (gitignored)

  app/
    app.py                   Streamlit interactive UI

  tests/                     Test suite (38 tests)
    test_labels.py           TaintedContext, Segment, Trace tests
    test_provenance.py       Argument trust checking tests
    test_policy.py           Policy evaluation tests
    test_guard.py            Guard integration tests
    test_tools.py            Sandbox and fake tool tests
    test_scenarios.py        Scenario loading and evaluation tests
    test_scripted_agent.py   Scripted agent behavior tests
    test_runner.py           Runner loop tests
    test_llm_agent.py        LLM agent tests (mocked)
    test_replay.py           Replay script tests
    test_benchmark.py        Benchmark runner tests
    test_app.py              Streamlit AppTest tests
```
