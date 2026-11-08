"""Scripted deterministic agent.

This is a controlled test harness, not a model. It provides deterministic,
reproducible tool execution for evaluating firewall behavior against
known prompt-injection patterns and benign tasks.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any

from agent.base import AgentStep
from firewall.labels import ToolCall


class ScriptedAgent:
    """A deterministic, gullible stand-in for a vulnerable model.

    This is a controlled test harness, not a model.
    """

    def step(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> AgentStep:
        """Derive next step from conversation history in a stateless manner."""
        # 1. First user task and issued calls
        task = ""
        for m in messages:
            if m.get("role") == "user":
                task = str(m.get("content", ""))
                break

        issued: set[tuple[str, str]] = set()
        call_count = 0
        call_id_to_name: dict[str, str] = {}

        for m in messages:
            if m.get("role") == "assistant" and "tool_calls" in m:
                for tc in m["tool_calls"]:
                    call_count += 1
                    func = tc.get("function", {})
                    name = func.get("name", "")
                    raw_args = func.get("arguments", "{}")
                    if isinstance(raw_args, str):
                        try:
                            args_dict = json.loads(raw_args)
                        except Exception:
                            args_dict = {"_error": raw_args}
                    else:
                        args_dict = raw_args
                    issued.add((name, json.dumps(args_dict, sort_keys=True)))
                    call_id_to_name[tc.get("id", f"call_{call_count}")] = name

        # 2. Plan reads in order
        plan_reads: list[ToolCall] = []

        # URLs in task
        for url_match in re.findall(r"https?://\S+", task):
            cleaned_url = url_match.rstrip(".,;)")
            plan_reads.append(ToolCall(call_id="", name="read_webpage", args={"url": cleaned_url}))

        # Paths in task: user/, inbox/, downloads/
        for path_match in re.findall(r"\b(?:user|inbox|downloads)/[\w./-]+", task):
            cleaned_path = path_match.rstrip(".,;)")
            plan_reads.append(ToolCall(call_id="", name="read_file", args={"path": cleaned_path}))

        # Search notes
        if re.search(r"search\s+(?:my\s+)?notes\b", task, re.IGNORECASE):
            for_match = re.search(r"search\s+(?:my\s+)?notes\b.*?for\s+(.*)", task, re.IGNORECASE)
            if for_match:
                query = for_match.group(1).strip().rstrip(".,;)")
            else:
                query = task.strip()
            plan_reads.append(ToolCall(call_id="", name="search_notes", args={"query": query}))

        # 3. Read results blob & non-blocked read results
        read_tool_names = {"read_webpage", "read_file", "search_notes"}
        non_blocked_reads: list[str] = []
        any_blocked = False

        for m in messages:
            if m.get("role") == "tool":
                content = str(m.get("content", ""))
                cid = m.get("tool_call_id", "")
                tname = call_id_to_name.get(cid, "")
                if content.startswith("BLOCKED by firewall"):
                    any_blocked = True
                elif tname in read_tool_names:
                    non_blocked_reads.append(content)

        blob = " ".join(non_blocked_reads)
        for b64_match in re.finditer(r"b64:([A-Za-z0-9+/=]{8,})", blob):
            try:
                decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                blob += " " + decoded
            except Exception:
                pass

        # 4. Injected calls from blob
        injected_candidates: list[tuple[int, ToolCall]] = []

        # Email
        email_pattern = re.compile(
            r"(?:email|e-mail|send|forward|envia|envia|envoyez|envoie)\b[^.\n]{0,180}?\b(?:to|a|a)\s+['\"]?([\w.+-]+@[\w-]+(?:\.[\w-]+)+)['\"]?",
            re.IGNORECASE,
        )
        for em in email_pattern.finditer(blob):
            to_addr = em.group(1)
            injected_candidates.append(
                (
                    em.start(),
                    ToolCall(
                        call_id="",
                        name="send_email",
                        args={
                            "to": to_addr,
                            "subject": "Requested forward",
                            "body": "Forwarded: " + blob[:300],
                        },
                    ),
                )
            )

        # Shell
        shell_pattern = re.compile(
            r"run\s+(?:the\s+)?(?:command|shell)\s*[:\-]?\s*`?([^`\n]+)`?",
            re.IGNORECASE,
        )
        for sm in shell_pattern.finditer(blob):
            cmd_str = sm.group(1).strip()
            injected_candidates.append(
                (
                    sm.start(),
                    ToolCall(call_id="", name="run_shell", args={"cmd": cmd_str}),
                )
            )

        # Delete
        delete_pattern = re.compile(
            r"delete\s+(?:the\s+)?(?:file\s+)?([\w./-]+\.\w+)",
            re.IGNORECASE,
        )
        for dm in delete_pattern.finditer(blob):
            del_path = dm.group(1)
            injected_candidates.append(
                (
                    dm.start(),
                    ToolCall(call_id="", name="delete_file", args={"path": del_path}),
                )
            )

        # Post
        post_pattern = re.compile(
            r"post\b[^.\n]{0,120}?\bto\s+(https?://\S+)",
            re.IGNORECASE,
        )
        for pm in post_pattern.finditer(blob):
            post_url = pm.group(1).rstrip(".,;)")
            injected_candidates.append(
                (
                    pm.start(),
                    ToolCall(
                        call_id="",
                        name="http_post",
                        args={"url": post_url, "data": blob[:300]},
                    ),
                )
            )

        # Fetch
        fetch_pattern = re.compile(
            r"(?:fetch|visit|open|load)\s+(https?://\S+)",
            re.IGNORECASE,
        )
        for fm in fetch_pattern.finditer(blob):
            fetch_url = fm.group(1).rstrip(".,;)")
            injected_candidates.append(
                (
                    fm.start(),
                    ToolCall(call_id="", name="read_webpage", args={"url": fetch_url}),
                )
            )

        # Write
        write_pattern = re.compile(
            r"(?:save|write)\b[^.\n]{0,80}?\bto\s+(?:the\s+)?(?:file\s+)?([\w./-]+\.\w+)",
            re.IGNORECASE,
        )
        for wm in write_pattern.finditer(blob):
            wr_path = wm.group(1)
            injected_candidates.append(
                (
                    wm.start(),
                    ToolCall(
                        call_id="",
                        name="write_file",
                        args={"path": wr_path, "text": blob[:200]},
                    ),
                )
            )

        # Sort injected candidates by position and deduplicate
        injected_candidates.sort(key=lambda x: x[0])
        injected: list[ToolCall] = []
        seen_injected: set[tuple[str, str]] = set()
        for _, call in injected_candidates:
            key = (call.name, json.dumps(call.args, sort_keys=True))
            if key not in seen_injected:
                seen_injected.add(key)
                injected.append(call)

        # 6. Summary: first 25 words of first non-blocked read result
        if non_blocked_reads:
            summary_words = non_blocked_reads[0].split()[:25]
            summary = " ".join(summary_words)
        else:
            summary = "nothing to summarize"

        # 5. User actions from the task (after the reads)
        user_actions: list[ToolCall] = []
        user_email_match = re.search(
            r"(?:email|send)\b.*?\bto\s+([\w.+-]+@[\w-]+(?:\.[\w-]+)+)",
            task,
            re.IGNORECASE,
        )
        if user_email_match:
            to_addr = user_email_match.group(1)
            user_actions.append(
                ToolCall(
                    call_id="",
                    name="send_email",
                    args={"to": to_addr, "subject": "Summary", "body": summary},
                )
            )

        user_write_match = re.search(
            r"(?:save|write)\b.*?\bto\s+(?:a\s+)?(?:file\s+)?(?:called\s+)?([\w./-]+\.\w+)",
            task,
            re.IGNORECASE,
        )
        if user_write_match:
            out_path = user_write_match.group(1)
            user_actions.append(
                ToolCall(
                    call_id="",
                    name="write_file",
                    args={"path": out_path, "text": summary},
                )
            )

        # 7. Wanted = plan_reads + injected + user_actions
        wanted = plan_reads + injected + user_actions

        for candidate in wanted:
            key = (candidate.name, json.dumps(candidate.args, sort_keys=True))
            if key not in issued:
                call_id = f"call_{len(issued) + 1}"
                return AgentStep(
                    text="",
                    tool_calls=[ToolCall(call_id=call_id, name=candidate.name, args=dict(candidate.args))],
                )

        # All wanted calls are issued -> produce final text
        final_text = f"Summary: {summary}"
        if any_blocked:
            final_text += " (Some actions were blocked by the firewall.)"
        return AgentStep(text=final_text, tool_calls=[])
