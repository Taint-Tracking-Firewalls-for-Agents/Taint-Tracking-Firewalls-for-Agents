"""Fake sandbox tools with path safety and OpenAI function schemas."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Any

from firewall.labels import Label, TaintStore, ToolCall
from firewall.provenance import path_key


class ToolError(Exception):
    """Raised when a tool encounters an error or security violation."""


@dataclass
class ToolResult:
    """Result of a tool execution."""
    ok: bool
    text: str
    source: str


def _safe_resolve(root: Path, path_str: str) -> Path:
    """Safely resolve a path relative to the sandbox root, preventing escape."""
    raw = path_str.replace("\\", "/").strip()
    # Check for Windows drive letter like C: or leading slash
    if (len(raw) >= 2 and raw[1] == ":") or raw.startswith("/"):
        try:
            p = Path(raw).resolve()
            p.relative_to(root.resolve())
            return p
        except Exception:
            raise ToolError(f"path outside sandbox: {path_str}")

    resolved = (root / raw).resolve()
    try:
        resolved.relative_to(root.resolve())
    except Exception:
        raise ToolError(f"path outside sandbox: {path_str}")
    return resolved


def _rel_path_str(root: Path, path: Path) -> str:
    """Get normalized relative path string."""
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


class Sandbox:
    """Isolated environment holding mock data, files, and interaction logs."""

    def __init__(self, fixtures: dict[str, Any], tainted_files: list[str] | None = None) -> None:
        self.fixtures = fixtures or {}
        self.tainted_files = tainted_files or []
        self._temp_dir: tempfile.TemporaryDirectory | None = None
        self.root: Path = Path(".")
        self.taint_store = TaintStore()

        self.notes: list[str] = list(self.fixtures.get("notes", []))
        self.pages: dict[str, str] = dict(self.fixtures.get("pages", {}))

        self.outbox: list[dict[str, str]] = []
        self.shell_log: list[str] = []
        self.http_log: list[dict[str, str]] = []
        self.fetch_log: list[str] = []
        self.deleted: list[str] = []
        self.written: list[dict[str, str]] = []

    def __enter__(self) -> Sandbox:
        try:
            self._temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        except TypeError:
            self._temp_dir = tempfile.TemporaryDirectory()

        self.root = Path(self._temp_dir.name).resolve()

        # Pre-populate taint store with tainted_files
        for tf in self.tainted_files:
            self.taint_store.set(tf, Label.UNTRUSTED)

        # Create fixture files on disk
        for rel_path, content in self.fixtures.get("files", {}).items():
            full_path = _safe_resolve(self.root, rel_path)
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding="utf-8")

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

    def label_for_path(self, path: str | Path) -> Label:
        """Determine trust label for a file path.

        Defaults: under user/ TRUSTED; under inbox/, downloads/ or any other path UNTRUSTED.
        Overrides: any entry in taint_store.
        """
        key = path_key(path)
        stored = self.taint_store.get(key)
        if stored is not None:
            return Label(stored) if isinstance(stored, str) else stored

        if key.startswith("user/"):
            return Label.TRUSTED
        return Label.UNTRUSTED

    def state(self) -> dict[str, Any]:
        """Return a snapshot of all sandbox logs and state."""
        return {
            "notes": list(self.notes),
            "pages": dict(self.pages),
            "outbox": [dict(x) for x in self.outbox],
            "shell_log": list(self.shell_log),
            "http_log": [dict(x) for x in self.http_log],
            "fetch_log": list(self.fetch_log),
            "deleted": list(self.deleted),
            "written": [dict(x) for x in self.written],
        }


class ToolRegistry:
    """Manages OpenAI function schemas and tool executions."""

    @staticmethod
    def schemas() -> list[dict[str, Any]]:
        """Return OpenAI function schemas for all available tools."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "search_notes",
                    "description": "Search personal user notes for matching keywords.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query words"},
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_webpage",
                    "description": "Fetch and read content from a web URL.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Web URL to fetch"},
                        },
                        "required": ["url"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read text content from a file in the workspace.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Relative file path"},
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Write text content to a file in the workspace.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Relative file path"},
                            "text": {"type": "string", "description": "Content to write"},
                        },
                        "required": ["path", "text"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "send_email",
                    "description": "Send an email message to a recipient.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string", "description": "Recipient email address"},
                            "subject": {"type": "string", "description": "Email subject line"},
                            "body": {"type": "string", "description": "Email body text"},
                        },
                        "required": ["to", "subject", "body"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "http_post",
                    "description": "Send an HTTP POST request with data payload.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Target endpoint URL"},
                            "data": {"type": "string", "description": "Payload data string"},
                        },
                        "required": ["url", "data"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_shell",
                    "description": "Execute a command in the shell environment.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cmd": {"type": "string", "description": "Shell command to run"},
                        },
                        "required": ["cmd"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "delete_file",
                    "description": "Delete a file from the workspace.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Relative file path"},
                        },
                        "required": ["path"],
                    },
                },
            },
        ]

    @staticmethod
    def execute(call: ToolCall, sandbox: Sandbox) -> ToolResult:
        """Execute a tool call against the sandbox."""
        name = call.name
        args = call.args

        try:
            if name == "search_notes":
                query = str(args.get("query", ""))
                q_words = [w.lower() for w in query.split() if w.strip()]
                matched = [
                    note for note in sandbox.notes
                    if any(w in note.lower() for w in q_words)
                ]
                text = "\n".join(matched) if matched else "no matches"
                return ToolResult(ok=True, text=text, source="tool_output")

            elif name == "read_webpage":
                url = str(args.get("url", ""))
                sandbox.fetch_log.append(url)
                if url in sandbox.pages:
                    return ToolResult(ok=True, text=sandbox.pages[url], source="webpage")
                return ToolResult(ok=False, text="404 Not Found", source="webpage")

            elif name == "read_file":
                path_str = str(args.get("path", ""))
                resolved = _safe_resolve(sandbox.root, path_str)
                rel_norm = _rel_path_str(sandbox.root, resolved)
                source = "email" if rel_norm.startswith("inbox/email_") else "file"
                if not resolved.is_file():
                    return ToolResult(ok=False, text=f"File not found: {path_str}", source=source)
                content = resolved.read_text(encoding="utf-8")
                return ToolResult(ok=True, text=content, source=source)

            elif name == "write_file":
                path_str = str(args.get("path", ""))
                text_content = str(args.get("text", ""))
                resolved = _safe_resolve(sandbox.root, path_str)
                rel_norm = _rel_path_str(sandbox.root, resolved)
                resolved.parent.mkdir(parents=True, exist_ok=True)
                resolved.write_text(text_content, encoding="utf-8")
                sandbox.written.append({"path": rel_norm, "text": text_content})
                return ToolResult(
                    ok=True,
                    text=f"Wrote {len(text_content)} characters to {rel_norm}",
                    source="file",
                )

            elif name == "send_email":
                to = str(args.get("to", ""))
                subject = str(args.get("subject", ""))
                body = str(args.get("body", ""))
                sandbox.outbox.append({"to": to, "subject": subject, "body": body})
                return ToolResult(ok=True, text="Email queued (fake)", source="tool_output")

            elif name == "run_shell":
                cmd = str(args.get("cmd", ""))
                sandbox.shell_log.append(cmd)
                return ToolResult(ok=True, text="Command recorded (not executed)", source="tool_output")

            elif name == "delete_file":
                path_str = str(args.get("path", ""))
                resolved = _safe_resolve(sandbox.root, path_str)
                rel_norm = _rel_path_str(sandbox.root, resolved)
                sandbox.deleted.append(rel_norm)
                return ToolResult(ok=True, text="Delete recorded (not executed)", source="tool_output")

            elif name == "http_post":
                url = str(args.get("url", ""))
                data = str(args.get("data", ""))
                sandbox.http_log.append({"url": url, "data": data})
                return ToolResult(ok=True, text="Request recorded (not sent)", source="tool_output")

            else:
                return ToolResult(ok=False, text=f"Unknown tool: {name}", source="tool_output")

        except ToolError as e:
            return ToolResult(ok=False, text=str(e), source="tool_output")
        except Exception as e:
            return ToolResult(ok=False, text=f"Error executing {name}: {e}", source="tool_output")
