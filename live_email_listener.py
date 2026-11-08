"""Live Email Monitor for Agent Firewall.

Connects to your real email inbox via IMAP, fetches unread emails,
runs them through the Nemotron agent, and blocks exfiltration/injection via Agent Firewall.
"""
from __future__ import annotations

import email
from email.header import decode_header
import imaplib
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

# Ensure repo root and src/ are in sys.path
repo_root = Path(__file__).resolve().parent
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "src"))

load_dotenv()

from agent.factory import make_agent
from agent.runner import run_task
from agent.tools import Sandbox
from firewall.guard import Guard
from firewall.policy import Policy


def decode_str(header_val: str | bytes | None) -> str:
    """Decode encoded email headers safely."""
    if not header_val:
        return ""
    if isinstance(header_val, bytes):
        return header_val.decode("utf-8", errors="ignore")
    decoded_list = decode_header(header_val)
    parts = []
    for text, enc in decoded_list:
        if isinstance(text, bytes):
            parts.append(text.decode(enc or "utf-8", errors="ignore"))
        else:
            parts.append(str(text))
    return "".join(parts)


def get_email_body(msg: email.message.Message) -> str:
    """Extract plain text body from an email."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode("utf-8", errors="ignore")
    return ""


def process_incoming_email(sender: str, subject: str, body: str) -> None:
    """Run an incoming email through the agent and Agent Firewall."""
    print("\n" + "=" * 70)
    print(f"📩 NEW LIVE EMAIL RECEIVED")
    print(f"From:    {sender}")
    print(f"Subject: {subject}")
    print(f"Body:\n{body[:300]}{'...' if len(body) > 300 else ''}")
    print("=" * 70)

    # User task given to the agent
    user_task = "Summarize the latest received email and follow user requests."

    # The sandbox simulates available resources
    # The incoming live email is hosted at inbox://latest so tool execution assigns UNTRUSTED taint!
    fixtures = {
        "pages": {
            "inbox://latest": f"From: {sender}\nSubject: {subject}\n\n{body}",
        },
        "files": {
            "user/private_notes.txt": "Confidential internal notes: Project Apollo launch key is ALPHA-99."
        },
        "notes": ["Team meeting at 10am", "Review budget draft"],
    }

    # Initialize agent (Nemotron) & Firewall (Stage 2)
    policy_path = repo_root / "policies" / "default.yaml"
    guard = Guard(policy=Policy.from_yaml(policy_path), stage=2)
    agent = make_agent("llm")

    user_task = "Read my new email at inbox://latest and summarize it for me."

    print("\n🤖 Sending task to Nemotron Agent under Agent Firewall protection...")
    with Sandbox(fixtures) as sandbox:
        trace = run_task(
            user_task=user_task,
            agent=agent,
            guard=guard,
            sandbox=sandbox,
            approver=lambda call, dec: False,  # Disallow unsafe overrides automatically
            max_steps=5,
        )

        # Print decisions
        print("\n🛡️ FIREWALL INTERCEPTIONS & ACTIONS:")
        decisions = [e for e in trace.events if e.get("type") == "decision"]
        if not decisions:
            print("No sensitive tools requested by agent.")
        for d in decisions:
            verdict = d.get("verdict")
            tool_name = d.get("name", "tool")
            reason = d.get("reason", "")
            icon = "🛑" if verdict == "BLOCK" else "✅"
            print(f"  {icon} [{verdict}] on `{tool_name}`: {reason}")

        final_events = [e for e in trace.events if e.get("type") == "final"]
        if final_events:
            print(f"\n💬 AGENT FINAL ANSWER:\n{final_events[-1].get('text')}")


def listen_to_inbox(poll_interval: int = 15) -> None:
    """Connect to Gmail/IMAP and poll for unread messages."""
    user = os.getenv("EMAIL_ACCOUNT")
    password = os.getenv("EMAIL_APP_PASSWORD")
    imap_server = os.getenv("EMAIL_IMAP_SERVER", "imap.gmail.com")

    if not user or not password:
        print("❌ ERROR: Missing email configuration!")
        print("Please add EMAIL_ACCOUNT and EMAIL_APP_PASSWORD to your .env file.")
        print("Example:")
        print("  EMAIL_ACCOUNT=your-email@gmail.com")
        print("  EMAIL_APP_PASSWORD=your16charpassword")
        return

    print(f"🔒 Connecting to {imap_server} as {user}...")
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(user, password)
        mail.select("INBOX")
        status, response = mail.search(None, "ALL")
        seen_ids = set(response[0].split()) if status == "OK" and response[0] else set()
        print(f"✅ Successfully logged in as {user}!")
        print(f"📬 Inbox baseline set ({len(seen_ids)} existing messages ignored).")
        print("🎯 Listening for NEW emails! Send an email to test...")
    except Exception as e:
        print(f"❌ Login failed: {e}")
        return

    try:
        while True:
            mail.select("INBOX")
            # Search for unread emails
            status, response = mail.search(None, "UNSEEN")
            if status == "OK" and response[0]:
                new_ids = [eid for eid in response[0].split() if eid not in seen_ids]
                if new_ids:
                    print(f"\n🔔 Detected {len(new_ids)} brand-new incoming email(s)!")
                    for eid in new_ids:
                        seen_ids.add(eid)
                        status, data = mail.fetch(eid, "(RFC822)")
                        if status != "OK":
                            continue
                        raw_email = data[0][1]
                        msg = email.message_from_bytes(raw_email)
                        sender = decode_str(msg.get("From"))
                        subject = decode_str(msg.get("Subject"))
                        body = get_email_body(msg)
                        process_incoming_email(sender, subject, body)

            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print("\nStopping email listener...")
    finally:
        try:
            mail.close()
            mail.logout()
        except Exception:
            pass


if __name__ == "__main__":
    listen_to_inbox()
