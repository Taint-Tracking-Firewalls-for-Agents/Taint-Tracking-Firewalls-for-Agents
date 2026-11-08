"""Nemotron 3.5 Super-VL Reasoning Example with OpenRouter API.

Demonstrates multi-turn conversation preserving reasoning_details across turns.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import requests
from dotenv import load_dotenv

# Load credentials from .env
load_dotenv()

OPENROUTER_URL = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/") + "/chat/completions"
API_KEY = os.getenv("LLM_API_KEY", "")
MODEL = os.getenv("LLM_MODEL", "nvidia/nemotron-3.5-super-vl:free")

if API_KEY.startswith("<") and API_KEY.endswith(">"):
    API_KEY = API_KEY[1:-1]


def run_nemotron_reasoning_example() -> dict[str, Any]:
    """Execute the multi-turn reasoning workflow preserving reasoning_details."""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    # First API call with reasoning
    print(f"Calling OpenRouter ({MODEL}) - Turn 1...")
    response = requests.post(
        url=OPENROUTER_URL,
        headers=headers,
        data=json.dumps({
            "model": MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": "How many r's are in the word 'strawberry'?",
                }
            ],
            "reasoning": {"enabled": True},
        }),
        timeout=30,
    )
    response.raise_for_status()

    # Extract the assistant message with reasoning_details
    data = response.json()
    assistant_msg = data["choices"][0]["message"]
    print("Turn 1 response:", assistant_msg.get("content"))
    print("Reasoning details captured:", bool(assistant_msg.get("reasoning_details")))

    # Preserve the assistant message with reasoning_details
    messages = [
        {"role": "user", "content": "How many r's are in the word 'strawberry'?"},
        {
            "role": "assistant",
            "content": assistant_msg.get("content"),
            "reasoning_details": assistant_msg.get("reasoning_details"),  # Pass back unmodified
        },
        {"role": "user", "content": "Are you sure? Think carefully."},
    ]

    # Second API call - model continues reasoning from where it left off
    print(f"Calling OpenRouter ({MODEL}) - Turn 2 (preserving reasoning_details)...")
    response2 = requests.post(
        url=OPENROUTER_URL,
        headers=headers,
        data=json.dumps({
            "model": MODEL,
            "messages": messages,  # Includes preserved reasoning_details
            "reasoning": {"enabled": True},
        }),
        timeout=30,
    )
    response2.raise_for_status()

    data2 = response2.json()
    assistant_msg2 = data2["choices"][0]["message"]
    print("Turn 2 response:", assistant_msg2.get("content"))

    return {
        "turn_1": assistant_msg,
        "turn_2": assistant_msg2,
    }


if __name__ == "__main__":
    result = run_nemotron_reasoning_example()
    print("\nComplete Multi-turn Result:")
    print(json.dumps(result, indent=2))
