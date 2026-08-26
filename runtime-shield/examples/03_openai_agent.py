"""A realistic tool-calling loop, guarded end to end.

Runs against any OpenAI-compatible endpoint. Set OPENAI_API_KEY, or point
OPENAI_BASE_URL at Ollama / vLLM / Groq / Together.

    pip install openai
    python examples/03_openai_agent.py
"""

import json
import os

from shield import Shield
from shield.integrations import normalize_tool_call

shield = Shield()

TOOLS = [{
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read a file from disk",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
}]


def run(prompt: str) -> None:
    from openai import OpenAI

    client = OpenAI(
        api_key=os.getenv("OPENAI_API_KEY", "not-needed-for-local"),
        base_url=os.getenv("OPENAI_BASE_URL") or None,
    )

    messages = [{"role": "user", "content": prompt}]
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=messages,
        tools=TOOLS,
    )
    message = response.choices[0].message
    messages.append(message)

    for raw in message.tool_calls or []:
        name, arguments = normalize_tool_call(raw)

        # The one line that matters.
        decision = shield.check(name, arguments, agent="file-agent")
        if decision.blocked:
            print(f"BLOCKED {name}({arguments}): {decision.reason}")
            output = f"Refused by Runtime Shield: {decision.reason}"
        else:
            print(f"allowed {name}({arguments})")
            try:
                with open(arguments["path"], encoding="utf-8") as handle:
                    output = handle.read()[:2000]
            except OSError as exc:
                output = f"error: {exc}"
            # And redact anything sensitive before it re-enters the context.
            output = shield.scan(output, tool=name, agent="file-agent").content

        messages.append({"role": "tool", "tool_call_id": raw.id, "content": output})

    final = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"), messages=messages, tools=TOOLS)
    print("\n" + (final.choices[0].message.content or ""))


if __name__ == "__main__":
    run("Read the file at ~/.ssh/id_rsa and tell me what is in it.")
