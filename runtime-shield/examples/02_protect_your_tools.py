"""Guard a whole tool registry with one call — works with any agent loop.

    python examples/02_protect_your_tools.py
"""

import subprocess

from shield import Shield, ShieldError

shield = Shield()


def read_file(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def run_shell(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def fetch(url: str) -> str:
    return f"(pretend we fetched {url})"


# One line: every tool is now checked on the way in and scanned on the way out.
tools = shield.wrap_tools({"read_file": read_file, "exec": run_shell, "fetch": fetch},
                          agent="demo-agent")

for name, kwargs in [
    ("exec", {"command": "echo hello"}),
    ("exec", {"command": "rm -rf /"}),
    ("fetch", {"url": "https://example.com"}),
    ("fetch", {"url": "http://169.254.169.254/"}),
]:
    try:
        print(f"OK      {name}({kwargs}) -> {tools[name](**kwargs)!r}")
    except ShieldError as exc:
        print(f"BLOCKED {name}({kwargs})\n        └─ {exc.decision.reason}")
