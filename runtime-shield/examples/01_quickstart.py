"""The 30-second version: check before acting, scan on the way back.

    python examples/01_quickstart.py
"""

from shield import Shield

shield = Shield()

print("--- checking tool calls ---")
for tool, arguments in [
    ("read_file", {"path": "README.md"}),
    ("exec", {"command": "npm test"}),
    ("exec", {"command": "rm -rf /"}),
    ("read_file", {"path": "~/.ssh/id_rsa"}),
    ("http_get", {"url": "http://169.254.169.254/latest/meta-data/"}),
]:
    decision = shield.check(tool, arguments, agent="demo-agent")
    verdict = "BLOCKED" if decision.blocked else "allowed"
    print(f"{verdict:8} {tool}({arguments})")
    if decision.blocked:
        print(f"         └─ {decision.stage.value}: {decision.reason}")

print("\n--- scanning output ---")
dirty = "Deploy key AKIAIOSFODNN7EXAMPLE, contact ops@example.com, card 4111 1111 1111 1111"
result = shield.scan(dirty)
print(f"before: {dirty}")
print(f"after:  {result.content}")

print(f"\n--- metrics ---\n{shield.metrics()}")
