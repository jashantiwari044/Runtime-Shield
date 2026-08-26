"""Using the shield from a non-Python service, over HTTP.

    shield serve                       # in another terminal
    python examples/04_http_client.py
"""

import json
import urllib.request

SHIELD = "http://localhost:8000"
API_KEY = ""   # set if SHIELD_API_KEYS is configured


def post(path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        SHIELD + path,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json",
                 **({"x-api-key": API_KEY} if API_KEY else {})},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


for tool, arguments in [
    ("read_file", {"path": "README.md"}),
    ("exec", {"command": "rm -rf /"}),
    ("http_get", {"url": "http://169.254.169.254/"}),
]:
    decision = post("/v1/check", {"tool": tool, "arguments": arguments, "agent": "svc"})
    verdict = "BLOCKED" if not decision["allowed"] else "allowed"
    print(f"{verdict:8} {tool}  {decision.get('reason', '')}")

scan = post("/v1/scan", {"text": "token ghp_" + "a" * 36})
print(f"\nredacted: {scan['content']}")
