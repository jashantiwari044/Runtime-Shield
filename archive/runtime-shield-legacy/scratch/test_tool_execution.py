import os
import requests
from dotenv import load_dotenv

DOTENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
load_dotenv(DOTENV_PATH, override=True)

token = os.getenv("KEYCLOAK_TOKEN")
url = "http://localhost:5001/v1/tool/execute"

headers = {
    "Content-Type": "application/json",
    "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent",
    "Authorization": f"Bearer {token}",
    "X-Shield-Token": token
}

payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "ScanDependencies",
        "arguments": {
            "role": "admin"
        }
    }
}

print("--- Calling ScanDependencies Tool Execute as Admin ---")
response = requests.post(url, json=payload, headers=headers, timeout=10)
print("STATUS CODE:", response.status_code)
print("RESPONSE:", response.text)
