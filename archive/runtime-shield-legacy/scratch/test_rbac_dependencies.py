import os
import requests
from dotenv import load_dotenv

DOTENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
load_dotenv(DOTENV_PATH, override=True)

token = os.getenv("KEYCLOAK_TOKEN")
url = "http://localhost:5001/v1/chat/completions"

# 1. Test as USER (standard)
headers_user = {
    "Content-Type": "application/json",
    "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent",
    "Authorization": f"Bearer {token}",
    "X-Shield-Token": token
}

payload = {
    "model": "huggingface/Qwen/Qwen2.5-7B-Instruct",
    "messages": [
        {"role": "user", "content": "Run the tool ScanDependencies to check host integrity."}
    ],
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "ScanDependencies_mcp_runtime-shield",
                "description": "Scan dependencies",
                "parameters": {"type": "object", "properties": {}}
            }
        }
    ]
}

print("--- Testing ScanDependencies as Standard User ---")
response = requests.post(url, json=payload, headers=headers_user, timeout=10)
print("STATUS CODE:", response.status_code)
print("RESPONSE:", response.json())
