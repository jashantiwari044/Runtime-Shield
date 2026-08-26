import os
import requests
from dotenv import load_dotenv

# Load env variables from the project's env file
DOTENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
load_dotenv(DOTENV_PATH, override=True)

token = os.getenv("KEYCLOAK_TOKEN")
print("Using Token:", token[:20] + "...")

url = "http://localhost:5001/v1/chat/completions"
headers = {
    "Content-Type": "application/json",
    "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent",
    "Authorization": f"Bearer {token}"
}

payload = {
    "model": "huggingface/Qwen/Qwen2.5-7B-Instruct",
    "messages": [
        {"role": "user", "content": "Please read the file secure-experiment-zone/test_sandbox.txt and tell me what is written in it."}
    ],
    "tools": [
        {
            "type": "function",
            "function": {
                "name": "read_file_mcp_runtime-shield",
                "description": "Read the content of a file at the specified path.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "The path to the file to read"
                        }
                    },
                    "required": ["path"]
                }
            }
        }
    ]
}

response = requests.post(url, json=payload, headers=headers, timeout=30)
print("STATUS CODE:", response.status_code)
print("RESPONSE:")
print(response.json())
