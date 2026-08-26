import sys

logs = open("scratch/gateway_logs.txt").read()

print("--- Completions Proxy requests: ---")
for line in logs.split("\n"):
    if "Received request" in line or "Proxying" in line or "Outbound Call" in line or "body" in line or "LLM Request" in line or "Upstream LLM Response" in line:
        print(line[:120])
