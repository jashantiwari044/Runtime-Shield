<h1 align="center">
  🛡️ Runtime Shield
</h1>

<p align="center">
  <b>Runtime security and dataflow tracking for AI Agents & Chatbots</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success.svg?style=flat-square" alt="Status Active">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Security-Dataflow%20Tracking-yellow?style=flat-square" alt="Security Dataflow">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License Apache 2.0">
</p>

<p align="center">
  Guardrails between your AI agents and the actions they take — catching data exfiltration and prompt injections that no regex or LLM judge can see.
</p>

---

## ⚡ Why Runtime Shield?

Most agent guardrails (like NeMo, LLM Guard, Guardrails AI) try to inspect **content** by asking *"does this text look like an attack?"* This is fundamentally flawed because natural language has infinite variations, and attackers can always rephrase. 

Runtime Shield takes a different approach by asking an answerable question:
> **Did bytes from an untrusted source end up in an outbound call, in a session that also touched private data?**

This is the **Lethal Trifecta**. Present in [98% of production agents](https://nhimg.org/articles/ai-agent-lethal-trifecta-exposes-a-governance-gap-in-access-control/), it's the primary way agents are exploited. Runtime Shield sees every tool call and stops the flow of tainted data instantly.

---

## 🚀 Quickstart

```bash
pip install runtime-shield
shield quickstart
```
*This instantly sets up your config, tests your policy, seeds demo traffic, and launches the real-time dashboard at `http://localhost:8000`.*

---

## 🤖 Using Runtime Shield with Chatbots & Agents

Runtime Shield is built to wrap around any LLM, Agent, or Chatbot framework. You can integrate it in three main ways:

### 1. The Zero-Code Drop-in Proxy (Recommended for Chatbots)
Point any OpenAI-compatible client (Chatbots, AutoGPT, UI frontends) directly at Runtime Shield. Every tool call the model proposes is intercepted and checked before it reaches your backend.

```bash
export SHIELD_UPSTREAM_BASE_URL=https://api.openai.com/v1
export SHIELD_UPSTREAM_API_KEY=sk-...
shield serve
```
Then, in your chatbot code, just change the base URL:
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1", # Points to Shield
    api_key="your-shield-key"
)
```

### 2. Framework Integrations
Runtime Shield has built-in lazy-loaded adapters for all major frameworks.

#### **OpenAI / Anthropic**
```python
from openai import OpenAI
from shield import Shield
from shield.integrations.openai_adapter import guard_client

client = guard_client(OpenAI(), Shield(), agent="support-bot")
# Blocked tool calls are automatically stripped and explained to the model!
```

#### **LangChain / LangGraph**
```python
from shield.integrations.langchain_adapter import guard_tools

tools = guard_tools(Shield(), [search_tool, shell_tool], agent="researcher")
```
*A blocked tool returns an error string directly to the model rather than crashing, allowing the agent to dynamically adapt.*

#### **Model Context Protocol (MCP)** (Claude Desktop, Cursor, Windsurf)
Put the shield between the client and any MCP server in your `mcp.json`:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "shield-mcp",
      "args": ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    }
  }
}
```

### 3. Native Python SDK (For custom loops like CrewAI, AutoGen)
```python
from shield import Shield
from shield.integrations import guard_functions

# Wrap all your custom tools with the shield
tools = guard_functions(Shield(), {"exec": run_shell, "read": read_file})
```

---

## 🛡️ The Guards

Guards run in order; the first block wins. Each one is independent.

| Guard | Stops |
|---|---|
| **Kill switch** | Everything, instantly. (`touch .shield-kill` — no restart required) |
| **Rate limit** | Runaway loops melting a downstream API. |
| **Policy** | Reads of `~/.ssh/`, `.env`, `*.pem`, `/etc/shadow`. Optional filesystem sandbox. |
| **Command** | `rm -rf /`, `curl … \| sh`, reverse shells, fork bombs. Inspects the *command text*, ignoring the tool name. |
| **Injection** | Instruction override, chat-template smuggling, system-prompt extraction. |
| **Egress** | SSRF to `169.254.169.254`, private ranges, `localhost`, obfuscated IPs. |
| **Trifecta** | **Dataflow tracking.** Private bytes leaving a session that read untrusted content (sees through base64/hex encoding). |
| **Secrets / PII** | Redacts AWS/GitHub/Stripe keys, emails, SSNs, Credit Cards on the way out. |

---

## 📊 Live Dashboard
Run `shield serve` and open [http://localhost:8000](http://localhost:8000).

Monitor the **Dataflow Sessions** panel. Each session shows three lights: **[P]** (Private data read), **[U]** (Untrusted content read), **[→]** (Outbound tool used). If all three light up, it's a lethal exfiltration attempt and the row turns red.

---

## 🛠️ Advanced Tools (That nobody else ships)

### `shield fuzz` (Find your own bypasses)
Attackers don't use canonical phrasing. The fuzzer takes every attack your policy blocks, generates mutations (string-splitting, homoglyphs, percent-encoding), and reports any that slip through.
```bash
shield fuzz
# Mutates blocked attacks and ensures 0 bypasses.
```

### `shield replay` (Time-travel testing)
Before deploying a new policy rule, re-decide **traffic you already served** to ensure you aren't breaking existing agent workflows.
```bash
shield replay --against candidate.yaml
# Warns you if the new policy would have blocked yesterday's legitimate traffic.
```

---

## ⚙️ Configuration (`shield.yaml`)

Run `shield init` to generate a starter config.

```yaml
mode: enforce            # use `monitor` to log everything without blocking
defaultAction: allow

filesystem:
  sandbox: ["./workspace"]
  deny: ["**/.ssh/**", "**/.env"]

agents:
  readonly-bot:
    allow: ["read_file", "search"]   
    rateLimit: "60/min"
```
*Tip: Start in `monitor` mode. Watch the dashboard for a few days, tune the noisy rules, then switch to `enforce`.*

---

## 🔒 Cryptographic Audit Trail
Every decision is a JSON line carrying the hash of the previous line. If an attacker tampers with the logs, the chain breaks.
```bash
shield audit verify
# ✓ Audit chain intact — 1,284 entries verified
```

---

## 🐳 Docker Deployment

```bash
SHIELD_API_KEYS=$(openssl rand -hex 32) docker compose up -d
```
Runs as a non-root user with a read-only filesystem. The verifiable audit log lives on a named volume so it survives restarts.

---

## 📝 License

Apache 2.0
