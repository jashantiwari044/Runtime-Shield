<h1 align="center">
  🧪 AI Security Labs & Runtime Shield
</h1>

<p align="center">
  <b>A comprehensive research and development repository for AI Agent Security, Model Context Protocol (MCP) vulnerabilities, and dataflow tracking.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success.svg?style=flat-square" alt="Status Active">
  <img src="https://img.shields.io/badge/Security-Dataflow%20Tracking-yellow?style=flat-square" alt="Security Dataflow">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License Apache 2.0">
</p>

Welcome to the **AI Security Labs**! This repository serves as the central hub for our open-source agentic security tools, vulnerable testing environments, and red-team research. 

---

## 🌟 The Flagship: `runtime-shield` (Stable)

**[`/runtime-shield`](./runtime-shield/) is the core, stable product of this repository.**

Most agent guardrails rely on flawed content-inspection (e.g., trying to detect if a prompt "looks like" an attack). `runtime-shield` takes a deterministic approach to AI security by analyzing **dataflow**. 

It prevents the **Lethal Trifecta**: *When an agent reads untrusted content, interacts with private data, and attempts to exfiltrate it via an outbound tool call.* 

**Key Features:**
- **Zero-Code Drop-in Proxy**: Works instantly with OpenAI, Anthropic, or any compatible client without changing your chatbot's core logic.
- **MCP Native**: Plugs directly between clients and Model Context Protocol servers.
- **Cryptographic Audit Trail**: Every decision is hashed and verifiable.
- **Live Dashboard**: Real-time traffic and exfiltration attempt monitoring.

👉 **[Read the full Runtime Shield documentation here](./runtime-shield/README.md)**

---

## 🧪 Experimental Labs & Legacy Environments

While `runtime-shield` is our production-ready tool, this repository also houses the vulnerable environments, sandbox chats, and older iterations we used to develop it. These are located in the following directories:

### 1. `MCP-Challenges` (Red-Team Labs)
The **[`/MCP-Challenges`](./MCP-Challenges/)** directory contains a suite of intentionally vulnerable Model Context Protocol (MCP) servers and practical red-team labs. 
* **How it works**: It sets up various challenge environments (like command injection via shell metacharacters or indirect prompt injections hidden inside mock database responses).
* **Purpose**: We use this as a live testing ground. It proves that `runtime-shield` can successfully intercept and block complex, multi-stage attacks in real-time. 

### 2. `librechat` (Testing Interface)
The **[`/librechat`](./librechat/)** directory contains an integration/fork of LibreChat. 
* **How it works**: It provides a full-featured conversational UI. 
* **Purpose**: We use this to test agent interactions with human users in a realistic environment, routing the chatbot's upstream API calls through our `runtime-shield` proxy to ensure seamless user experience during blocks.

### 3. `archive` (Legacy Iterations)
The **[`/archive`](./archive/)** folder contains older, deprecated versions of our security tools. 
* **How it works**: These are early prototypes and regex-based guardrails that we built before pivoting to full dataflow tracking.
* **Purpose**: Kept for historical context, research reference, and demonstrating why pattern-matching alone fails against modern prompt injection.

---

## 🚀 Getting Started

If you are looking to secure your AI agents today, you only need the stable `runtime-shield`.

```bash
cd runtime-shield
pip install -e ".[dev]"
shield quickstart
```

If you are a security researcher looking to test exploits, head over to the `MCP-Challenges` directory and follow the lab setup instructions.

## 🤝 Contributing
We welcome contributions to both our `runtime-shield` engine and new vulnerable scenarios for the `MCP-Challenges` labs! Please read the `CONTRIBUTING.md` inside the `runtime-shield` folder for our testing rules and fuzzer requirements.

## 📝 License
This project is licensed under Apache 2.0.
