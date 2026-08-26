# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:
open a [GitHub security advisory](https://github.com/YOUR-ORG/runtime-shield/security/advisories/new).
We aim to acknowledge within 72 hours.

## Threat model — what this does and does not do

Runtime Shield is a **policy enforcement point** between an agent and its
actions. Being clear about the boundary matters more than a long feature list.

**It defends against:**

- An agent taking a destructive or unauthorised action, whether the cause is a
  prompt injection, a model mistake, or a bug in the agent loop.
- **Exfiltration of private data after exposure to untrusted content** — the
  lethal trifecta — caught by dataflow tracking rather than by pattern matching,
  so rephrasing the injection does not evade it.
- Credentials and PII leaving in tool output and entering the model's context,
  the transcript, or your logs.
- SSRF from agent-controlled URLs into your internal network or cloud metadata.
- Silent tampering with the record of what an agent did.

**It does not defend against:**

- **A compromised host.** If an attacker already runs code as your process, they
  can bypass an in-process guard. Run agents in a container or VM; the shield is
  one layer, not the only one.
- **Direct calls that skip the shield.** It only sees calls you route through
  it. Wire it at the tool-dispatch boundary, not next to it.
- **A malicious model provider.** The shield inspects text; it does not attest
  to the model's integrity.
- **Perfect prompt-injection detection.** No pattern set catches every phrasing.
  Injection detection is defence in depth; permissions, egress control, the
  command guard and the trifecta guard are the load-bearing parts.
- **Exfiltration through a channel the shield never sees.** Dataflow tracking
  knows only about tool calls routed through `check()` and content passed to
  `scan()`/`observe()`. A tool that reads and sends in one un-instrumented step
  is invisible to it.
- **Semantic laundering.** A marker-based check sees copied bytes. An agent that
  *summarises* a secret in its own words, or encrypts it with a key the shield
  never saw, defeats marker matching — the posture warning still fires, which is
  why `trifecta_action` exists and why it is worth raising to `block` on agents
  that handle real secrets.

## Deployment guidance

1. **Start in `monitor` mode.** Confirm the policy fits your traffic before
   enforcing, so nobody is tempted to switch the shield off entirely.
2. **Set `SHIELD_API_KEYS` before binding anything but `127.0.0.1`.** With no
   keys set the API is open. The server warns at startup if it binds a
   non-loopback address without keys.
3. **Put the audit log on durable storage.** Losing it loses the evidence.
   Enable `audit.sign` where non-repudiation matters.
4. **Keep the kill-switch file on a volume an operator can reach** without
   needing the API, so a runaway agent can be stopped when the API cannot be.
5. **Pass a stable `session` id per unit of agent work.** Dataflow tracking is
   scoped to a session; without one, every call collapses into a per-agent
   bucket and long-lived agents accumulate false trifectas.
6. **Run `shield fuzz` and `shield replay` in CI**, not just `shield test`. The
   first proves your policy is not evadable by rephrasing, the second proves a
   policy edit does not un-block traffic you currently stop.
5. **Give the shield process fewer privileges than the agent it guards**, so a
   compromised agent cannot rewrite the policy that constrains it.

## Handling of sensitive data

Tool arguments are **hashed, never written** to the audit log — the log records
that a call happened and how it was decided, not its contents. Setting
`audit.capture_arguments: true` (needed for full-fidelity `shield replay`)
reverses that trade: the log then holds real arguments and must be protected
accordingly. Dataflow markers are held in memory only, never persisted, expire
with their session, and are masked (`Xq7L…Bc4`) wherever they appear in a
finding. Detected secrets
and PII are replaced with typed placeholders before findings are recorded.
