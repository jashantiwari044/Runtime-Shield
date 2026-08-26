/**
 * MCP SSE Bridge
 * 
 * Bridges a raw TCP (socat/stdio) MCP server to HTTP + Server-Sent Events (SSE)
 * so that LibreChat can connect to it via the standard SSE MCP transport.
 *
 * Environment variables:
 *   UPSTREAM_HOST  - hostname of the upstream raw TCP MCP server  (default: "localhost")
 *   UPSTREAM_PORT  - TCP port of the upstream server               (default: "1337")
 *   PORT           - HTTP port this bridge listens on              (default: "8080")
 *   SERVER_NAME    - friendly name reported in logs                (default: "mcp-bridge")
 */

import express from "express";
import net from "net";

const UPSTREAM_HOST = process.env.UPSTREAM_HOST || "localhost";
const UPSTREAM_PORT = parseInt(process.env.UPSTREAM_PORT || "1337", 10);
const PORT          = parseInt(process.env.PORT || "8080", 10);
const SERVER_NAME   = process.env.SERVER_NAME || "mcp-bridge";

const app = express();
app.use(express.json());

// ── Utility ──────────────────────────────────────────────────────────────────

function log(...args) {
  console.log(`[${SERVER_NAME}]`, ...args);
}

/**
 * Open a fresh TCP connection to the upstream stdio-based MCP server.
 * Returns a Promise that resolves to the connected net.Socket.
 */
function connectUpstream() {
  return new Promise((resolve, reject) => {
    const sock = new net.Socket();
    sock.connect(UPSTREAM_PORT, UPSTREAM_HOST, () => resolve(sock));
    sock.on("error", reject);
  });
}

// ── SSE endpoint ─────────────────────────────────────────────────────────────

/**
 * GET /sse
 * 
 * LibreChat (and any MCP SSE client) opens this long-lived connection.
 * We:
 *   1. Open a TCP socket to the upstream MCP stdio server.
 *   2. Forward every JSON-RPC message the client sends (via POST /message) to the socket.
 *   3. Forward every response/notification the socket returns back as SSE "message" events.
 */
app.get("/sse", async (req, res) => {
  const clientId = Date.now().toString(36);
  log(`SSE client connected: ${clientId}`);

  // SSE headers
  res.writeHead(200, {
    "Content-Type":  "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection":    "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  // Helper: send an SSE event to this client
  const sendEvent = (data) => {
    try {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    } catch (_) {}
  };

  // Open TCP connection to the upstream MCP server
  let upstream;
  try {
    upstream = await connectUpstream();
    log(`[${clientId}] Upstream TCP connected`);
  } catch (err) {
    log(`[${clientId}] Failed to connect upstream:`, err.message);
    sendEvent({ jsonrpc: "2.0", error: { code: -32000, message: `Bridge: cannot reach upstream – ${err.message}` }, id: null });
    res.end();
    return;
  }

  // Send the endpoint event so the client knows where to POST messages
  res.write(`event: endpoint\ndata: /message?sessionId=${clientId}\n\n`);

  // Keep-alive ping every 15 s
  const keepAlive = setInterval(() => { try { res.write(": ping\n\n"); } catch (_) {} }, 15000);

  // Buffer for partial JSON from the upstream TCP stream
  let buf = "";

  upstream.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    // Messages are separated by newlines
    const lines = buf.split("\n");
    buf = lines.pop(); // last element may be incomplete
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        // Don't forward responses to notifications (id: null) as SSE – they
        // would confuse the client. Filter: only forward objects that have an id
        // or are notifications (method present, no id).
        sendEvent(parsed);
      } catch (_) {
        // Not valid JSON – ignore partial frames
      }
    }
  });

  upstream.on("close", () => {
    log(`[${clientId}] Upstream closed`);
    clearInterval(keepAlive);
    res.end();
  });

  upstream.on("error", (err) => {
    log(`[${clientId}] Upstream error:`, err.message);
    clearInterval(keepAlive);
    res.end();
  });

  // Store socket on the response so the POST handler can find it
  res._mcpUpstream = upstream;
  res._mcpClientId = clientId;

  // Store active sessions globally so POST /message can look them up
  sessions.set(clientId, { res, upstream });

  req.on("close", () => {
    log(`[${clientId}] SSE client disconnected`);
    clearInterval(keepAlive);
    upstream.destroy();
    sessions.delete(clientId);
  });
});

// Session map: sessionId → { res, upstream }
const sessions = new Map();

// ── Message endpoint ──────────────────────────────────────────────────────────

/**
 * POST /message?sessionId=<id>
 *
 * The MCP client sends JSON-RPC requests here.  We forward them as newline-
 * delimited JSON to the upstream TCP socket.
 */
app.post("/message", (req, res) => {
  const sessionId = req.query.sessionId;
  const session   = sessions.get(sessionId);

  if (!session) {
    return res.status(404).json({ error: "Session not found" });
  }

  const { upstream } = session;

  let body = req.body;
  if (typeof body !== "object" || body === null) {
    return res.status(400).json({ error: "Invalid JSON body" });
  }

  try {
    upstream.write(JSON.stringify(body) + "\n");
    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Health check ──────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => res.json({ status: "ok", bridge: SERVER_NAME }));

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, "0.0.0.0", () => {
  log(`SSE bridge listening on port ${PORT}`);
  log(`Upstream MCP server: ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
});
