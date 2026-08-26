const http = require('http');
const { spawn } = require('child_process');
const crypto = require('crypto');
const url = require('url');

const PORT = 5002;
const sessions = new Map();

const server = http.createServer((req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Shield-Token, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);

  if (req.method === 'GET' && parsedUrl.pathname === '/sse') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });

    const sessionId = crypto.randomUUID();
    console.log(`[SSE Bridge] New connection: ${sessionId}`);

    // Spawn bridge.py in stdio mode with STDIO ONLY flag to prevent port conflict
    const mcpProcess = spawn('python', ['bridge.py'], {
      env: { 
        ...process.env, 
        SHIELD_STDIO_ONLY: 'true',
        RUNTIME_ROLE: 'user' 
      }
    });

    sessions.set(sessionId, { process: mcpProcess, res });

    // Send initial endpoint event containing redirect URL for client POST messages
    const clientUrl = `http://gateway:5002/message?session_id=${sessionId}`;
    res.write(`event: endpoint\ndata: ${clientUrl}\n\n`);

    mcpProcess.stdout.on('data', (data) => {
      const chunk = data.toString();
      const lines = chunk.split('\n');
      for (const line of lines) {
        if (line.trim()) {
          res.write(`event: message\ndata: ${line.trim()}\n\n`);
        }
      }
    });

    mcpProcess.stderr.on('data', (data) => {
      console.error(`[bridge.py stdio stderr]: ${data.toString().trim()}`);
    });

    req.on('close', () => {
      console.log(`[SSE Bridge] Connection closed: ${sessionId}`);
      mcpProcess.kill();
      sessions.delete(sessionId);
    });

  } else if (req.method === 'POST' && parsedUrl.pathname === '/message') {
    const sessionId = parsedUrl.query.session_id;
    const session = sessions.get(sessionId);
    if (!session) {
      res.writeHead(404);
      res.end('Session not found');
      return;
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      session.process.stdin.write(body + '\n');
      res.writeHead(202);
      res.end('Accepted');
    });

  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[SSE Bridge] Relaying bridge.py stdio on port ${PORT}`);
});
