"""MCP proxy — put the shield between an MCP client and an MCP server.

Claude Desktop, Cursor, Windsurf and friends launch MCP servers over stdio.
This proxy sits in the middle: it launches the real server, relays JSON-RPC
both ways, and checks every `tools/call` before it reaches the server.

Point the client at the proxy instead of the server:

    {
      "mcpServers": {
        "filesystem": {
          "command": "shield-mcp",
          "args": ["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
        }
      }
    }

Blocked calls come back as a normal MCP error result, so the model sees the
refusal and can adapt instead of hanging.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, TextIO

from ..engine import Shield


class MCPProxy:
    """Bidirectional stdio relay with a policy check on `tools/call`."""

    def __init__(
        self,
        command: list[str],
        shield: Shield | None = None,
        agent: str = "mcp",
        scan_results: bool = True,
    ) -> None:
        if not command:
            raise ValueError("an upstream MCP server command is required")
        self.command = command
        self.shield = shield or Shield()
        self.agent = agent
        self.scan_results = scan_results
        self._pending: dict[Any, str] = {}   # request id -> tool name
        self._lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------

    def run(self) -> int:
        """Relay until the upstream server exits. Returns its exit code."""
        # The command comes from the operator's own MCP config, not from the
        # model -- launching it is the entire purpose of this proxy.
        process = subprocess.Popen(  # noqa: S603
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,          # upstream logs pass through untouched
            text=True,
            bufsize=1,
        )
        assert process.stdin and process.stdout

        upstream = threading.Thread(
            target=self._pump_downstream, args=(process.stdout, sys.stdout), daemon=True
        )
        upstream.start()

        try:
            self._pump_upstream(sys.stdin, process.stdin)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

        return process.returncode or 0

    # -- client -> server -------------------------------------------------

    def _pump_upstream(self, source: TextIO, sink: TextIO) -> None:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                _write(sink, line)
                continue

            if message.get("method") == "tools/call":
                params = message.get("params") or {}
                name = params.get("name", "")
                arguments = params.get("arguments") or {}

                decision = self.shield.check(name, arguments, agent=self.agent)
                if decision.blocked:
                    _write_json(sys.stdout, _error_result(message.get("id"), decision.reason))
                    continue

                with self._lock:
                    self._pending[message.get("id")] = name

            _write_json(sink, message)

    # -- server -> client -------------------------------------------------

    def _pump_downstream(self, source: TextIO, sink: TextIO) -> None:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                _write(sink, line)
                continue

            if self.scan_results and "result" in message:
                with self._lock:
                    tool = self._pending.pop(message.get("id"), "")
                if tool:
                    message = self._scan_result(message, tool)

            _write_json(sink, message)

    def _scan_result(self, message: dict[str, Any], tool: str) -> dict[str, Any]:
        """Redact secrets and PII in the text blocks of a tool result."""
        result = message.get("result")
        if not isinstance(result, dict):
            return message
        for block in result.get("content") or []:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                block["text"] = self.shield.scan(
                    block["text"], tool=tool, agent=self.agent
                ).content
        return message


def _error_result(request_id: Any, reason: str) -> dict[str, Any]:
    """An MCP tool result the model can read, rather than a protocol error."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": f"Blocked by Runtime Shield: {reason}"}],
            "isError": True,
        },
    }


def _write(sink: TextIO, line: str) -> None:
    sink.write(line + "\n")
    sink.flush()


def _write_json(sink: TextIO, message: dict[str, Any]) -> None:
    _write(sink, json.dumps(message, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `shield-mcp` console script."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="shield-mcp",
        description="Run an MCP server behind Runtime Shield.",
        epilog="example: shield-mcp -- npx -y @modelcontextprotocol/server-filesystem /data",
    )
    parser.add_argument("-c", "--config", help="path to shield.yaml")
    parser.add_argument("--agent", default="mcp", help="agent identity for policy lookups")
    parser.add_argument("--no-scan", action="store_true", help="do not redact tool results")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="-- followed by the upstream server command")

    args = parser.parse_args(argv)
    command = [a for a in args.command if a != "--"]
    if not command:
        parser.error("an upstream command is required, after `--`")

    proxy = MCPProxy(
        command=command,
        shield=Shield(config_path=args.config),
        agent=args.agent,
        scan_results=not args.no_scan,
    )
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
