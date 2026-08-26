#!/bin/bash
# Usage: mcp-connect.sh <host> <port>
# Connects via ncat, strips the PoW banner line before forwarding to stdout
HOST=$1
PORT=$2
ncat "$HOST" "$PORT" | (read -r _powline; cat)
