#!/bin/bash
# Start sse_bridge.cjs in the background
node sse_bridge.cjs &

# Start bridge.py in the foreground (acts as main process)
exec python bridge.py
