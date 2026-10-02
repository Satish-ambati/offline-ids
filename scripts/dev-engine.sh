#!/usr/bin/env bash
# Run the engine alone (any OS) for API/UI development: no token, loopback only.
cd "$(dirname "$0")/../security-engine" && python main.py --port 8765
