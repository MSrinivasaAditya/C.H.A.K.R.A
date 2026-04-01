#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Virtualenv ────────────────────────────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "[CHAKRA] Creating Python virtual environment..."
    python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate

# ── Dependencies ──────────────────────────────────────────────────────────────
echo "[CHAKRA] Installing dependencies..."
pip install -q -r requirements.txt

# ── Environment file ──────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    echo "[CHAKRA] No .env found — copying .env.example to .env"
    cp .env.example .env
    echo "[CHAKRA] Edit .env to set your ANTHROPIC_API_KEY before using."
fi

# ── Start server ──────────────────────────────────────────────────────────────
echo "[CHAKRA] Starting server... (logs → chakra.log)"
nohup python -m backend.chakra_server >> chakra.log 2>&1 &
SERVER_PID=$!

sleep 1
if kill -0 "$SERVER_PID" 2>/dev/null; then
    PORT="${PORT:-7777}"
    echo ""
    echo "  ✅  C.H.A.K.R.A is running  →  http://127.0.0.1:${PORT}"
    echo "      Dashboard               →  http://127.0.0.1:${PORT}/dashboard"
    echo "      PID: ${SERVER_PID}  |  Logs: ${SCRIPT_DIR}/chakra.log"
    echo ""
else
    echo "  ❌  Server failed to start. Check chakra.log for details."
    exit 1
fi
