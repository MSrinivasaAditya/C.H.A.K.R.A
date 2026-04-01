"""
Test 7 — Ollama mode (no Anthropic API calls)

Protocol:
  1. Patch LLM_BACKEND=ollama in the process env (does NOT restart server).
     Alternatively: test against a server already started with LLM_BACKEND=ollama.
  2. POST /scan for the demo app.
  3. Confirm findings are returned (Ollama generated them).
  4. Confirm chakra.log contains NO line with "anthropic" in it after the scan.

Environment requirements:
  - Ollama must be running with codellama:13b pulled.
  - Set OLLAMA_RUNNING=1 to enable this test.
  - Override model: CHAKRA_OLLAMA_MODEL=codellama:13b

This test only validates the LOG — it does NOT patch the live server's env.
Run the server with LLM_BACKEND=ollama yourself, then run this test.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, scan_demo, log_tail,
    LOG_FILE,
)

OLLAMA_RUNNING = os.environ.get("OLLAMA_RUNNING", "").strip() not in ("", "0", "false", "no")


def run() -> bool:
    section("Test 7 — Ollama mode (no Anthropic API calls)")

    if not OLLAMA_RUNNING:
        warn("Skipping: OLLAMA_RUNNING env-var not set.")
        warn("To run this test:")
        warn("  1. Install Ollama and run: ollama pull codellama:13b")
        warn("  2. Set LLM_BACKEND=ollama in .env and restart the CHAKRA server")
        warn("  3. Re-run with:  OLLAMA_RUNNING=1 python tests/test_7_ollama.py")
        return True  # Skip, not fail

    require_server()

    # ── Note the log size before the scan ──────────────────────────────────────
    log_size_before = LOG_FILE.stat().st_size if LOG_FILE.exists() else 0

    info("Scanning demo app via server configured with LLM_BACKEND=ollama…")
    code, resp = scan_demo()

    if code != 200:
        fail(f"Scan returned HTTP {code}: {resp}")
        return False

    findings = resp.get("findings", [])
    ok(f"HTTP 200 — {len(findings)} finding(s) returned")

    passed = True

    if not findings:
        fail("No findings returned — Ollama may not have responded correctly")
        passed = False
    else:
        # Spot-check that findings have the expected LLM fields
        for f in findings[:3]:
            for field in ("explanation", "attack_scenario", "fix_diff", "future_guidance"):
                if f.get(field):
                    ok(f"Finding {f.get('cwe')} has '{field}' ✓")
                    break
            else:
                warn(f"Finding {f.get('cwe')} missing LLM fields (Ollama may have timed out)")

    # ── Inspect log for Anthropic API calls ───────────────────────────────────
    time.sleep(1)  # give log a moment to flush
    if LOG_FILE.exists():
        new_bytes = LOG_FILE.read_bytes()[log_size_before:]
        new_log = new_bytes.decode(errors="replace").lower()
    else:
        new_log = ""

    if "anthropic" in new_log:
        fail("chakra.log shows 'anthropic' keyword after Ollama scan — Anthropic API was called")
        passed = False
    else:
        ok("chakra.log contains no 'anthropic' keyword after scan ✓")

    if "ollama" in new_log or "codellama" in new_log:
        ok("chakra.log mentions ollama/codellama (confirming Ollama backend was used) ✓")
    else:
        warn("No ollama/codellama keyword in new log lines — inconclusive but non-fatal")

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
