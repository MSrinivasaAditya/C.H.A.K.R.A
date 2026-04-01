"""
Test 5 — Authentication enforcement

Protocol:
  1. Server must be running WITH AUTH_TOKEN set to "testtoken123".
     (Set CHAKRA_AUTH_TOKEN_OVERRIDE=testtoken123 to skip patching .env.)
  2. Send scan WITHOUT a token → expect HTTP 401.
  3. Send scan WITH wrong token → expect HTTP 401.
  4. Send scan WITH correct token → expect HTTP 200.
  5. GET /dashboard WITHOUT token → expect HTTP 200 (dashboard is token-exempt).

This test does NOT restart the server.  It expects you to have already
configured AUTH_TOKEN=testtoken123 in .env and restarted the server.

Run with:
  AUTH_TOKEN_SET=1 python tests/test_5_auth.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, post, get, demo_source,
    ORG_ID, DEV_ID, SERVER_URL,
)

import urllib.request, urllib.error

CORRECT_TOKEN = os.environ.get("CHAKRA_CORRECT_TOKEN", "testtoken123")

# Reminder gate — skip gracefully if caller hasn't set the flag
AUTH_TOKEN_SET = os.environ.get("AUTH_TOKEN_SET", "").strip() not in ("", "0", "false", "no")


def http_get_raw(path: str, token: str | None = None) -> int:
    """Return just the HTTP status code for a GET request."""
    import urllib.request, urllib.error
    url = SERVER_URL + path
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def run() -> bool:
    section("Test 5 — Authentication enforcement")

    if not AUTH_TOKEN_SET:
        warn("Skipping: AUTH_TOKEN_SET env-var not set.")
        warn("To run this test:")
        warn("  1. Add AUTH_TOKEN=testtoken123 to .env")
        warn("  2. Restart the CHAKRA server")
        warn("  3. Re-run with:  AUTH_TOKEN_SET=1 python tests/test_5_auth.py")
        return True   # Skip, not fail

    require_server(token=CORRECT_TOKEN)

    filepath = "demo/chakra_demo_app.py"
    source = demo_source()
    body = {"filepath": filepath, "source": source, "org_id": ORG_ID, "dev_id": DEV_ID}

    passed = True

    # ── Case 1: no token → 401 ─────────────────────────────────────────────────
    info("Case 1: POST /scan with NO token…")
    code1, _ = post("/scan", body, token="")
    if code1 == 401:
        ok("HTTP 401 returned (correct — no token) ✓")
    else:
        fail(f"Expected 401, got {code1}")
        passed = False

    # ── Case 2: wrong token → 401 ─────────────────────────────────────────────
    info("Case 2: POST /scan with WRONG token…")
    code2, _ = post("/scan", body, token="wrong-token-xyzzy")
    if code2 == 401:
        ok("HTTP 401 returned (correct — wrong token) ✓")
    else:
        fail(f"Expected 401, got {code2}")
        passed = False

    # ── Case 3: correct token → 200 ───────────────────────────────────────────
    info("Case 3: POST /scan with correct token…")
    code3, resp3 = post("/scan", body, token=CORRECT_TOKEN)
    if code3 == 200:
        ok(f"HTTP 200 returned (correct token accepted) — {len(resp3.get('findings',[]))} findings ✓")
    else:
        fail(f"Expected 200 with correct token, got {code3}: {resp3}")
        passed = False

    # ── Case 4: dashboard is token-exempt ─────────────────────────────────────
    info("Case 4: GET /dashboard WITHOUT token (should be 200)…")
    dash_code = http_get_raw("/dashboard")
    if dash_code == 200:
        ok("Dashboard accessible without token (HTTP 200) ✓")
    else:
        fail(f"Dashboard returned HTTP {dash_code} — expected 200 (token-exempt)")
        passed = False

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
