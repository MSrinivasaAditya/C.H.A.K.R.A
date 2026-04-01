"""
Test 2 — Dismissed finding persistence

Protocol:
  1. Scan the demo app, pick the first finding.
  2. POST /dismiss for that finding.
  3. Restart the backend server (kills the current process, starts a new one).
  4. Scan the demo app again.
  5. Confirm the dismissed finding does NOT appear in the new scan response.
  6. Confirm it does NOT appear in GET /findings for the org.

NOTE: This test controls the server process directly.
      It requires the CHAKRA_SERVER_CMD env-var OR falls back to:
        python -m backend.chakra_server
      Run from the repo root.
"""
from __future__ import annotations

import os
import sys
import time
import signal
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, scan_demo, post, get,
    demo_source, ORG_ID, DEV_ID, SERVER_URL,
)

ROOT = Path(__file__).parent.parent.resolve()
SERVER_CMD = os.environ.get(
    "CHAKRA_SERVER_CMD",
    f"{sys.executable} -m backend.chakra_server",
).split()


def start_server() -> subprocess.Popen:
    proc = subprocess.Popen(
        SERVER_CMD,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait for it to come up
    import urllib.request, urllib.error
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{SERVER_URL}/stats?org_id={ORG_ID}", timeout=2)
            return proc
        except Exception:
            time.sleep(1)
    proc.terminate()
    raise RuntimeError("Server did not start within 30 s")


def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run() -> bool:
    section("Test 2 — Dismissed finding persistence")

    # ── Step 1: initial scan ───────────────────────────────────────────────────
    info("Step 1: starting server and scanning demo app…")
    proc = start_server()

    try:
        code, resp = scan_demo()
        if code != 200:
            fail(f"Initial scan returned HTTP {code}")
            stop_server(proc)
            return False

        findings = resp.get("findings", [])
        if not findings:
            warn("No findings returned — demo app scan produced zero findings.")
            warn("Ensure the demo app is unchanged and the pipeline is working.")
            stop_server(proc)
            return False

        target = findings[0]
        ok(f"Got {len(findings)} finding(s). Dismissing: {target.get('cwe')} on line {target.get('line_number')}")

        # ── Step 2: dismiss ────────────────────────────────────────────────────
        dismiss_body = {
            "filepath": str(ROOT / "demo" / "chakra_demo_app.py"),
            "cwe": target.get("cwe", "unknown"),
            "original_line_content": target.get("original_line_content", ""),
            "org_id": ORG_ID,
            "dev_id": DEV_ID,
        }
        dc, dr = post("/dismiss", dismiss_body)
        if dc != 200 or not dr.get("success"):
            fail(f"Dismiss returned HTTP {dc}: {dr}")
            stop_server(proc)
            return False
        ok("Dismiss accepted (HTTP 200, success=True)")

        # ── Step 3: restart server ─────────────────────────────────────────────
        info("Step 3: restarting the server…")
        stop_server(proc)
        time.sleep(1)
        proc = start_server()
        ok("Server restarted successfully")

        # ── Step 4: rescan ─────────────────────────────────────────────────────
        info("Step 4: scanning demo app again after restart…")
        code2, resp2 = scan_demo()
        if code2 != 200:
            fail(f"Post-restart scan returned HTTP {code2}")
            stop_server(proc)
            return False

        findings2 = resp2.get("findings", [])

        # ── Step 5: verify dismissed finding is absent ─────────────────────────
        target_fp = target.get("dismissal_fingerprint") or target.get("fingerprint")
        dismissed_cwes = {f.get("cwe") for f in findings2}
        dismissed_lines = {f.get("line_number") for f in findings2}

        still_present = any(
            f.get("cwe") == target.get("cwe")
            and f.get("line_number") == target.get("line_number")
            for f in findings2
        )

        passed = True
        if still_present:
            fail(f"Dismissed finding ({target.get('cwe')} line {target.get('line_number')}) "
                 f"still appears after server restart")
            passed = False
        else:
            ok("Dismissed finding absent from post-restart scan ✓")

        # ── Step 6: verify via /findings endpoint ──────────────────────────────
        gc, gf = get("/findings", params={"org_id": ORG_ID})
        if gc != 200:
            fail(f"/findings returned HTTP {gc}")
            passed = False
        else:
            org_findings = gf if isinstance(gf, list) else []
            dashboard_still = any(
                f.get("cwe") == target.get("cwe")
                and f.get("line_number") == target.get("line_number")
                for f in org_findings
            )
            if dashboard_still:
                fail("Dismissed finding still appears in /findings (dashboard) after restart")
                passed = False
            else:
                ok("Dismissed finding absent from /findings endpoint ✓")

        return passed

    finally:
        stop_server(proc)


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
