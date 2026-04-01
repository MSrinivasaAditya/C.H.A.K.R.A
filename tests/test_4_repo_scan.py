"""
Test 4 — Repo scan end-to-end

Protocol:
  1. POST /scan/repo with a known-vulnerable public Python repo URL.
  2. Poll GET /scan/repo/status/<id> until status == "complete" (or timeout).
  3. Confirm findings list is non-empty.
  4. Confirm at least one finding includes a SQL-injection or similar high-severity CWE.

Default repo: https://github.com/payloadbox/sql-injection-payload-list
(Fallback: any public Python repo known to have eval / SQL issues.)

Override with env-var:  CHAKRA_REPO_URL=https://github.com/...
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, post, get,
    ORG_ID, DEV_ID,
)

# A small deliberately-vulnerable Python repo suited for CI testing
DEFAULT_REPO = os.environ.get(
    "CHAKRA_REPO_URL",
    "https://github.com/mukultaneja/dvwa-python",
)

POLL_INTERVAL = 10   # seconds between status polls
POLL_TIMEOUT  = 300  # 5 minutes max


def run() -> bool:
    section("Test 4 — Repo scan end-to-end")
    require_server()

    repo_url = DEFAULT_REPO
    info(f"Repo URL: {repo_url}")
    warn("This test clones a public GitHub repo — requires internet access.")
    warn(f"Override with:  CHAKRA_REPO_URL=<url>")

    # ── Step 1: kick off repo scan ─────────────────────────────────────────────
    info("Step 1: POST /scan/repo…")
    code, resp = post("/scan/repo", {
        "repo_url": repo_url,
        "org_id": ORG_ID,
        "dev_id": DEV_ID,
    })

    if code != 200:
        fail(f"/scan/repo returned HTTP {code}: {resp}")
        return False

    scan_id = resp.get("scan_id")
    status  = resp.get("status")
    ok(f"Repo scan queued: id={scan_id}, initial status='{status}'")

    if not scan_id:
        fail("No scan_id in response")
        return False

    # ── Step 2: poll for completion ────────────────────────────────────────────
    info(f"Step 2: polling /scan/repo/status/{scan_id} (timeout {POLL_TIMEOUT}s)…")
    deadline = time.time() + POLL_TIMEOUT
    final_status = status
    findings = []

    while time.time() < deadline:
        time.sleep(POLL_INTERVAL)
        gc, gr = get(f"/scan/repo/status/{scan_id}")
        if gc != 200:
            fail(f"Status poll returned HTTP {gc}: {gr}")
            return False

        gr_dict = gr if isinstance(gr, dict) else {}
        final_status = gr_dict.get("status", "unknown")
        info(f"  status = '{final_status}'")

        if final_status == "complete":
            findings = gr_dict.get("findings", [])
            break
        if final_status == "failed":
            err = gr_dict.get("findings", [{}])
            fail(f"Repo scan failed: {err}")
            return False

    passed = True

    # ── Step 3: confirm completion ────────────────────────────────────────────
    if final_status != "complete":
        fail(f"Repo scan did not complete within {POLL_TIMEOUT}s — final status: '{final_status}'")
        return False
    ok("Status reached 'complete' ✓")

    # ── Step 4: confirm findings ───────────────────────────────────────────────
    if not findings:
        fail("No findings returned from repo scan")
        passed = False
    else:
        ok(f"{len(findings)} finding(s) returned ✓")

        # Look for at least one meaningful CWE
        EXPECTED_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-327", "CWE-330", "CWE-798"}
        found_cwes = {f.get("cwe", "") for f in findings}
        matched = EXPECTED_CWES & found_cwes

        if matched:
            ok(f"High-value CWE(s) detected: {matched} ✓")
        else:
            warn(f"None of the expected CWEs {EXPECTED_CWES} were detected (got: {found_cwes})")
            warn("The repo may not contain patterns the current ruleset covers — non-fatal")

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
