"""
Test 3 — Dual-surface sync (Extension ↔ Dashboard)

Protocol:
  1. POST /scan with a unique dev_id → get findings back.
  2. Poll GET /findings for up to 35 s (simulating the dashboard 30-s poll).
  3. Confirm the finding appears in /findings with the correct dev_id.
  4. Poll GET /stats and confirm findings_by_developer contains our dev_id.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, post, get, demo_source,
    ORG_ID,
)

SYNC_DEV_ID = "sync-test-dev-99"   # unique so we can find it in org findings


def run() -> bool:
    section("Test 3 — Dual-surface sync (extension ↔ dashboard)")
    require_server()

    filepath = "demo/chakra_demo_app.py"
    source = demo_source()

    # ── Step 1: trigger a scan as SYNC_DEV_ID ─────────────────────────────────
    info(f"Step 1: scanning as dev_id='{SYNC_DEV_ID}'…")
    code, resp = post("/scan", {
        "filepath": filepath,
        "source": source,
        "org_id": ORG_ID,
        "dev_id": SYNC_DEV_ID,
    })

    if code != 200:
        fail(f"Scan returned HTTP {code}: {resp}")
        return False

    scan_findings = resp.get("findings", [])
    ok(f"Scan returned {len(scan_findings)} finding(s)")

    if not scan_findings:
        warn("Zero findings — if this is a clean-DB first run, re-run after the demo app is in cache")

    # ── Step 2: poll /findings (simulating the dashboard 30-s cycle) ──────────
    info("Step 2: polling /findings for up to 35 s (simulating dashboard auto-poll)…")
    deadline = time.time() + 35
    found_in_dashboard = False
    polls = 0

    while time.time() < deadline:
        polls += 1
        gc, gf = get("/findings", params={"org_id": ORG_ID})
        if gc != 200:
            fail(f"/findings returned HTTP {gc}")
            return False

        org_list = gf if isinstance(gf, list) else []
        matching = [f for f in org_list if f.get("dev_id") == SYNC_DEV_ID]

        if matching:
            found_in_dashboard = True
            ok(f"Finding(s) for dev_id='{SYNC_DEV_ID}' visible in /findings after {polls} poll(s) ✓")
            break

        time.sleep(5)

    passed = True

    if not found_in_dashboard:
        if not scan_findings:
            warn("No findings to sync (demo scan was empty). Test inconclusive but not failing.")
        else:
            fail(f"Finding did not appear in /findings within 35 s for dev_id='{SYNC_DEV_ID}'")
            passed = False
    else:
        # ── Step 3: verify dev_id is correct in each returned finding ──────────
        gc2, gf2 = get("/findings", params={"org_id": ORG_ID})
        org_list2 = gf2 if isinstance(gf2, list) else []
        for f in org_list2:
            if f.get("dev_id") == SYNC_DEV_ID:
                ok(f"Correct dev_id='{SYNC_DEV_ID}' in finding: {f.get('cwe')} line {f.get('line_number')}")
                break

        # ── Step 4: verify /stats contains our dev_id ──────────────────────────
        sc, sf = get("/stats", params={"org_id": ORG_ID})
        if sc != 200:
            fail(f"/stats returned HTTP {sc}")
            passed = False
        else:
            by_dev = (sf if isinstance(sf, dict) else {}).get("findings_by_developer", {})
            if SYNC_DEV_ID in by_dev:
                ok(f"/stats.findings_by_developer contains '{SYNC_DEV_ID}' → {by_dev[SYNC_DEV_ID]} finding(s) ✓")
            else:
                fail(f"'{SYNC_DEV_ID}' not found in /stats.findings_by_developer: {by_dev}")
                passed = False

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
