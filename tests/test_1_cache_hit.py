"""
Test 1 — Cache hit verification

Protocol:
  1. Send a full scan of the demo app (first scan → no cached fingerprint).
  2. Change one line, scan again →  must report changed_lines and NOT cache_hit.
  3. Scan again with the same source →  must report cache_hit=True and arrive
     in under 100 ms.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, scan_demo, demo_source, log_tail,
    ORG_ID, DEV_ID,
)


def run() -> bool:
    section("Test 1 — Cache hit verification")
    require_server()

    filepath = "demo/chakra_demo_app.py"   # consistent key across all scans
    original_source = demo_source()

    # ── Step 1: full scan (cold cache) ────────────────────────────────────────
    info("Step 1: cold scan (first-ever scan for this filepath/org/dev triple)…")
    t0 = time.time()
    code, resp = scan_demo(filepath=filepath, source=original_source)
    elapsed_ms_1 = (time.time() - t0) * 1000

    if code != 200:
        fail(f"Scan returned HTTP {code}: {resp}")
        return False

    ok(f"HTTP 200 — {len(resp.get('findings', []))} findings in {elapsed_ms_1:.0f} ms")

    if resp.get("cache_hit"):
        warn("cache_hit=True on first scan — wipe chakra_state.db and re-run if this persists")
    else:
        ok("cache_hit=False (expected for cold scan)")

    # ── Step 2: partial scan (one line changed) ────────────────────────────────
    info("Step 2: change line 9 (API_TOKEN) and scan again…")
    modified = original_source.replace(
        'API_TOKEN = "xyz123_super_secret_token"',
        'API_TOKEN = "changed_for_test_xyz999"',
    )
    assert modified != original_source, "Source substitution failed — demo app may have changed"

    t0 = time.time()
    code2, resp2 = scan_demo(filepath=filepath, source=modified)
    elapsed_ms_2 = (time.time() - t0) * 1000

    if code2 != 200:
        fail(f"Step 2 scan returned HTTP {code2}: {resp2}")
        return False

    ok(f"HTTP 200 — {elapsed_ms_2:.0f} ms")

    passed = True

    if resp2.get("cache_hit"):
        fail("cache_hit=True on a modified file — delta engine may be broken")
        passed = False
    else:
        ok("cache_hit=False (correct — content changed)")

    if resp2.get("changed_lines") is not None:
        cl = resp2["changed_lines"]
        ok(f"changed_lines reported: {cl[0]}–{cl[1]}")
    else:
        # On a fresh first-scan the server does a full scan (changed_lines=None is valid
        # only if there was no previous fingerprint; after step 1 there IS one).
        fail("changed_lines is None — expected a non-null range after a single-line edit")
        passed = False

    # ── Step 3: cache-hit scan (identical source) ──────────────────────────────
    info("Step 3: scan SAME source again — expecting cache_hit=True in <100 ms…")
    t0 = time.time()
    code3, resp3 = scan_demo(filepath=filepath, source=modified)
    elapsed_ms_3 = (time.time() - t0) * 1000

    if code3 != 200:
        fail(f"Step 3 scan returned HTTP {code3}: {resp3}")
        return False

    ok(f"HTTP 200 — {elapsed_ms_3:.0f} ms")

    if resp3.get("cache_hit"):
        ok("cache_hit=True ✓")
    else:
        fail("cache_hit=False — server did NOT serve from cache for identical source")
        passed = False

    if elapsed_ms_3 < 100:
        ok(f"Cache response time {elapsed_ms_3:.1f} ms < 100 ms ✓")
    else:
        fail(f"Cache response time {elapsed_ms_3:.1f} ms ≥ 100 ms — too slow")
        passed = False

    # ── Log verification ───────────────────────────────────────────────────────
    tail = log_tail(30)
    if "file_cached" in tail or "cache_hit" in tail:
        ok("chakra.log contains cache evidence")
    else:
        warn("Could not find cache evidence in recent log lines (non-fatal)")

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
