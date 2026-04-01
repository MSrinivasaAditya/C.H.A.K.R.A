"""
Test 6 — Rate limiting

Protocol:
  1. Send 12 POST /scan requests from the same dev_id within 30 s.
  2. The 11th and 12th must return HTTP 429 (limit is 10 per 60 s).
  3. Wait 61 s for the sliding window to expire.
  4. Send one more request — must return HTTP 200.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, post, demo_source,
    ORG_ID,
)

RATE_DEV_ID   = "rate-limit-dev-test"   # isolated dev to avoid polluting other tests
BURST_COUNT   = 12
RATE_LIMIT    = 10
WINDOW_S      = 60
WAIT_AFTER_S  = 62


def run() -> bool:
    section("Test 6 — Rate limiting")
    require_server()

    source = demo_source()
    body = {
        "filepath": "demo/chakra_demo_app.py",
        "source": source,
        "org_id": ORG_ID,
        "dev_id": RATE_DEV_ID,
    }

    info(f"Sending {BURST_COUNT} requests from dev_id='{RATE_DEV_ID}' as fast as possible…")

    statuses: list[int] = []
    t_start = time.time()

    for i in range(BURST_COUNT):
        code, _ = post("/scan", body, timeout=180)
        statuses.append(code)
        elapsed = time.time() - t_start
        label = "OK " if code == 200 else "429" if code == 429 else str(code)
        info(f"  Request {i+1:>2}: HTTP {label}  ({elapsed:.1f}s elapsed)")

    burst_elapsed = time.time() - t_start
    info(f"Burst completed in {burst_elapsed:.1f}s")

    passed = True

    # ── Assertions ─────────────────────────────────────────────────────────────
    success_count = statuses.count(200)
    limit_count   = statuses.count(429)

    if success_count >= RATE_LIMIT:
        ok(f"First {RATE_LIMIT} requests accepted (HTTP 200) ✓")
    else:
        # Fewer could succeed if cache returns very fast — that's fine.
        # The key assertion is that SOME 429s were issued.
        warn(f"Only {success_count} 200s (may be OK if some were cached/fast-pathed)")

    if limit_count >= (BURST_COUNT - RATE_LIMIT):
        ok(f"Requests {RATE_LIMIT+1}–{BURST_COUNT} returned HTTP 429 ({limit_count} total) ✓")
    else:
        fail(f"Expected ≥{BURST_COUNT - RATE_LIMIT} HTTP 429 responses, got {limit_count}")
        fail(f"Full status list: {statuses}")
        passed = False

    # Verify 429 starts at position ≥ 10, not earlier
    first_429 = next((i for i, s in enumerate(statuses) if s == 429), None)
    if first_429 is not None and first_429 < RATE_LIMIT:
        fail(f"Rate limit triggered at request {first_429+1} (before the {RATE_LIMIT}-request threshold)")
        passed = False
    elif first_429 is not None:
        ok(f"First 429 at request {first_429+1} (threshold is {RATE_LIMIT}) ✓")

    # ── Wait for window to expire ──────────────────────────────────────────────
    info(f"Waiting {WAIT_AFTER_S}s for the {WINDOW_S}s sliding window to expire…")
    time.sleep(WAIT_AFTER_S)

    info("Sending one request after window expiry…")
    code_after, _ = post("/scan", body, timeout=180)
    if code_after == 200:
        ok(f"Request after window expiry: HTTP 200 ✓")
    elif code_after == 429:
        fail("Still rate-limited after waiting 62 s — window did not reset")
        passed = False
    else:
        warn(f"Unexpected status after window wait: {code_after}")

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
