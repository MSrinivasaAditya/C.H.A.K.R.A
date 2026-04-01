#!/usr/bin/env python3
"""
CHAKRA Phase-9 Acceptance Test Runner
──────────────────────────────────────
Usage:
  python tests/run_all.py              # run all tests
  python tests/run_all.py 1 3 8        # run only tests 1, 3, 8
  python tests/run_all.py --no-slow    # skip tests 4, 6, 7 (need internet / Ollama / long wait)

Exit code: 0 if all executed tests pass, 1 otherwise.

Environment variables (override defaults):
  CHAKRA_SERVER_URL   default http://127.0.0.1:7777
  CHAKRA_ORG_ID       default test-org
  CHAKRA_DEV_ID       default test-dev
  CHAKRA_AUTH_TOKEN   default "" (empty)

Test-specific flags:
  AUTH_TOKEN_SET=1    enable test 5 (auth enforcement)
  OLLAMA_RUNNING=1    enable test 7 (Ollama mode)
  CHAKRA_REPO_URL     override the repo URL for test 4
  CHAKRA_SERVER_CMD   override the server start command for test 2
"""
from __future__ import annotations

import importlib
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── ANSI colours ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

TESTS = [
    (1, "tests.test_1_cache_hit",               "Cache hit verification"),
    (2, "tests.test_2_dismissal_persistence",   "Dismissed finding persistence"),
    (3, "tests.test_3_dual_surface_sync",       "Dual-surface sync"),
    (4, "tests.test_4_repo_scan",               "Repo scan end-to-end"),
    (5, "tests.test_5_auth",                    "Authentication enforcement"),
    (6, "tests.test_6_rate_limit",              "Rate limiting"),
    (7, "tests.test_7_ollama",                  "Ollama mode"),
    (8, "tests.test_8_demo_coverage",           "Demo app coverage"),
]

SLOW_TESTS = {4, 6, 7}    # internet / Ollama / long wait required


def banner() -> None:
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║   C.H.A.K.R.A  —  Phase 9 Acceptance Test Runner    ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def result_row(num: int, name: str, status: str, dur: float, note: str = "") -> None:
    if status == "PASS":
        colour = GREEN
        sym = "✔"
    elif status == "SKIP":
        colour = YELLOW
        sym = "○"
    else:
        colour = RED
        sym = "✘"

    note_str = f"  {DIM}{note}{RESET}" if note else ""
    print(f"  {colour}{sym}{RESET}  Test {num:<2}  {name:<38}  "
          f"{colour}{status}{RESET}  {DIM}{dur:>6.1f}s{RESET}{note_str}")


def main() -> int:
    banner()

    # ── Parse CLI args ─────────────────────────────────────────────────────────
    args = sys.argv[1:]
    no_slow = "--no-slow" in args
    args = [a for a in args if a != "--no-slow"]

    if args:
        try:
            selected_nums = {int(a) for a in args}
        except ValueError:
            print(f"{RED}Usage: python tests/run_all.py [test_numbers...] [--no-slow]{RESET}")
            return 2
    else:
        selected_nums = {n for n, _, _ in TESTS}

    if no_slow:
        selected_nums -= SLOW_TESTS
        print(f"{YELLOW}--no-slow: skipping tests {sorted(SLOW_TESTS)}{RESET}\n")

    # ── Run ────────────────────────────────────────────────────────────────────
    results: list[tuple[int, str, str, float, str]] = []  # (num, name, status, dur, note)

    for num, module_path, display_name in TESTS:
        if num not in selected_nums:
            continue

        t0 = time.time()
        try:
            mod = importlib.import_module(module_path)
            passed = mod.run()   # type: ignore[attr-defined]
            dur = time.time() - t0
            if passed is True:
                status, note = "PASS", ""
            elif passed is None:
                status, note = "SKIP", "returned None (skipped)"
            else:
                status, note = "FAIL", ""
        except SystemExit as e:
            dur = time.time() - t0
            status = "SKIP" if e.code == 2 else "FAIL"
            note = f"exit({e.code})"
        except Exception as exc:
            dur = time.time() - t0
            status = "FAIL"
            note = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()

        results.append((num, display_name, status, dur, note))

    # ── Summary table ──────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  Results{RESET}")
    print(f"{BOLD}{'─'*70}{RESET}")

    n_pass = n_fail = n_skip = 0
    for num, name, status, dur, note in results:
        result_row(num, name, status, dur, note)
        if status == "PASS":
            n_pass += 1
        elif status == "SKIP":
            n_skip += 1
        else:
            n_fail += 1

    total = n_pass + n_fail
    print(f"\n{BOLD}{'─'*70}{RESET}")
    verdict_colour = GREEN if n_fail == 0 else RED
    verdict_label  = "ALL TESTS PASSED" if n_fail == 0 else f"{n_fail} TEST(S) FAILED"
    print(f"  {verdict_colour}{BOLD}{verdict_label}{RESET}  "
          f"({n_pass}/{total} passed, {n_skip} skipped)\n")

    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
