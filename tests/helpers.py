"""
Shared helpers for CHAKRA acceptance tests.
Every test module imports from here.
"""
from __future__ import annotations

import os
import sys
import time
import json
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent.resolve()
DEMO_APP = ROOT / "demo" / "chakra_demo_app.py"
LOG_FILE = ROOT / "chakra.log"
ENV_FILE = ROOT / ".env"

# ── Server config (can be overridden via env) ──────────────────────────────────
SERVER_URL = os.environ.get("CHAKRA_SERVER_URL", "http://127.0.0.1:7777").rstrip("/")
ORG_ID = os.environ.get("CHAKRA_ORG_ID", "test-org")
DEV_ID = os.environ.get("CHAKRA_DEV_ID", "test-dev")
AUTH_TOKEN = os.environ.get("CHAKRA_AUTH_TOKEN", "")


# ── Colours ───────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def ok(msg: str) -> None:
    print(f"  {GREEN}✔{RESET}  {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✘{RESET}  {msg}")


def info(msg: str) -> None:
    print(f"  {CYAN}·{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}!{RESET}  {msg}")


def section(title: str) -> None:
    bar = "─" * (len(title) + 4)
    print(f"\n{BOLD}{CYAN}┌{bar}┐{RESET}")
    print(f"{BOLD}{CYAN}│  {title}  │{RESET}")
    print(f"{BOLD}{CYAN}└{bar}┘{RESET}")


def assert_eq(label: str, got: Any, expected: Any, fatal: bool = True) -> bool:
    if got == expected:
        ok(f"{label}: {got!r}")
        return True
    msg = f"{label}: expected {expected!r}, got {got!r}"
    fail(msg)
    if fatal:
        raise AssertionError(msg)
    return False


def assert_true(label: str, value: Any, fatal: bool = True) -> bool:
    if value:
        ok(f"{label}")
        return True
    msg = f"{label}: value was falsy ({value!r})"
    fail(msg)
    if fatal:
        raise AssertionError(msg)
    return False


# ── HTTP helpers ───────────────────────────────────────────────────────────────
def _build_headers(extra_token: str | None = None) -> dict[str, str]:
    token = extra_token if extra_token is not None else AUTH_TOKEN
    h: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def post(endpoint: str, body: dict, token: str | None = None,
         timeout: int = 120) -> tuple[int, dict]:
    """HTTP POST → (status_code, parsed_json)."""
    url = SERVER_URL + endpoint
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=_build_headers(token), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            body_json = json.loads(raw)
        except Exception:
            body_json = {"_raw": raw.decode(errors="replace")}
        return e.code, body_json


def get(endpoint: str, params: dict | None = None,
        token: str | None = None, timeout: int = 30) -> tuple[int, dict | str]:
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = SERVER_URL + endpoint + qs
    req = urllib.request.Request(url, headers=_build_headers(token), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get_content_type()
            raw = resp.read()
            if "json" in ct:
                return resp.status, json.loads(raw)
            return resp.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode(errors="replace")


# ── Server liveness ────────────────────────────────────────────────────────────
def wait_for_server(timeout_s: int = 30, token: str | None = None) -> bool:
    """Poll /stats until the server responds or timeout."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            code, _ = get("/stats", params={"org_id": ORG_ID}, token=token)
            if code < 500:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def require_server(token: str | None = None) -> None:
    """Abort the current test script if the server is not reachable."""
    if not wait_for_server(token=token):
        print(f"\n{RED}FATAL:{RESET} CHAKRA server not reachable at {SERVER_URL}")
        print(f"  Start it with:  bash start_server.sh  (or start_server.bat)")
        sys.exit(2)


# ── Demo-app source ────────────────────────────────────────────────────────────
def demo_source() -> str:
    return DEMO_APP.read_text(encoding="utf-8")


def scan_demo(filepath: str | None = None,
              source: str | None = None,
              token: str | None = None) -> tuple[int, dict]:
    fp = filepath or str(DEMO_APP)
    src = source if source is not None else demo_source()
    return post("/scan", {
        "filepath": fp,
        "source": src,
        "org_id": ORG_ID,
        "dev_id": DEV_ID,
    }, token=token)


# ── Tail of chakra.log ─────────────────────────────────────────────────────────
def log_tail(n: int = 50) -> str:
    if not LOG_FILE.exists():
        return ""
    lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-n:])
