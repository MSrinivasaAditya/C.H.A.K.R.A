"""
Test 8 — Demo app coverage (all 7 vulnerabilities, all 4 LLM fields, specific guidance)

Protocol:
  1. Scan demo/chakra_demo_app.py.
  2. Confirm ≥ 7 distinct findings are returned.
  3. Confirm all 7 vulnerability CWE families are covered:
       CWE-798 (hardcoded secret / AWS key)
       CWE-89  (SQL injection)
       CWE-78  (OS command injection)
       CWE-502 (pickle deserialization)
       CWE-327 (weak MD5 hash)
       CWE-330 (insecure random)
       CWE-94  (eval / code injection)
  4. For EVERY finding confirm these four LLM fields are non-empty:
       explanation, attack_scenario, fix_diff, future_guidance
  5. For future_guidance: confirm it is NOT generic boilerplate by checking
     that it references at least one of the specific code tokens from the
     finding's original_line_content (function name, module, variable, etc.)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests.helpers import (
    section, ok, fail, info, warn,
    require_server, scan_demo,
)

# CWE families we expect — matching by prefix so CWE-89 matches "CWE-89" or "CWE-089"
EXPECTED_CWE_PREFIXES = {
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-502": "Insecure Deserialization (pickle)",
    "CWE-327": "Weak Cryptography (MD5)",
    "CWE-330": "Insecure Randomness",
    "CWE-94":  "Code Injection (eval)",
    "CWE-798": "Hardcoded Credential / Secret",
}

LLM_FIELDS = ("explanation", "attack_scenario", "fix_diff", "future_guidance")

# Tokens from the demo app that a specific future_guidance should reference
SPECIFIC_TOKENS_BY_LINE = {
    # line content fragments → expected token keywords in future_guidance
    "sqlite3": ["sqlite", "parameterized", "query", "sql"],
    "os.system": ["os.system", "subprocess", "shell", "command"],
    "pickle.loads": ["pickle", "deserializ", "marshal", "untrusted"],
    "hashlib.md5": ["md5", "sha-256", "sha256", "bcrypt", "argon"],
    "random.randint": ["random", "secrets", "cryptograph", "predictable"],
    "eval(": ["eval", "ast.literal", "expression", "inject"],
    "AKIAIOSFODNN7EXAMPLE": ["hardcoded", "secret", "credential", "environ", "vault"],
}

BOILERPLATE_PHRASES = [
    "follow secure coding guidelines",
    "consult a security expert",
    "always validate user input",
    "use best practices",
    "review your code for security issues",
]


def _normalise_cwe(cwe: str) -> str:
    """Normalise 'CWE-089' → 'CWE-89'."""
    m = re.match(r"CWE-0*(\d+)", cwe, re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else cwe.upper()


def _is_specific(guidance: str, line_content: str) -> tuple[bool, str]:
    gl = guidance.lower()
    lc = line_content.lower()
    for snippet, keywords in SPECIFIC_TOKENS_BY_LINE.items():
        if snippet.lower() in lc:
            for kw in keywords:
                if kw in gl:
                    return True, kw
            return False, f"(none of {keywords})"
    # For lines we have no specific mapping — just reject pure boilerplate
    for bp in BOILERPLATE_PHRASES:
        if bp in gl:
            return False, f"boilerplate: '{bp}'"
    return True, "(no boilerplate detected)"


def run() -> bool:
    section("Test 8 — Demo app coverage (7 vulns, 4 LLM fields, specific guidance)")
    require_server()

    info("Scanning demo/chakra_demo_app.py for full coverage check…")
    code, resp = scan_demo()

    if code != 200:
        fail(f"Scan returned HTTP {code}: {resp}")
        return False

    findings = resp.get("findings", [])
    info(f"Received {len(findings)} finding(s)")

    passed = True

    # ── Check 1: at least 7 findings ──────────────────────────────────────────
    if len(findings) >= 7:
        ok(f"Finding count {len(findings)} ≥ 7 ✓")
    else:
        fail(f"Only {len(findings)} findings returned — expected ≥ 7")
        passed = False

    # ── Check 2: CWE coverage ─────────────────────────────────────────────────
    detected_cwes = {_normalise_cwe(f.get("cwe", "")) for f in findings}
    info(f"Detected CWEs: {sorted(detected_cwes)}")

    for prefix, label in EXPECTED_CWE_PREFIXES.items():
        matched = any(dc.startswith(prefix) for dc in detected_cwes)
        if matched:
            ok(f"  {prefix} ({label}) detected ✓")
        else:
            fail(f"  {prefix} ({label}) NOT detected")
            passed = False

    # ── Check 3 & 4: LLM fields + specificity ──────────────────────────────────
    info("Checking LLM fields and future_guidance specificity…")

    for i, f in enumerate(findings):
        cwe = f.get("cwe", f"finding[{i}]")
        line_content = f.get("original_line_content", "")

        # 3a: all four fields present and non-empty
        for field in LLM_FIELDS:
            val = f.get(field, "")
            if val and val.strip():
                pass  # OK
            else:
                fail(f"  {cwe}: field '{field}' is missing or empty")
                passed = False

        # 3b: future_guidance is specific, not boilerplate
        fg = f.get("future_guidance", "")
        if fg:
            specific, reason = _is_specific(fg, line_content)
            if specific:
                ok(f"  {cwe}: future_guidance is specific (matched '{reason}') ✓")
            else:
                fail(f"  {cwe}: future_guidance appears generic — {reason}")
                fail(f"    guidance: {fg[:120]}…")
                passed = False

    # ── Summary ────────────────────────────────────────────────────────────────
    if passed:
        ok(f"\nAll coverage checks passed for {len(findings)} finding(s) ✓")
    else:
        fail("\nSome coverage checks failed — see above")

    return passed


if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
