<div align="center">

# C.H.A.K.R.A
### Codebase Hardening through Agentic Knowledge, Risk and Audit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-Frontend-blue.svg)](https://www.typescriptlang.org/)
[![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

**Most security scanners find the problem and leave you to fix it. CHAKRA finds it, patches it, and verifies the patch works.**

[Live Demo](#) · [Report a Bug](../../issues) · [Request a Feature](../../issues)

</div>

---

## The Problem

AI coding assistants are now part of nearly every developer workflow. They write fast, they write confidently, and they regularly write insecure code.

SQL injection vectors. Hardcoded credentials. Broken access control. Unsafe deserialization. These patterns don't disappear because an AI generated the function — they ship faster, at higher volume, with less scrutiny than ever before.

Traditional scanners hand you a list of findings and stop there. The developer still has to understand the vulnerability, write a fix, test it, and hope they got it right.

CHAKRA closes the loop.

---

## How It Works

CHAKRA is an **agentic security tool** — it doesn't just flag vulnerabilities, it acts on them.

```
Input (code / GitHub URL)
        ↓
   [Parser layer]          — Parses codebase by language and file type
        ↓
   [Core analysis]         — Identifies vulnerabilities, maps to CVE/OWASP categories
        ↓
   [Agent layer]           — Generates targeted patches for each finding
        ↓
   [Sandbox verification]  — Executes and verifies each patch in isolation
        ↓
   [Dashboard]             — Structured report: findings + verified fixes
```

The sandbox verification step is what makes CHAKRA agentic. It doesn't hand you an untested fix — it checks its own work first.

---

## Features

**Two input modes:**
- Paste any code snippet directly for instant analysis
- Provide a GitHub repository URL to audit the full codebase

**Agentic patch generation:**
For every vulnerability found, CHAKRA generates a remediation patch and runs it through a sandboxed verification step before surfacing it in the report.

**Multi-language parser support:**
The `parsers/` layer handles multiple languages and file types across a codebase.

**Web dashboard:**
Full TypeScript + HTML frontend — no CLI required. Results are surfaced in a structured, readable interface.

**Persistent scan history:**
The `db/` layer stores past scan results for reference and comparison.

---

## Architecture

```
C.H.A.K.R.A/
├── agents/          # Agentic patch generation logic
├── core/            # Vulnerability analysis engine
├── parsers/         # Multi-language code parsers
├── dashboard/       # TypeScript + HTML frontend
├── sandbox/         # Isolated patch verification environment
├── db/              # Scan result persistence
├── config/          # Configuration and ruleset management
├── main.py          # Entry point
└── requirements.txt
```

---

## Getting Started

```bash
git clone https://github.com/MSrinivasaAditya/C.H.A.K.R.A.git
cd C.H.A.K.R.A
pip install -r requirements.txt
python main.py
```

On Windows, use the included PowerShell scripts:
```powershell
./start_app.ps1     # Start the application
./restart_app.ps1   # Restart after changes
./stop_app.ps1      # Stop the application
```

---

## Vulnerability Coverage

| Category | Examples |
|---|---|
| Injection flaws | SQL injection, command injection, SSTI |
| Broken access control | IDOR patterns, privilege escalation |
| Sensitive data exposure | Hardcoded secrets, API keys, tokens |
| Security misconfigurations | Insecure defaults, debug exposure |
| Insecure deserialization | Unsafe eval/exec/pickle patterns |
| AI-generated code patterns | LLM output-specific vulnerability signatures |

---

## Roadmap

- [x] Paste-and-scan code analysis
- [x] GitHub repository audit
- [x] Agentic patch generation
- [x] Sandboxed patch verification
- [x] Web dashboard with scan history
- [ ] PR diff scanning for CI/CD pipelines
- [ ] GitHub Actions integration
- [ ] Expanded AI-specific vulnerability ruleset
- [ ] Private repository support

---

## Built By

**M Srinivasa Aditya** — B.E. CSE (Honors in Cybersecurity), graduating 2026

Former intern at CERT-IN (India's national cybersecurity agency) and Telangana Cyber Security Bureau. Built CHAKRA after observing a consistent pattern during real-world pentesting: AI-generated code shipped at scale, without security review.

→ [LinkedIn](https://www.linkedin.com/in/msa2204/) · [GitHub](https://github.com/MSrinivasaAditya)

---

## Contributing

Contributions welcome — especially around expanding vulnerability rulesets and parser support for additional languages. Open an issue to discuss before submitting a PR.

---

## License

MIT

---

<div align="center">
<sub>The AI wrote the code. Did anyone check it?</sub>
</div>