# C.H.A.K.R.A
### Codebase Hardening through Agentic Knowledge, Risk and Audit

> *Most security scanners tell you what is wrong and stop. CHAKRA tells you what is wrong, why an attacker would care, how to fix it right now, and how to avoid reintroducing it when you extend the code — all running locally, with no source code leaving your machine.*

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![Semgrep](https://img.shields.io/badge/Semgrep-SAST-orange?style=flat-square)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20%7C%20Anthropic-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)

---

## What Is CHAKRA?

CHAKRA is an agentic security intelligence platform for Python codebases. It combines static analysis with a three-stage LLM pipeline to detect vulnerabilities, reduce false positives, and generate actionable remediation guidance — including a novel **future-proofing field** that tells developers how to safely extend vulnerable code patterns without reintroducing the vulnerability.

It runs as a single Python process with no cloud dependencies. Source code never leaves your machine.

### Two Surfaces, One Brain

| Surface | Who Uses It | What It Does |
|---|---|---|
| **VS Code Extension** | Developer writing code | Real-time scanning on every save, inline highlights, hover cards, CodeLens labels |
| **Web Dashboard** | Tech lead / Security reviewer | Org-wide findings, repo scanner, Remediation Decision Matrix, severity trends |

Both surfaces share one backend, one database, and one detection pipeline.

---

## Key Features

### Developer Surface (VS Code)
- Scans on every `Ctrl+S` — results in under 5 seconds
- **Delta scanning** — only analyses changed lines, not the full file
- Inline severity highlights (red / orange / yellow by CWE risk)
- CodeLens labels above every flagged line
- Hover cards with attack scenario and fix buttons
- Modal popup with full finding detail and Apply Fix gate
- **Dismissed findings persist permanently** across VS Code and server restarts

### Security Intelligence Pipeline
Three sequential stages run on every scan:

1. **Scout** — AST parsing extracts functions, classes, imports, and dangerous patterns structurally
2. **Audit** — Semgrep static analysis combined with LLM false positive reduction
3. **Remediate** — LLM generates four fields per finding:
   - `explanation` — what is wrong and why it is dangerous
   - `attack_scenario` — concrete attack vector specific to the code
   - `fix_diff` — minimal before/after code diff
   - `future_guidance` — **novel contribution** — how to safely extend this code in your future roadmap

### Organization Dashboard
- Org-wide findings aggregated from all developers
- Repository scanner — paste a GitHub URL and scan the entire codebase
- Remediation Decision Matrix per finding (Apply Now / Defer / Assign Owner)
- Severity distribution charts
- Auto-refresh every 30 seconds
- No installation required — open in any browser

### Privacy-First Architecture
- **Ollama mode** — LLM runs fully locally, zero API calls, zero data leaves the machine
- **Anthropic mode** — cloud LLM for higher quality output, switchable via one config line
- Single Python process — no Docker, no Redis, no cloud services
- SQLite for all persistence — one file, no database server

---

## Novel Contribution

The `future_guidance` field is CHAKRA's primary research contribution. No existing published security tool answers the question:

> *"If my roadmap requires adding OAuth next sprint, how do I do that safely given this vulnerability?"*

Every tool on the market tells you what is wrong and how to fix it **right now**. CHAKRA additionally tells you how to **extend the code safely in the future** — a gap identified across the published literature on automated vulnerability repair.

---

## Supported Vulnerability Patterns

CHAKRA detects 8 CWE categories with 24 Semgrep rules:

| CWE | Vulnerability | Severity |
|---|---|---|
| CWE-89 | SQL Injection | HIGH |
| CWE-78 | OS Command Injection | HIGH |
| CWE-502 | Insecure Deserialization (pickle) | HIGH |
| CWE-95 | Code Injection (eval/exec) | HIGH |
| CWE-798 | Hardcoded Credentials | HIGH |
| CWE-22 | Path Traversal | HIGH |
| CWE-328 | Weak Cryptographic Hash (MD5/SHA1) | MEDIUM |
| CWE-338 | Insecure Randomness | MEDIUM |

---

## vs. Existing Tools

| Capability | CHAKRA | Snyk | SonarQube | Semgrep | Bandit |
|---|---|---|---|---|---|
| Finds vulnerabilities | ✅ | ✅ | ✅ | ✅ | ✅ |
| Generates patch diff | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Future-proofing guidance** | ✅ | ❌ | ❌ | ❌ | ❌ |
| LLM false positive filtering | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Air-gapped local LLM mode** | ✅ | ❌ | ❌ | ❌ | ✅ |
| Real-time IDE integration | ✅ | Partial | ❌ | ❌ | ❌ |
| **Delta scanning** | ✅ | ❌ | ❌ | ❌ | ❌ |
| Org-wide dashboard | ✅ | ✅ | ✅ | ❌ | ❌ |
| GitHub repo audit | ✅ | ✅ | ✅ | ✅ | ❌ |
| Free / open source | ✅ MIT | ❌ | ❌ | ✅ limited | ✅ |

---

## Quick Start

### Requirements
- Python 3.11 or higher
- Git
- [Ollama](https://ollama.com) (for local LLM mode) or an Anthropic API key

### Local Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/VibeSentinel.git
cd VibeSentinel

# Copy environment config
copy .env.example .env

# Install dependencies
pip install -r requirements.txt

# Pull the LLM model (local mode)
ollama pull qwen2.5:0.5b

# Start the server
python backend\chakra_server.py
```

Server starts at `http://127.0.0.1:7777`

Open the dashboard at `http://127.0.0.1:7777/dashboard`

### VS Code Extension

```bash
cd extension
npm install
npm run compile
```

Press `F5` in VS Code to launch the Extension Development Host. Open any Python file and press `Ctrl+S` to trigger a scan.

### Configuration

Edit `.env` to configure:

```env
# LLM Backend: "ollama" (local, free) or "anthropic" (cloud, requires API key)
LLM_BACKEND=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5:0.5b

# Server mode: "local" (127.0.0.1) or "server" (0.0.0.0 for org deployment)
DEPLOYMENT_MODE=local

# Optional auth token for org deployments
AUTH_TOKEN=

# Default org ID for multi-team deployments
DEFAULT_ORG_ID=default
```

---

## Organization Deployment

For teams, run CHAKRA on a shared server. Every developer only needs to install the VS Code extension and change one setting:

```
chakra.serverUrl = http://<your-server-ip>:7777
```

No per-machine Python installation. No per-machine API key. One server, all findings in one place.

**Server setup:**

```bash
# On the server machine
DEPLOYMENT_MODE=server
AUTH_TOKEN=your_chosen_token

# Run start script
bash start_server.sh
```

Open port 7777 on your internal firewall. Share the server IP and auth token with your team.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/scan` | POST | Scan a file — accepts `filepath`, `source`, `org_id`, `dev_id` |
| `/dismiss` | POST | Permanently dismiss a finding by `dismissal_fingerprint` |
| `/findings` | GET | All active findings for an org — `?org_id=default` |
| `/stats` | GET | Scan metrics and finding counts — `?org_id=default` |
| `/scan/repo` | POST | Trigger async GitHub repo scan — accepts `repo_url` |
| `/scan/repo/status/:id` | GET | Poll repo scan status and results |
| `/config` | GET | Server configuration and defaults |
| `/dashboard` | GET | Serves the web dashboard HTML |

---

## Project Structure

```
VibeSentinel/
├── backend/
│   ├── chakra_server.py          # Single HTTP server, all endpoints
│   ├── delta.py                  # Delta scanning, line fingerprinting
│   ├── pipeline/
│   │   ├── stage_scout.py        # AST analysis, structure extraction
│   │   ├── stage_audit.py        # Semgrep + LLM false positive reduction
│   │   └── stage_remediate.py    # LLM enrichment, future_guidance generation
│   ├── db/
│   │   └── state_manager.py      # All SQLite operations
│   ├── llm/
│   │   └── llm_client.py         # Dual-mode: Ollama + Anthropic
│   └── rules/
│       └── chakra_rules.yaml     # 24 Semgrep rules, 8 CWEs
├── dashboard/
│   └── dashboard.html            # Self-contained web dashboard
├── extension/
│   └── src/
│       └── extension.ts          # VS Code extension
├── demo/
│   └── chakra_demo_app.py        # 7 deliberate vulnerabilities for testing
├── .env.example
├── requirements.txt
├── start_server.sh
└── start_server.bat
```

---

## Research Background

CHAKRA is developed as part of academic research targeting publication in IEEE Access / IEEE SecDev. The primary novel contribution is **Developer Decision Intelligence** — a vulnerability reporting framework that extends existing SAST+LLM pipelines with scope-aware patch rationale and future-proofing guidance.

### Key References

- Steenhoek et al. — DeepVulGuard (ICSE 2025)
- Gajjar et al. — SecureFixAgent (ICMLA 2025, arXiv:2509.16275)
- Fu et al. — VulRepair (ACM ESEC/FSE 2022)
- Pearce et al. — Zero-shot vulnerability repair (IEEE S&P 2023)
- Hu et al. — SoK on Automated Vulnerability Repair (USENIX Security 2025)

---

## Roadmap

- [ ] Benchmark evaluation on OWASP WebGoat (Precision / Recall / F1 vs Bandit and Semgrep)
- [ ] GitHub Actions CI/CD integration
- [ ] JavaScript and TypeScript language support
- [ ] Sandboxed patch verification via isolated execution
- [ ] PR diff scanning — scan only changed files in a pull request
- [ ] SARIF report export for integration with GitHub Security tab

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request describing the change and its motivation.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built with [Semgrep](https://semgrep.dev), [Ollama](https://ollama.com), and the [Anthropic API](https://anthropic.com). Vulnerability patterns informed by OWASP Top 10 and NIST NVD CWE classifications.

---

*CHAKRA is a research project and should be used as one layer of a broader security strategy, not as a sole security control.*
