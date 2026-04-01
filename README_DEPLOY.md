# CHAKRA — Deployment Guide

## 1. Requirements

- **Python 3.11 or higher** — [download](https://www.python.org/downloads/)
- **Git** — [download](https://git-scm.com/downloads)
- **Semgrep** — installed automatically by the start script via `pip`

No other manual installation is needed. The start scripts handle everything else.

---

## 2. Local Setup (single developer)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/chakra.git
cd chakra

# 2. Start the server (Linux / macOS)
bash start_server.sh

# Windows
start_server.bat
```

The script will:
- Create a Python virtual environment in `./venv`
- Install all dependencies
- Copy `.env.example` → `.env` (edit it to add your API key)
- Start the server at `http://127.0.0.1:7777`

```
3. Open VS Code
4. Install the CHAKRA extension (from the extension/ folder or the marketplace)
5. Done — open any Python file and CHAKRA will scan on save
```

---

## 3. Organisation Server Setup (shared team server)

Run the start script on your internal server machine, then:

1. **Open port 7777** on the internal firewall (no internet exposure needed).
2. **Edit `.env`** on the server:
   ```
   DEPLOYMENT_MODE=server
   AUTH_TOKEN=your-secret-token-here
   ```
3. **Tell all developers** to update their VS Code settings:
   - `chakra.serverUrl` → `http://<server-internal-ip>:7777`
   - `chakra.authToken` → the same token you set in `AUTH_TOKEN`
   - `chakra.organizationId` → your org name (e.g. `acme-corp`)
   - `chakra.developerId` → each developer's username

> In `server` mode CHAKRA rejects absolute file paths and expects workspace-relative paths — the VS Code extension handles this automatically.

---

## 4. LLM Configuration

**Default — Anthropic Claude (requires internet):**

```env
LLM_BACKEND=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

**Alternative — Local Ollama (no internet required):**

```env
LLM_BACKEND=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=codellama:13b
```

To use Ollama:
1. [Install Ollama](https://ollama.com/download)
2. Pull the model: `ollama pull codellama:13b`
3. Set `LLM_BACKEND=ollama` in `.env`
4. Restart the server

In Ollama mode the entire pipeline runs on your local machine — no data leaves your network.

---

## 5. Dashboard

Open in any browser — no login required for the read-only view:

```
http://<server-ip>:7777/dashboard
```

The dashboard shows:
- Live findings grouped by file and developer
- Severity breakdown and scan history
- Per-developer security scores

If `AUTH_TOKEN` is set, the dashboard page itself is exempt from authentication so read-only viewers don't need the token.

---

## 6. Troubleshooting

**Always check `chakra.log` first.** The log file is created in the project root.

| Symptom | Likely cause | Fix |
|---|---|---|
| Extension shows "CHAKRA: Error" | Server not running | Re-run `start_server.sh` / `start_server.bat` |
| Server starts then immediately stops | `chakra.log` will show the Python traceback | Usually a missing `ANTHROPIC_API_KEY` |
| Port 7777 refused | Firewall blocking | Allow TCP 7777 in your OS firewall / security group |
| `semgrep: command not found` | Semgrep not in PATH | Run `pip install semgrep` inside the venv manually |
| Python version error | Python < 3.11 | Install Python 3.11+ and recreate the venv: `rm -rf venv && bash start_server.sh` |
| Scan never returns | LLM API timeout | Check `ANTHROPIC_API_KEY` validity or switch to `LLM_BACKEND=ollama` |
| Dashboard shows no data | Wrong `org_id` in extension | Set `chakra.organizationId` in VS Code to match the server's org |
