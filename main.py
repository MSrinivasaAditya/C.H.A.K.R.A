import argparse
import sys
import subprocess
import os
from core.orchestrator import AgentOrchestrator

def start_dashboard():
    """
    Spins up the local HITL FastAPI dashboard.
    """
    print("[CLI] Starting Human-In-The-Loop local dashboard on port 8000...")
    subprocess.Popen([sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", "127.0.0.1", "--port", "8000"])
    print("[CLI] Dashboard running at http://127.0.0.1:8000")

from core.utils import clone_repo

def run_agents(target: str):
    """
    Kicks off the Multi-Agent Auditor loop.
    Checks if target is a GitHub URL.
    """
    if target.startswith("http://") or target.startswith("https://") or target.startswith("git@"):
        print(f"[CLI] Detect GitHub repo URL: {target}")
        target_dir = os.path.join(os.getcwd(), "target_repo_cloned")
        try:
            clone_repo(target, target_dir)
            target_to_audit = target_dir
        except Exception as e:
            print(f"[CLI] Error cloning repository: {e}")
            return
    else:
        target_to_audit = target

    print(f"[CLI] Auditing target: {target_to_audit}")
    orchestrator = AgentOrchestrator(target_to_audit)
    orchestrator.run_squad()
    print("[CLI] Agentic loop completed. Results are ready for Human-in-the-Loop review.")

def main():
    parser = argparse.ArgumentParser(description="C.H.A.K.R.A Air-Gapped Multi-Agent Security Auditor")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Audit Command
    audit_parser = subparsers.add_parser("audit", help="Run the Security Squad against a target or GitHub URL")
    audit_parser.add_argument("target", type=str, help="Path to the directory or GitHub URL to audit")
    
    # Dashboard Command
    dashboard_parser = subparsers.add_parser("dashboard", help="Start the local HITL dashboard")

    args = parser.parse_args()

    if args.command == "audit":
        run_agents(args.target)
    elif args.command == "dashboard":
        start_dashboard()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
