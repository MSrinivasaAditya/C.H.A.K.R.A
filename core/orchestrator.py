import json
from typing import Dict, Any

from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager

from agents.scout import ScoutAgent
from agents.threat_modeler import ThreatModelerAgent
from agents.auditor import AuditorAgent
from agents.remediation import RemediationAgent
from agents.validation import ValidationAgent

class AgentOrchestrator:
    """
    Coordinates the multi-agent 'Security Squad' framework and the Agentic Loop.
    """
    def __init__(self, target_dir: str):
        print("[Orchestrator] Initializing VibeSentinel Security Squad...")
        self.target_dir = target_dir
        self.llm = LocalLLMClient()
        self.db = ChromaDBManager()
        
        # Load the Squad
        self.scout = ScoutAgent(self.target_dir, self.llm, self.db)
        self.threat_modeler = ThreatModelerAgent(self.llm, self.db, config_path="Anthropic-Cybersecurity-Skills/index.json")
        self.auditor = AuditorAgent(self.llm, self.db)
        self.remediator = RemediationAgent(self.llm, self.db)
        self.validator = ValidationAgent(self.llm, self.db)

    def run_squad(self) -> Dict[str, Any]:
        """
        Executes the Agentic Loop sequentially.
        """
        print("[Orchestrator] Starting Agentic Loop.")
        
        context = {}
        
        # 1. Scout parses the codebase
        context = self.scout.act(context)
        
        # 2. Threat Modeler hypothesizes attacks
        context = self.threat_modeler.act(context)
        
        # 3. Auditor verifies specific flaws
        context = self.auditor.act(context)
        
        # 4. Remediation suggests patches
        context = self.remediator.act(context)
        
        # 5. Validation tests patches in a sandbox
        context = self.validator.act(context)
        
        self.save_results(context)
        return context

    def save_results(self, context: Dict[str, Any]):
        """
        Saves the validation results for the HITL Dashboard to read.
        """
        results_file = "dashboard/results.json"
        
        patches = context.get("verified_patches", [])
        issues = context.get("identified_issues", [])

        output = {
            "summary": {
                "issues_found": len(issues),
                "patches_generated": len(patches)
            },
            "patches": patches
        }

        try:
            with open(results_file, "w") as f:
                json.dump(output, f, indent=4)
            print(f"[Orchestrator] Results saved to {results_file}. Dashboard ready.")
        except Exception as e:
            print(f"[Orchestrator] Failed to save results: {e}")

if __name__ == "__main__":
    orchestrator = AgentOrchestrator(".")
    orchestrator.run_squad()
