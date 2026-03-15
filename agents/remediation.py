from typing import Any, Dict, List
from agents.base import BaseAgent
from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager

class RemediationAgent(BaseAgent):
    """
    Generates git-diff like patches based on the issues found by the Auditor.
    """
    def __init__(self, llm_client: LocalLLMClient, db_manager: ChromaDBManager):
        super().__init__(llm_client, db_manager)

    def act(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes identified issues and generates a patch using the LLM.
        """
        print("[Remediation] Starting patch generation...")
        issues = context.get("identified_issues", [])
        patches = []

        if not issues:
            print("[Remediation] No issues to fix.")
            return context

        print(f"[Remediation] Generating fixes for {len(issues)} issues...")

        for issue in issues:
            target_file = issue.get("target_file")
            skill_name = issue.get("skill_name")
            reasoning = issue.get("reasoning")
            code_snippet = issue.get("code_snippet")

            prompt = f"""
            You are a senior security engineer. Fix the following code to mitigate the vulnerability identified below.
            
            Return ONLY the modified code block. Do NOT include any conversational text. Keep the exact same indentation.
            
            Vulnerability: {skill_name}
            Audit Notes: {reasoning}
            
            Original Code:
            {code_snippet}
            """

            print(f"[Remediation] Requesting patch for {target_file} ({skill_name})...")
            
            response = self.llm.generate(prompt=prompt)
            print(f"[Remediation] -> Patch generated.")

            patches.append({
                "target_file": target_file,
                "skill_name": skill_name,
                "original_code": code_snippet,
                "fixed_code": response,
                "audit_notes": reasoning
            })

        context["generated_patches"] = patches
        print(f"[Remediation] Finished generating {len(patches)} patches.")
        return context
