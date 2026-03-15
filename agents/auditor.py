from typing import Any, Dict, List
from agents.base import BaseAgent
from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager

class AuditorAgent(BaseAgent):
    """
    Scans the actual code against hypothesized threat vectors.
    """
    def __init__(self, llm_client: LocalLLMClient, db_manager: ChromaDBManager):
        super().__init__(llm_client, db_manager)

    def act(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the tasks prepared by the Threat Modeler.
        Logs any findings into a list of issues.
        """
        print("[Auditor] Beginning audit phase...")
        tasks = context.get("audit_tasks", [])
        issues = []

        if not tasks:
            print("[Auditor] No audit tasks found.")
            return context

        print(f"[Auditor] Processing {len(tasks)} validation tasks...")

        for task in tasks:
            skill = task.get("skill")
            target_file = task.get("target_file")
            code = task.get("code")

            skill_name = skill.get("name")
            description = skill.get("description", "")
            
            # Construct a prompt for the specific skill since Anthropic skills don't have predefined prompts
            prompt = f"You are a professional security auditor. Review the following code snippet for vulnerabilities related to the skill: '{skill_name}'.\nSkill Description: {description}\nAnalyze the code closely. If you find any issue, explain the vulnerability starting with the word 'Vulnerability'. If the code is completely safe, simply respond with 'Safe'.\n\nCode:\n{code}"

            print(f"[Auditor] Inspecting {target_file} for {skill_name}...")
            
            # Send to local LLM
            response = self.llm.generate(prompt=prompt)
            print(f"[Auditor] Got response for {skill_name} on {target_file}")
            
            # Very basic heuristic: if the model says 'vulnerability found', we flag it.
            # In a real scenario, the LLM prompt should return structural JSON (e.g. valid: false)
            if "vulnerability" in response.lower() or "hardcoded" in response.lower() or "suggest" in response.lower():
                print(f"[Auditor] -> Issue identified! {skill_name} in {target_file}")
                issues.append({
                    "skill_name": skill_name,
                    "target_file": target_file,
                    "code_snippet": code,
                    "reasoning": response
                })

        context["identified_issues"] = issues
        print(f"[Auditor] Finished audit. Found {len(issues)} issues.")
        return context
