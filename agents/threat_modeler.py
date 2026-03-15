from typing import Any, Dict, List
from agents.base import BaseAgent
from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager
import re
import json

class ThreatModelerAgent(BaseAgent):
    """
    Analyzes the mapped files to hypothesize potential attack vectors.
    Uses the Anthropic Cybersecurity Skills registry.
    """
    def __init__(self, llm_client: LocalLLMClient, db_manager: ChromaDBManager, config_path: str = "Anthropic-Cybersecurity-Skills/index.json"):
        super().__init__(llm_client, db_manager)
        self.config_path = config_path
        self._load_skills()

    def _load_skills(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            all_skills = data.get("skills", [])
            relevant_skills = []
            
            # Filter the 600+ skills down to those relevant to code auditing/python/web apps
            for s in all_skills:
                tags = [t.lower() for t in s.get("tags", [])]
                subdomain = s.get("subdomain", "").lower()
                
                if "python" in tags or "code-review" in tags or "web-application-security" in subdomain or "api-security" in subdomain or "injection" in tags:
                    relevant_skills.append(s)
            
            # Limit to 10 to keep the LLM fast and responsive during the demo
            if len(relevant_skills) > 10:
                relevant_skills = relevant_skills[:10]
            elif not relevant_skills:
                relevant_skills = all_skills[:5]

            self.config = {"skills": relevant_skills}
            print(f"[Threat Modeler] Loaded {len(relevant_skills)} relevant skills from Anthropic repository.")
        except Exception as e:
            print(f"Failed to parse or find {self.config_path}: {e}")
            self.config = {"skills": []}

    def act(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Loads the list of mapped files, and identifies relevant 'files' to check 
        for specific vulnerabilities.
        """
        print("[Threat Modeler] Starting vector hypothesizing...")
        skills = self.config.get("skills", [])
        
        # We will create a list of tasks for the Auditor
        audit_tasks = []

        mapped_files = context.get("mapped_files", [])

        if not mapped_files:
            print("[Threat Modeler] No files were mapped by Scout.")
            return context

        print(f"[Threat Modeler] Assessing {len(mapped_files)} files against {len(skills)} skills.")

        for skill in skills:
            skill_name = skill.get("name")
            print(f"[Threat Modeler] Selecting targets for skill: {skill_name}")
            
            # Simple heuristic: we retrieve the top K chunks most relevant to the skill's description
            # This represents hybrid deterministic + LLM semantic searching
            description = skill.get("description", "")
            
            # Search ChromaDB
            results = self.db.search_similar(query=description, n_results=5)
            
            for result in results:
                target_file = result.get("metadata", {}).get("file")
                code = result.get("code")
                chunk_id = result.get("id")

                if target_file not in mapped_files:
                    continue

                audit_tasks.append({
                    "skill": skill,
                    "target_file": target_file,
                    "chunk_id": chunk_id,
                    "code": code
                })
                print(f"[Threat Modeler] -> Queued {target_file} for {skill_name}")

        context["audit_tasks"] = audit_tasks
        print(f"[Threat Modeler] Finished generating {len(audit_tasks)} audit tasks.")
        return context
