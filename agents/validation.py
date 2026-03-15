from typing import Any, Dict, List
from agents.base import BaseAgent
from core.llm_client import LocalLLMClient
from core.db_manager import ChromaDBManager
from sandbox.docker_runner import DockerSandboxRunner

class ValidationAgent(BaseAgent):
    """
    Validates patches structurally before sending them to the HITL dashboard.
    Uses 'docker' sandbox to confirm the fix doesn't break basic syntax.
    """
    def __init__(self, llm_client: LocalLLMClient, db_manager: ChromaDBManager):
        super().__init__(llm_client, db_manager)
        self.sandbox = DockerSandboxRunner()

    def act(self, context: Dict[str, Any]) -> Dict[str, Any]:
        print("[Validation] Starting patch verification...")
        patches = context.get("generated_patches", [])
        verified_patches = []

        if not patches:
            print("[Validation] No patches found.")
            return context

        print(f"[Validation] Verifying {len(patches)} patches in Air-gapped Sandbox...")

        for patch in patches:
            file_name = patch.get("target_file")
            fixed_code = patch.get("fixed_code")
            original_code = patch.get("original_code")
            print(f"[Validation] -> Validating {file_name}")

            import re
            safety_pattern = re.compile(r"(os\.system|subprocess|eval\s*\(|exec\s*\(|child_process|require\s*\(\s*['\"]child_process['\"]\s*\))")
            if safety_pattern.search(fixed_code):
                print(f"[Validation] -> Check FAILED. Safety filter triggered on generated patch. Rejected.")
                patch["passed_validation"] = False
                verified_patches.append(patch)
                continue

            try:
                # To do robust verification, apply the modified block to the whole file
                with open(file_name, "r", encoding="utf-8") as f:
                    full_content = f.read()
                patched_full_content = full_content.replace(original_code, fixed_code)
            except Exception as e:
                print(f"[Validation] -> Could not read {file_name} for patching: {e}")
                patched_full_content = fixed_code # Fallback

            # Basic Validation: Verify the Python syntax using Docker
            # (In production: Replace with full unit test suite execution)
            success = self.sandbox.run_validation(script_content=patched_full_content, file_name=file_name)
            
            patch["passed_validation"] = success
            if success:
                 print(f"[Validation] -> Check PASSED.")
                 verified_patches.append(patch)
            else:
                 print(f"[Validation] -> Check FAILED. Will require manual review.")
                 verified_patches.append(patch)

        context["verified_patches"] = verified_patches
        print(f"[Validation] Finished validation phase. Processed {len(verified_patches)} patches.")
        return context
