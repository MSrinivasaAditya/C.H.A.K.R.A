import os
import sys
import json
import logging
import hashlib

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from db.state_manager import StateManager

logger = logging.getLogger(__name__)

def _generate_fingerprint(filepath: str, cwe_id: str, original_line: str) -> str:
    """ Computes the unique deterministic hash for tracking dismissal across sessions. """
    norm_path = filepath.replace("\\", "/").lower()
    line_stripped = original_line.strip()
    payload = f"{norm_path}{cwe_id}{line_stripped}"
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()

def normalize_finding(f):
    f["severity"] = str(f.get("severity") or f.get("chakra_severity") or "LOW").upper()
    f["cwe"] = str(f.get("cwe") or f.get("cwe_id") or "CWE-UNKNOWN")
    f["message"] = str(f.get("message") or f.get("description") or "Security finding detected")
    f["line"] = int(f.get("line") or f.get("line_number") or 0)
    return f

def run_remediate(confirmed_findings: list, scout_output: dict, source_code: str, llm_client, state_manager=None) -> list:
    """
    Takes confirmed findings, relies on the LLMClient for formatting an exact 4-metric schema,
    binds fingerprint attributes natively based on AST/Source bindings, and excludes dismissed objects implicitly via the StateManager.
    """
    if not confirmed_findings:
        return []
        
    system_prompt = (
        "You are an expert application security engineer. "
        "Return a JSON object with exactly these keys in this order:\n"
        "1. \"explanation\" - two sentences: what is wrong and why it is dangerous\n"
        "2. \"attack_scenario\" - one sentence starting with \"An attacker can\"\n"
        "3. \"fix_diff\" - object with \"original_lines\" and \"fixed_lines\"\n"
        "4. \"future_guidance\" - one sentence starting with \"If your roadmap requires\"\n"
        "Respond only with valid JSON. No preamble, no markdown fences, no explanation outside the JSON structure."
    )
    
    def build_prompt_for_one(finding):
        user_context = {
            "file_summary": scout_output.get("structure_summary", ""),
            "finding_to_enrich": finding,
            "source_code_context": source_code
        }
        return f"Please enrich this finding:\n{json.dumps(user_context, indent=2)}\n\n"

    enriched_response = []
    for finding in confirmed_findings:
        try:
            # attempt LLM enrichment
            result = llm_client.complete(system_prompt, build_prompt_for_one(finding), expect_json=True)
            if isinstance(result, dict) and result.get("explanation"):
                finding.update(result)
            else:
                raise ValueError("LLM returned empty or invalid result")
        except Exception as e:
            logger.error(f"Failed to reach LLM during remediation phase: {e}")
            # ALWAYS use placeholders on failure — never drop the finding
            finding["explanation"] = finding.get("explanation") or "Manual review required."
            finding["attack_scenario"] = finding.get("attack_scenario") or "An attacker can exploit this vulnerability to gain unauthorized access."
            finding["fix_diff"] = finding.get("fix_diff") or {"original_lines": finding.get("snippet",""), "fixed_lines": "# Apply security fix here"}
            finding["future_guidance"] = finding.get("future_guidance") or "If your roadmap requires extending this code, consult security documentation for this CWE."
            
        enriched_response.append(finding)

    final_findings = []
    
    lines = source_code.split("\n")
    
    for finding in enriched_response:
        finding = normalize_finding(finding)
        line_num = finding.get("line_number", finding.get("line", 0))
        cwe_id = finding.get("cwe", "CWE-Unknown")
        filepath = finding.get("path") or scout_output.get("filepath") or scout_output.get("file") or "unknown_file.py"
        
        # Scrape original line mapping via line boundaries 
        original_line = ""
        if 1 <= line_num <= len(lines):
            original_line = lines[line_num - 1]
        else:
            original_line = finding.get("snippet", "")
            
        fingerprint = _generate_fingerprint(filepath, cwe_id, original_line)
        finding["dismissal_fingerprint"] = fingerprint
        
        # Validation of existing dismissals 
        if state_manager is None or not state_manager.is_dismissed(fingerprint):
            final_findings.append(finding)
    
    logger.info(f"[DEBUG] Remediate stage: {len(enriched_response)} enriched findings in, {len(final_findings)} after dismissal filter")
    return final_findings

if __name__ == "__main__":
    from stage_scout import run_scout
    from stage_audit import run_audit
    from llm.llm_client import LLMClient
    
    demo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "demo", "chakra_demo_app.py")
    if os.path.exists(demo_path):
        with open(demo_path, "r", encoding="utf-8") as f:
            code = f.read()
            
        print("Running Scout Stage...")
        scout_res = run_scout(code, demo_path)
        
        print("Running Audit Stage...")
        audit_res = run_audit(scout_res, code, demo_path)
        
        print("Running Remediate Stage...")
        llm = LLMClient()
        final_res = run_remediate(audit_res, scout_res, code, llm)
        
        print("FINAL REMEDIATED EXPORT:")
        print(json.dumps(final_res, indent=2))
    else:
        print("Test file not found.")
