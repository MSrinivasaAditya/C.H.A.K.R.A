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

def run_remediate(confirmed_findings: list, scout_output: dict, source_code: str, llm_client) -> list:
    """
    Takes confirmed findings, relies on the LLMClient for formatting an exact 4-metric schema,
    binds fingerprint attributes natively based on AST/Source bindings, and excludes dismissed objects implicitly via the StateManager.
    """
    if not confirmed_findings:
        return []
        
    n_findings = len(confirmed_findings)
    system_prompt = (
        "You are an expert application security engineer. "
        f"Here are {n_findings} findings, return a JSON array of {n_findings} enriched findings.\n"
        "Your task is to enrich EVERY finding in the provided JSON array with exactly four new fields:\n"
        "1. 'explanation': Two to three sentences. Explain what is wrong, why it is dangerous, and what class of attacker exploits this.\n"
        "2. 'attack_scenario': One concrete paragraph starting with 'An attacker could send...'. Detail a specific hypothetical attack showing what they send, what they get back, and what damage they cause. No abstractions.\n"
        "3. 'fix_diff': A JSON object containing exactly two keys: 'original_lines' (the vulnerable code exactly as it appears in the file) and 'fixed_lines' (the minimal replacement that resolves the vulnerability without changing surrounding logic, preserving exact indentation).\n"
        "4. 'future_guidance': One to two sentences answering: 'If this developer's roadmap requires extending this code, what is the safe way to do it without reintroducing the vulnerability?'\n"
        "\n"
        "Return the EXACT same JSON array provided, modified to include these four fields for each finding. "
        "Do not alter existing IDs or structure. Respond only with valid JSON. No preamble, no markdown fences, no explanation outside the JSON structure."
    )
    
    user_context = {
        "file_summary": scout_output.get("structure_summary", ""),
        "findings_to_enrich": confirmed_findings,
        "source_code_context": source_code
    }
    
    user_prompt = f"Please enrich these findings:\n{json.dumps(user_context, indent=2)}\n\n"
    
    try:
        enriched_response = llm_client.complete(system_prompt, user_prompt, expect_json=True)
    except Exception as e:
        logger.error(f"Failed to reach LLM during remediation phase: {e}")
        return []
        
    if not isinstance(enriched_response, list):
        if isinstance(enriched_response, dict) and "error" in enriched_response:
            logger.warning(f"LLM Client encountered an error: {enriched_response['error']}")
        else:
            logger.warning("LLM returned malformed structure during remediate batch, expected an array.")
        return []

    # Map state manager explicitly natively since it's just Python bindings to Local DB
    db = StateManager()
    final_findings = []
    
    lines = source_code.split("\n")
    
    for finding in enriched_response:
        line_num = finding.get("line_number", 0)
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
        if not db.is_dismissed(fingerprint):
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
