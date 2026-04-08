import os
import sys
import json
import logging
import threading
import subprocess
import tempfile

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from llm.llm_client import LLMClient

logger = logging.getLogger(__name__)

SEMGREP_LOCK = threading.Lock()

SCOUT_CWE_MAP = {
    "sql_string_concat": "CWE-89",
    "exec_call": "CWE-94",
    "eval_call": "CWE-94",
    "subprocess_call": "CWE-78",
    "pickle_load": "CWE-502",
    "hardcoded_string_credential": "CWE-798",
    "md5_hash": "CWE-327",
    "insecure_random": "CWE-330"
}

def _run_semgrep(filepath: str, source_code: str) -> list:
    """Runs Semgrep natively with an atomic lock binding to limit resource scaling issues.
    
    Writes source_code to a temp file on disk because Semgrep cannot scan
    strings passed via stdin in --json mode. The temp file preserves the .py
    extension so Semgrep's language detection works correctly.
    """
    with SEMGREP_LOCK:
        tmp_fd = None
        tmp_path = None
        try:
            # Write source to a real temp file — Semgrep needs a path on disk
            suffix = os.path.splitext(filepath)[1] or ".py"
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="chakra_scan_")
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_f:
                tmp_f.write(source_code)
            tmp_fd = None  # fd is now closed by os.fdopen

            result = subprocess.run(
                ["semgrep", "--config", "p/python", tmp_path, "--json", "--no-git-ignore", "--disable-version-check"],
                capture_output=True,
                text=True
            )
            # 0=ok, 1=finding. Anything else indicates Semgrep threw an unrecoverable exception
            if result.returncode not in (0, 1):
                logger.warning(f"Semgrep returned unexpected exit code {result.returncode}. Output: {result.stderr}")
                return []
                
            data = json.loads(result.stdout)
            results = data.get("results", [])
            logger.info(f"[DEBUG] Semgrep raw output: {len(results)} results for {filepath}")
            logger.info(f"[DEBUG] Semgrep raw JSON: {json.dumps(data, indent=2)[:2000]}")
            return results
            
        except FileNotFoundError:
            logger.warning("Semgrep executable not found. Falling back to Scout only.")
            return []
        except Exception as e:
            logger.warning(f"Failed to run semgrep: {e}")
            return []
        finally:
            # Clean up temp file
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

def _extract_cwe_from_semgrep(sg: dict) -> str:
    metadata = sg.get("extra", {}).get("metadata", {})
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and len(cwe) > 0:
        return str(cwe[0])
    if isinstance(cwe, str):
        return cwe
    return "CWE-Unknown"

def _map_semgrep_severity(sg: dict) -> str:
    sev = sg.get("extra", {}).get("severity", "INFO").upper()
    if sev == "ERROR": return "HIGH"
    elif sev == "WARNING": return "MEDIUM"
    return "LOW"

def _get_abstract_type(chk: str) -> str:
    """Rough logical mapping so line number collisions match semgrep findings with scout findings properly."""
    chk = chk.lower()
    if "sql" in chk: return "sql"
    if "exec" in chk or "eval" in chk or "subprocess" in chk or "popen" in chk or "command" in chk: return "exec"
    if "pickle" in chk or "deserialize" in chk or "load" in chk: return "deserialization"
    if "hardcode" in chk or "secret" in chk or "credential" in chk or "token" in chk: return "secret"
    if "md5" in chk or "hash" in chk: return "hash"
    if "random" in chk: return "random"
    return chk

def run_audit(scout_output: dict, source_code: str, filepath: str) -> list:
    """
    1. Runs Semgrep safely using a lock.
    2. Combines with Scout patterns.
    3. Deduplicates by line number + abstract pattern type.
    4. Slices to top 5 prioritized findings.
    5. Calls LLM with batch payload to approve/reject.
    6. Returns verified list with line_number, cwe, and severity.
    """
    
    raw_semgrep = _run_semgrep(filepath, source_code)
    scout_patterns = scout_output.get("dangerous_patterns", [])
    
    combined = []
    
    # Translate Semgrep payload
    for sg in raw_semgrep:
        line_num = sg.get("start", {}).get("line", 0)
        cwe = _extract_cwe_from_semgrep(sg)
        sev = _map_semgrep_severity(sg)
        check_id = sg.get("check_id", "unknown")
        
        combined.append({
            "source": "semgrep",
            "check_id": check_id,
            "abstract_type": _get_abstract_type(check_id),
            "line_number": line_num,
            "severity": sev,
            "cwe": cwe,
            "message": sg.get("extra", {}).get("message", ""),
            "snippet": sg.get("extra", {}).get("lines", "").strip()
        })
        
    # Translate Scout payload
    for sp in scout_patterns:
        ptype = sp.get("pattern_type", "unknown")
        line_num = sp.get("line_number", 0)
        
        combined.append({
            "source": "scout",
            "check_id": ptype,
            "abstract_type": _get_abstract_type(ptype),
            "line_number": line_num,
            "severity": "LOW",  
            "cwe": SCOUT_CWE_MAP.get(ptype, "CWE-Unknown"),
            "message": f"Structural detection of {ptype}",
            "snippet": sp.get("source_snippet", "")
        })
        
    # Deduplicate via line bounds and mapped overlap types
    dedup_map = {}
    for f in combined:
        key = (f["line_number"], f["abstract_type"])
        if key not in dedup_map:
            dedup_map[key] = []
        dedup_map[key].append(f)
        
    unique_findings = []
    for key, items in dedup_map.items():
        # Instruction dictates preferring Semgrep's metadata representation naturally over Scout
        items.sort(key=lambda x: 1 if x["source"] == "semgrep" else 0, reverse=True)
        unique_findings.append(items[0])
        
    # Priority sorting logic: High > Low; Semgrep > Scout
    def sort_rank(f):
        score = 0
        if f["severity"] == "HIGH": score += 30
        elif f["severity"] == "MEDIUM": score += 20
        elif f["severity"] == "LOW": score += 10
        
        if f["source"] == "semgrep": score += 5
        return score
        
    unique_findings.sort(key=sort_rank, reverse=True)
    batched_findings = unique_findings[:5] # Enforced batch size limits
    
    if not batched_findings:
        return []
        
    # Scrub abstract parameters to preserve LLM token context limits
    for bf in batched_findings:
        bf.pop("abstract_type", None)
        
    llm = LLMClient()
    system_prompt = (
        "You are a senior security auditor reviewing preliminary findings from static analysis tools. "
        "Your job is to determine if each finding is a real vulnerability in context, or a false positive. "
        "A hardcoded string that is clearly a configuration key name but not a password should be marked as a false positive. "
        "Return the EXACT same JSON array of findings provided, but with a new boolean field 'confirmed' added to every object. "
        "Do not change existing fields."
    )
    
    user_context = {
        "file_summary": scout_output.get("structure_summary", ""),
        "imports": scout_output.get("imports", []),
        "findings_to_review": batched_findings
    }
    
    user_prompt = f"Review these findings:\n{json.dumps(user_context, indent=2)}\n\n"
    
    try:
        # Pushes exactly out to the updated 2.3 LLM Client specification with built-in format guards
        llm_response = llm.complete(system_prompt, user_prompt, expect_json=True)
    except Exception as e:
        logger.error(f"Failed to reach LLM during audit phase: {e}")
        return []

    verified_findings = []
    
    logger.info(f"[DEBUG] LLM raw response type: {type(llm_response).__name__}, content preview: {json.dumps(llm_response, default=str)[:1000]}")
    
    # Re-iterate array structures from LLM back into native application bounds, filtering False Positives
    if isinstance(llm_response, list):
        for f in llm_response:
            if f.get("confirmed") is True:
                verified_findings.append({
                    "line_number": f.get("line_number"),
                    "cwe": f.get("cwe", "CWE-Unknown"),
                    "severity": f.get("severity", "LOW"),
                    "check_id": f.get("check_id"),
                    "snippet": f.get("snippet", ""),
                    "message": f.get("message", "")
                })
    elif isinstance(llm_response, dict) and "error" in llm_response:
        logger.warning(f"LLM Client encountered an error: {llm_response['error']}")
        return []
    
    logger.info(f"[DEBUG] Audit stage: {len(batched_findings)} findings sent to LLM, {len(verified_findings)} confirmed after filter")
    return verified_findings

if __name__ == "__main__":
    from stage_scout import run_scout
    demo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "demo", "chakra_demo_app.py")
    if os.path.exists(demo_path):
        with open(demo_path, "r", encoding="utf-8") as f:
            code = f.read()
            
        print("Running Scout Stage...")
        scout_res = run_scout(code, demo_path)
        
        print(f"Running LLM Audit Deduplication Engine ...")
        audit_res = run_audit(scout_res, code, demo_path)
        print("FINAL VERIFIED FINDINGS EXPORT:")
        print(json.dumps(audit_res, indent=2))
    else:
        print("Test file not found.")
