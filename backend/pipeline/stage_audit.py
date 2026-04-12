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

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'rules', 'chakra_rules.yaml')
RULES_PATH = os.path.normpath(RULES_PATH)

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

CWE_SEVERITY = {
    "CWE-89": "HIGH",
    "CWE-78": "HIGH",
    "CWE-798": "HIGH",
    "CWE-502": "HIGH",
    "CWE-95": "HIGH",
    "CWE-22": "HIGH",
    "CWE-328": "MEDIUM",
    "CWE-338": "MEDIUM"
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "ERROR": 0, "WARNING": 1, "INFO": 2}

def safe_severity_key(finding):
    sev = finding.get("severity") or finding.get("chakra_severity") or "LOW"
    if isinstance(sev, int):
        return sev
    return SEVERITY_ORDER.get(str(sev).upper(), 99)

def normalize_finding(f):
    f["severity"] = str(f.get("severity") or f.get("chakra_severity") or "LOW").upper()
    f["cwe"] = str(f.get("cwe") or f.get("cwe_id") or "CWE-UNKNOWN")
    f["message"] = str(f.get("message") or f.get("description") or "Security finding detected")
    f["line"] = int(f.get("line") or f.get("line_number") or 0)
    return f

def _run_semgrep(filepath: str, source_code: str) -> list:
    """Runs Semgrep natively with an atomic lock binding to limit resource scaling issues.
    
    Writes source_code to a temp file on disk because Semgrep cannot scan
    strings passed via stdin in --json mode. The temp file preserves the .py
    extension so Semgrep's language detection works correctly.
    """
    print(f"DEBUG: _run_semgrep called — source_code length = {len(source_code)}", flush=True)
    print(f"DEBUG: filepath = {filepath}", flush=True)
    print(f"DEBUG: rules_path = {RULES_PATH}", flush=True)

    with SEMGREP_LOCK:
        tmp_fd = None
        tmp_path = None
        try:
            # Write source to a real temp file — Semgrep needs a path on disk
            suffix = os.path.splitext(filepath)[1] or ".py"
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="chakra_scan_")
            print(f"DEBUG: Created temp file at {tmp_path}", flush=True)

            with os.fdopen(tmp_fd, "w", encoding="utf-8") as tmp_f:
                tmp_f.write(source_code)
            tmp_fd = None  # fd is now closed by os.fdopen
            print(f"DEBUG: Wrote {len(source_code)} bytes to temp file", flush=True)

            # Verify file has content
            with open(tmp_path, "r", encoding="utf-8") as _vf:
                _content = _vf.read()
            print(f"DEBUG: Temp file contains {len(_content)} bytes after write", flush=True)

            result = subprocess.run(
                ["semgrep", "--config", RULES_PATH, tmp_path, "--json", "--no-git-ignore", "--disable-version-check"],
                capture_output=True,
                text=True
            )
            print(f"DEBUG: Semgrep exit code = {result.returncode}", flush=True)
            # 0=ok, 1=finding. Anything else indicates Semgrep threw an unrecoverable exception
            if result.returncode not in (0, 1):
                logger.warning(f"Semgrep returned unexpected exit code {result.returncode}. Output: {result.stderr}")
                print(f"DEBUG: Semgrep stderr = {result.stderr[:500]}", flush=True)
                return []
                
            data = json.loads(result.stdout)
            results = data.get("results", [])
            logger.info(f"[DEBUG] Semgrep raw output: {len(results)} results for {filepath}")
            logger.info(f"[DEBUG] Semgrep raw JSON: {json.dumps(data, indent=2)[:2000]}")
            print(f"DEBUG: Semgrep returned {len(results)} results", flush=True)
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
    """Maps Semgrep severity (ERROR/WARNING/INFO) to CHAKRA severity (HIGH/MEDIUM/LOW).
    Always returns a string — never a number."""
    chakra_sev = sg.get("extra", {}).get("metadata", {}).get("chakra_severity")
    if chakra_sev:
        return str(chakra_sev).upper()
        
    raw = sg.get("extra", {}).get("severity", "INFO")
    sev = str(raw).upper()
    if sev == "ERROR": return "HIGH"
    if sev == "WARNING": return "MEDIUM"
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
        
        is_chakra_high = str(sg.get("extra", {}).get("metadata", {}).get("chakra_severity", "")).upper() == "HIGH"
        
        combined.append({
            "source": "semgrep",
            "check_id": check_id,
            "abstract_type": _get_abstract_type(check_id),
            "line_number": line_num,
            "severity": str(sev).upper(),
            "cwe": cwe,
            "message": sg.get("extra", {}).get("message", ""),
            "snippet": sg.get("extra", {}).get("lines", "").strip(),
            "_high_confidence": is_chakra_high
        })
        
    # Translate Scout payload
    for sp in scout_patterns:
        ptype = sp.get("pattern_type", "unknown")
        line_num = sp.get("line_number", 0)
        cwe_val = SCOUT_CWE_MAP.get(ptype, "CWE-Unknown")
        
        combined.append({
            "source": "scout",
            "check_id": ptype,
            "abstract_type": _get_abstract_type(ptype),
            "line_number": line_num,
            "severity": CWE_SEVERITY.get(cwe_val, "MEDIUM"),  
            "cwe": cwe_val,
            "message": f"Structural detection of {ptype}",
            "snippet": sp.get("source_snippet", ""),
            "_high_confidence": ptype in ["hardcoded_string_credential", "eval_call", "exec_call", "pickle_load"]
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
        items.sort(key=safe_severity_key)
        unique_findings.append(items[0])
        
    unique_findings.sort(key=safe_severity_key)
    batched_findings = unique_findings[:5] # Enforced batch size limits
    
    if not batched_findings:
        return []
        
    needs_llm = []
    verified_findings = []
    
    # Scrub abstract parameters to preserve LLM token context limits
    # and separate high confidence findings from ones that need LLM verification
    for bf in batched_findings:
        bf.pop("abstract_type", None)
        is_high_conf = bf.pop("_high_confidence", False)
        if is_high_conf:
            verified_findings.append({
                "line_number": bf.get("line_number"),
                "cwe": bf.get("cwe", "CWE-Unknown"),
                "severity": str(bf.get("severity", "LOW")).upper(),
                "check_id": bf.get("check_id"),
                "snippet": bf.get("snippet", ""),
                "message": bf.get("message", "")
            })
        else:
            needs_llm.append(bf)
            
    if needs_llm:
        llm = LLMClient()
        system_prompt = (
            "You are a security auditor reviewing preliminary findings.\n"
            "Your job is to confirm whether each finding is a REAL vulnerability.\n"
            "Be PERMISSIVE — when in doubt, confirm the finding.\n"
            "Only mark confirmed=false if you are certain it is a false positive.\n"
            "A hardcoded password string is ALWAYS a real finding. Never reject it.\n"
            "An eval() call is ALWAYS a real finding. Never reject it.\n"
            "A pickle.loads() call is ALWAYS a real finding. Never reject it.\n"
            "Return only a JSON array. No other text."
        )
        
        user_context = {
            "file_summary": scout_output.get("structure_summary", ""),
            "imports": scout_output.get("imports", []),
            "findings_to_review": needs_llm
        }
        
        user_prompt = f"Review these findings:\n{json.dumps(user_context, indent=2)}\n\n"
        
        try:
            # Pushes exactly out to the updated 2.3 LLM Client specification with built-in format guards
            llm_response = llm.complete(system_prompt, user_prompt, expect_json=True)
        except Exception as e:
            logger.error(f"Failed to reach LLM during audit phase: {e}")
            llm_response = []
            
        logger.info(f"[DEBUG] LLM raw response type: {type(llm_response).__name__}, content preview: {json.dumps(llm_response, default=str)[:1000]}")
        
        if isinstance(llm_response, dict) and "error" in llm_response:
            logger.warning(f"LLM Client encountered an error: {llm_response['error']}")
            llm_response = []
            
        if not isinstance(llm_response, list):
            llm_response = []
            
        # Never return more confirmed findings than were sent
        confirmed = [f for f in llm_response if f.get("confirmed") == True]
        confirmed = confirmed[:len(needs_llm)]
        
        if len(confirmed) == 0:
            # LLM filter failed — confirm all findings by default
            for f in needs_llm:
                f["confirmed"] = True
            confirmed = needs_llm
            
        for f in confirmed:
            verified_findings.append({
                "line_number": f.get("line_number"),
                "cwe": f.get("cwe", "CWE-Unknown"),
                "severity": str(f.get("severity", "LOW")).upper(),
                "check_id": f.get("check_id"),
                "snippet": f.get("snippet", ""),
                "message": f.get("message", "")
            })
            
    simplified_findings = []
    for f in verified_findings:
        simplified_findings.append(normalize_finding(f))
    verified_findings = simplified_findings
    
    # Sort verified findings by severity for consistency
    verified_findings.sort(key=safe_severity_key)
    logger.info(f"[DEBUG] Audit stage: {len(needs_llm)} findings sent to LLM, {len(verified_findings)} confirmed after filter")
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
