import os
import time
import json
import logging
import threading
import queue
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List
from dotenv import load_dotenv
import traceback

from db.state_manager import StateManager
from delta import compute_fingerprints, compute_changed_range
from pipeline.stage_scout import run_scout
from pipeline.stage_audit import run_audit
from pipeline.stage_remediate import run_remediate
from llm.llm_client import LLMClient

load_dotenv()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Log rotation & file-based logging setup
# ---------------------------------------------------------------------------

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'chakra.log')
LOG_PATH = os.path.normpath(LOG_PATH)

LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB


class _ChakraFormatter(logging.Formatter):
    """Emits lines in the format: [ISO-8601] [LEVEL] [dev_id] message"""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        dev = getattr(record, "dev_id", "-")
        return f"[{ts}] [{record.levelname}] [{dev}] {record.getMessage()}"


def setup_logging() -> None:
    """Configure file-only logging with log rotation (>10 MB → chakra.log.1)."""
    # Rotate if oversized
    if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > LOG_MAX_BYTES:
        rotated = LOG_PATH + ".1"
        try:
            if os.path.exists(rotated):
                os.remove(rotated)
            os.rename(LOG_PATH, rotated)
        except OSError as exc:
            # Non-fatal — keep writing to the existing file
            print(f"[CHAKRA] Warning: could not rotate log file: {exc}")

    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(_ChakraFormatter())

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Remove any existing handlers (e.g. StreamHandler added by basicConfig)
    root.handlers.clear()
    root.addHandler(file_handler)

# Single global dependencies
llm_client = LLMClient()
state_manager = StateManager()
state_manager.load_all_into_memory()
SCAN_QUEUE = queue.Queue(maxsize=10)

DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "local")
AUTH_TOKEN = os.environ.get("AUTH_TOKEN")
PORT = int(os.environ.get("PORT", "7777"))
DEFAULT_ORG_ID = os.environ.get("DEFAULT_ORG_ID", "default")

# 5.3 Limit map
_rate_limit_counters = {}

def check_rate_limit(dev_id: str) -> bool:
    """Limits individual developers to 10 incoming pipeline requests every 60 seconds."""
    now = time.time()
    if dev_id not in _rate_limit_counters:
        _rate_limit_counters[dev_id] = []
    _rate_limit_counters[dev_id] = [t for t in _rate_limit_counters[dev_id] if now - t < 60]
    if len(_rate_limit_counters[dev_id]) >= 10:
        return False
    _rate_limit_counters[dev_id].append(now)
    return True

def handle_scan(filepath: str, source_code: str, org_id: str, dev_id: str) -> Dict[str, Any]:
    """
    Main entrypoint for the scan handler.
    Returns the JSON 5.4 layout directly to the threaded socket payload queue.

    Source resolution priority:
      1. Inline ``source_code`` — used as-is when non-empty (API / VS Code inline scan).
      2. File on disk (``filepath``) — read only when ``source_code`` is empty
         (file-based scanning that already works correctly).
    """
    filepath = filepath.replace("\\", "/").strip().lower()
    start_time = time.time()

    # ------------------------------------------------------------------
    # Source resolution: inline payload wins; disk is a fallback only
    # when the file actually exists on disk.
    # ------------------------------------------------------------------
    if not source_code and filepath and os.path.exists(filepath):
        logger.info(f"[handle_scan] No inline source; reading from disk: '{filepath}'",
                    extra={"dev_id": dev_id})
        with open(filepath, 'r', encoding='utf-8') as f:
            source_code = f.read()
        logger.info(f"[handle_scan] Read {len(source_code)} chars from '{filepath}'",
                    extra={"dev_id": dev_id})
    elif not source_code:
        logger.warning(f"[handle_scan] No source provided and '{filepath}' does not exist on disk.",
                       extra={"dev_id": dev_id})
        return {"findings": [], "error": "No source code provided and filepath does not exist on disk"}
    else:
        logger.info(f"[handle_scan] Using inline source_code for '{filepath}' "
                    f"({len(source_code)} chars)", extra={"dev_id": dev_id})
    # ------------------------------------------------------------------

    old_fingerprints = state_manager.get_fingerprint(filepath, org_id, dev_id)
    logger.info(f"[handle_scan] get_fingerprint for '{filepath}': {old_fingerprints}", extra={"dev_id": dev_id})
    new_fingerprints = compute_fingerprints(source_code)
    
    if not old_fingerprints:
        scout_output = run_scout(source_code, filepath)
        audit_findings = run_audit(scout_output, source_code, filepath)
        findings = run_remediate(audit_findings, scout_output, source_code, llm_client, state_manager)
        
        print(f"[DEBUG] Saving {len(findings)} findings, first has explanation: {'explanation' in findings[0] if findings else 'N/A'}")
        print(f"[DEBUG] About to save findings: filepath={filepath}, org_id={org_id}, dev_id={dev_id}, count={len(findings)}")
        state_manager.set_findings(filepath, org_id, dev_id, findings)
        print(f"[DEBUG] Findings saved successfully")
        state_manager.set_fingerprint(filepath, org_id, dev_id, new_fingerprints)
        logger.info(f"[handle_scan] set_fingerprint successfully called for '{filepath}' (full scan).", extra={"dev_id": dev_id})
        
        scan_time_ms = int((time.time() - start_time) * 1000)
        state_manager.log_scan(org_id, dev_id, filepath, "file_full", len(findings), scan_time_ms, 0)
        return {
            "findings": findings,
            "scan_time_ms": scan_time_ms,
            "cache_hit": False,
            "changed_lines": None
        }

    changed_range = compute_changed_range(old_fingerprints, new_fingerprints)
    
    if changed_range is None:
        findings = state_manager.get_findings(filepath, org_id, dev_id)
        if findings is None:
            findings = []
            
        scan_time_ms = int((time.time() - start_time) * 1000)
        state_manager.log_scan(org_id, dev_id, filepath, "file_cached", len(findings), scan_time_ms, 1)
        return {
            "findings": findings,
            "scan_time_ms": scan_time_ms,
            "cache_hit": True,
            "changed_lines": None
        }

    start_line, end_line = changed_range
    lines = source_code.split('\n')
    slice_lines = lines[start_line - 1 : end_line]
    slice_source = "\n".join(slice_lines)
    
    scout_output = run_scout(slice_source, filepath)
    audit_findings = run_audit(scout_output, slice_source, filepath)
    new_findings = run_remediate(audit_findings, scout_output, slice_source, llm_client, state_manager)
    
    for nf in new_findings:
        if nf.get("source") == "scout":
            nf["line_number"] += (start_line - 1)
            
    old_findings = state_manager.get_findings(filepath, org_id, dev_id) or []
        
    merged_findings = [f for f in old_findings if not (start_line <= f.get("line_number", 0) <= end_line)]
    merged_findings.extend(new_findings)
        
    print(f"[DEBUG] Saving {len(merged_findings)} findings, first has explanation: {'explanation' in merged_findings[0] if merged_findings else 'N/A'}")
    print(f"[DEBUG] About to save findings: filepath={filepath}, org_id={org_id}, dev_id={dev_id}, count={len(merged_findings)}")
    state_manager.set_findings(filepath, org_id, dev_id, merged_findings)
    print(f"[DEBUG] Findings saved successfully")
    state_manager.set_fingerprint(filepath, org_id, dev_id, new_fingerprints)
    logger.info(f"[handle_scan] set_fingerprint successfully called for '{filepath}' (partial scan).", extra={"dev_id": dev_id})
    
    scan_time_ms = int((time.time() - start_time) * 1000)
    state_manager.log_scan(org_id, dev_id, filepath, "file_partial", len(merged_findings), scan_time_ms, 0)
    return {
        "findings": merged_findings,
        "scan_time_ms": scan_time_ms,
        "cache_hit": False,
        "changed_lines": list(changed_range)
    }

def handle_dismiss(data: dict) -> dict:
    filepath = data.get("filepath", "")
    org_id = data.get("org_id", "default")
    dev_id = data.get("dev_id", "anon")
    # Use dismissal_fingerprint directly if provided
    fingerprint = data.get("dismissal_fingerprint", "")
    if not fingerprint:
        # fallback: recompute from parts
        cwe = data.get("cwe", "unknown")
        original_line_content = data.get("original_line_content", "")
        norm_path = filepath.replace("\\", "/").lower()
        line_stripped = original_line_content.strip()
        payload = f"{norm_path}{cwe}{line_stripped}"
        fingerprint = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    state_manager.add_dismissal(fingerprint, org_id, dev_id, filepath)
    return {"success": True}
    state_manager.add_dismissal(fingerprint, org_id, dev_id, filepath)
    
    return {"success": True}

def process_repo_scan(scan_id: int, repo_url: str, org_id: str, dev_id: str):
    import git
    import tempfile
    
    findings = []
    temp_dir_obj = None
    
    try:
        if repo_url.startswith("https://"):
            temp_dir_obj = tempfile.TemporaryDirectory()
            target_dir = temp_dir_obj.name
            git.Repo.clone_from(repo_url, target_dir)
        else:
            target_dir = repo_url
            
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, target_dir)
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            src = f.read()
                        
                        scout_res = run_scout(src, full_path)
                        audit_res = run_audit(scout_res, src, full_path)
                        local_findings = run_remediate(audit_res, scout_res, src, llm_client, state_manager)
                        
                        for fnd in local_findings:
                            fnd["filepath"] = rel_path
                        findings.extend(local_findings)
                    except Exception as e:
                        logger.error(f"Error processing {full_path} in repo scan: {e}")
                        
        if temp_dir_obj:
            temp_dir_obj.cleanup()

        with state_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE repo_scans 
                SET status=?, findings_json=?, completed_at=?
                WHERE id=?
            ''', ("complete", json.dumps(findings), int(time.time()), scan_id))
            conn.commit()
    except Exception as e:
        logger.error(f"Repo scan {scan_id} failed: {e}")
        with state_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE repo_scans 
                SET status=?, findings_json=?, completed_at=?
                WHERE id=?
            ''', ("failed", json.dumps([{"error": str(e)}]), int(time.time()), scan_id))
            conn.commit()

def handle_repo_scan(data: dict) -> dict:
    repo_url = data.get("repo_url", "")
    org_id = data.get("org_id", "default")
    dev_id = data.get("dev_id", "anon")
    
    with state_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO repo_scans (org_id, repo_url, status, started_at)
            VALUES (?, ?, ?, ?)
        ''', (org_id, repo_url, "running", int(time.time())))
        scan_id = cursor.lastrowid
        conn.commit()
        
    t = threading.Thread(target=process_repo_scan, args=(scan_id, repo_url, org_id, dev_id), daemon=True)
    t.start()
    
    return {"scan_id": scan_id, "status": "pending"}

def scan_worker():
    while True:
        try:
            req_data, response_q = SCAN_QUEUE.get()
            filepath = req_data.get('filepath', '')
            source_code = req_data.get('source_code', '')
            org_id = req_data.get('org_id', 'default')
            dev_id = req_data.get('dev_id', 'anon')
            
            try:
                result_payload = handle_scan(filepath, source_code, org_id, dev_id)
            except Exception as e:
                full_trace = traceback.format_exc()
                print(full_trace)  # prints to terminal
                # also write to chakra.log
                with open("chakra.log", "a") as log:
                    log.write(full_trace + "\n")
                result_payload = {"findings": [{"error": str(e)}], "scan_time_ms": 0, "cache_hit": False, "changed_lines": None}
                
            response_q.put(result_payload)
            SCAN_QUEUE.task_done()
        except Exception as e:
            logger.error(f"Thread worker encountered an unrecoverable crash: {e}")

def cleanup_worker():
    while True:
        time.sleep(3600)
        try:
            state_manager.cleanup_stale_entries()
        except:
            pass

class ChakraHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def check_auth(self):
        if not AUTH_TOKEN: return True
        parsed_path = urlparse(self.path).path
        if parsed_path in ['/dashboard', '/config'] and self.command == 'GET': return True
            
        auth_header = self.headers.get('Authorization')
        if auth_header != f"Bearer {AUTH_TOKEN}":
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return False
        return True

    def do_GET(self):
        if not self.check_auth(): return
        
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        
        if path == '/dashboard':
            dash_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "dashboard.html")
            try:
                with open(dash_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                self.send_response(404)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b"Dashboard not found")
            return
            
        if path.startswith('/scan/repo/status/'):
            scan_id_str = path.split('/')[-1]
            try:
                scan_id = int(scan_id_str)
            except:
                self.send_response(400)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                return

            with state_manager.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status, findings_json FROM repo_scans WHERE id=?", (scan_id,))
                row = cursor.fetchone()
                
            if not row:
                self.send_response(404)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                return
                
            res = {"status": row["status"]}
            if row["status"] == "complete":
                try:
                    res["findings"] = json.loads(row["findings_json"])
                except:
                    res["findings"] = []
                    
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
            return
            
        if path == '/config':
            res = {
                "default_org_id": DEFAULT_ORG_ID,
                "default_dev_id": "anon",
                "auth_enabled": bool(AUTH_TOKEN),
                "version": "1.0.0"
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
            return
            
        if path == '/findings':
            org_id = query.get("org_id", ["default"])[0]
            findings = state_manager.get_org_findings(org_id)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(findings).encode())
            return

        if path == '/stats':
            org_id = query.get("org_id", ["default"])[0]
            stats = state_manager.get_org_stats(org_id)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode())
            return

        if path == '/debug/reset-rate-limit':
            _rate_limit_counters.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"success": true}')
            return

        self.send_response(404)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_POST(self):
        if not self.check_auth(): return
        
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        if body:
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid JSON"}')
                return
        else:
            data = {}
            
        if path == '/scan':
            dev_id = data.get("dev_id", "anon")
            filepath = data.get("filepath", "")
            source = data.get("source", "")
            
            org_id = data.get("org_id")
            if not org_id or str(org_id).strip() == "":
                data["org_id"] = DEFAULT_ORG_ID
            
            if DEPLOYMENT_MODE == "server":
                if filepath.startswith("/") or ":\\" in filepath:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(b'{"error": "Absolute paths not supported in server mode."}')
                    return
                    
            if not check_rate_limit(dev_id):
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "30")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"error": "Rate limit exceeded. Retry in 30 seconds."}')
                return
                
            data["source_code"] = source
            
            response_q = queue.Queue(1)
            try:
                SCAN_QUEUE.put_nowait((data, response_q))
            except queue.Full:
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "10")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"error": "Queue full. Retry in 10 seconds."}')
                return
                
            payload = response_q.get()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())
            return
            
        if path == '/dismiss':
            res = handle_dismiss(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
            return
            
        if path == '/scan/repo':
            res = handle_repo_scan(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
            return

        self.send_response(404)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

def run_server():
    setup_logging()

    cleaner = threading.Thread(target=cleanup_worker, daemon=True)
    cleaner.start()

    worker = threading.Thread(target=scan_worker, daemon=True)
    worker.start()

    host = "127.0.0.1" if DEPLOYMENT_MODE == "local" else "0.0.0.0"

    logger.info("--- C.H.A.K.R.A Server Started ---")
    logger.info(f"Mode: {DEPLOYMENT_MODE}")
    logger.info(f"Host: {host}:{PORT}")
    logger.info(f"LLM Backend: {llm_client.backend}")
    logger.info(f"Auth Enabled: {bool(AUTH_TOKEN)}")

    # Also echo the URL to stdout so the start scripts can report it
    print(f"C.H.A.K.R.A running at http://{host}:{PORT}  (logs: {LOG_PATH})", flush=True)

    server = ThreadingHTTPServer((host, PORT), ChakraHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down.")
        server.server_close()

if __name__ == "__main__":
    run_server()
