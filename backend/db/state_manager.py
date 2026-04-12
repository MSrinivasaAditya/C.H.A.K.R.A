import sqlite3
import os
import json
import time
from pathlib import Path
from collections import OrderedDict

# The single database configuration
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'chakra_state.db')
DB_PATH = os.path.normpath(DB_PATH)

class StateManager:
    """
    Manages all database operations. 
    Nothing outside this file touches the database directly.
    """
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._fingerprints_cache = OrderedDict()
        self._findings_cache = OrderedDict()
        self._init_db()

    def get_connection(self):
        """Returns a new connection to the SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes the database schema based on Phase 1 requirements."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Table: file_fingerprints
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_fingerprints (
                    filepath TEXT PRIMARY KEY,
                    org_id TEXT,
                    dev_id TEXT,
                    fingerprint_json TEXT,
                    last_updated INTEGER
                )
            ''')

            # Table: findings_cache
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings_cache (
                    filepath TEXT,
                    org_id TEXT,
                    dev_id TEXT,
                    findings_json TEXT,
                    last_updated INTEGER,
                    PRIMARY KEY (filepath, org_id, dev_id)
                )
            ''')

            # Table: dismissed_findings
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dismissed_findings (
                    fingerprint TEXT PRIMARY KEY,
                    org_id TEXT,
                    dev_id TEXT,
                    filepath TEXT,
                    dismissed_at INTEGER
                )
            ''')

            # Table: scan_log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id TEXT,
                    dev_id TEXT,
                    filepath TEXT,
                    scan_type TEXT,
                    findings_count INTEGER,
                    scan_time_ms INTEGER,
                    cache_hit INTEGER,
                    scanned_at INTEGER
                )
            ''')

            # Table: repo_scans
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS repo_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id TEXT,
                    repo_url TEXT,
                    status TEXT,
                    findings_json TEXT,
                    started_at INTEGER,
                    completed_at INTEGER
                )
            ''')
            
            conn.commit()

    def load_all_into_memory(self):
        """Reads all rows from file_fingerprints and findings_cache into memory."""
        self._fingerprints_cache.clear()
        self._findings_cache.clear()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT filepath, org_id, dev_id, fingerprint_json FROM file_fingerprints")
            for row in cursor.fetchall():
                key = (row['filepath'], row['org_id'], row['dev_id'])
                def _parse_key(k):
                    k = str(k).strip()
                    if k.startswith("line"):
                        k = k[4:]
                    return int(k)
                self._fingerprints_cache[key] = {_parse_key(k): v for k, v in json.loads(row['fingerprint_json']).items()}
                
            cursor.execute("SELECT filepath, org_id, dev_id, findings_json FROM findings_cache")
            for row in cursor.fetchall():
                key = (row['filepath'], row['org_id'], row['dev_id'])
                self._findings_cache[key] = json.loads(row['findings_json'])
                
        self.evict_lru_if_needed()

    def get_fingerprint(self, filepath, org_id, dev_id):
        key = (filepath, org_id, dev_id)
        if key in self._fingerprints_cache:
            self._fingerprints_cache.move_to_end(key)
            return self._fingerprints_cache[key]
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT fingerprint_json FROM file_fingerprints WHERE filepath=? AND org_id=? AND dev_id=?", 
                (filepath, org_id, dev_id)
            )
            row = cursor.fetchone()
            if row:
                def _parse_key(k):
                    k = str(k).strip()
                    if k.startswith("line"):
                        k = k[4:]
                    return int(k)
                data = {_parse_key(k): v for k, v in json.loads(row['fingerprint_json']).items()}
                self._fingerprints_cache[key] = data
                self.evict_lru_if_needed()
                return data
        return None

    def set_fingerprint(self, filepath, org_id, dev_id, fingerprint_dict):
        key = (filepath, org_id, dev_id)
        self._fingerprints_cache[key] = fingerprint_dict
        self._fingerprints_cache.move_to_end(key)
        self.evict_lru_if_needed()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO file_fingerprints (filepath, org_id, dev_id, fingerprint_json, last_updated)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(filepath) DO UPDATE SET
                    org_id=excluded.org_id,
                    dev_id=excluded.dev_id,
                    fingerprint_json=excluded.fingerprint_json,
                    last_updated=excluded.last_updated
            ''', (filepath, org_id, dev_id, json.dumps(fingerprint_dict), int(time.time())))
            conn.commit()

    def get_findings(self, filepath, org_id, dev_id):
        key = (filepath, org_id, dev_id)
        if key in self._findings_cache:
            self._findings_cache.move_to_end(key)
            return self._findings_cache[key]
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT findings_json FROM findings_cache WHERE filepath=? AND org_id=? AND dev_id=?", 
                (filepath, org_id, dev_id)
            )
            row = cursor.fetchone()
            if row:
                data = json.loads(row['findings_json'])
                self._findings_cache[key] = data
                self.evict_lru_if_needed()
                return data
        return None

    def set_findings(self, filepath, org_id, dev_id, findings_list):
        print(f"[DEBUG] set_findings called: {filepath}, {org_id}, {dev_id}, {len(findings_list)} findings")
        key = (filepath, org_id, dev_id)
        self._findings_cache[key] = findings_list
        self._findings_cache.move_to_end(key)
        self.evict_lru_if_needed()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO findings_cache (filepath, org_id, dev_id, findings_json, last_updated)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(filepath, org_id, dev_id) DO UPDATE SET
                    findings_json=excluded.findings_json,
                    last_updated=excluded.last_updated
            ''', (filepath, org_id, dev_id, json.dumps(findings_list), int(time.time())))
            conn.commit()

    def is_dismissed(self, fingerprint):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM dismissed_findings WHERE fingerprint=?", (fingerprint,))
            return cursor.fetchone() is not None

    def add_dismissal(self, fingerprint, org_id, dev_id, filepath):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO dismissed_findings (fingerprint, org_id, dev_id, filepath, dismissed_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (fingerprint, org_id, dev_id, filepath, int(time.time())))
            conn.commit()
            
        for key, findings_list in self._findings_cache.items():
            self._findings_cache[key] = [
                f for f in findings_list 
                if f.get("dismissal_fingerprint") != fingerprint
            ]

    def log_scan(self, org_id, dev_id, filepath, scan_type, findings_count, scan_time_ms, cache_hit):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_log (org_id, dev_id, filepath, scan_type, findings_count, scan_time_ms, cache_hit, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (org_id, dev_id, filepath, scan_type, findings_count, scan_time_ms, cache_hit, int(time.time())))
            conn.commit()

    def get_org_findings(self, org_id):
        print(f"[DEBUG] get_org_findings called for org_id={org_id}")
        print(f"[DEBUG] findings_cache keys: {list(self._findings_cache.keys())}")
        all_findings = []
        # Get all findings for this org from findings_cache
        for (fp, oid, did), findings in self._findings_cache.items():
            if oid != org_id:
                continue
            for finding in findings:
                fingerprint = finding.get("dismissal_fingerprint", "")
                # Only include if NOT dismissed
                if not self.is_dismissed(fingerprint):
                    finding_copy = dict(finding)
                    finding_copy["filepath"] = fp
                    finding_copy["dev_id"] = did
                    all_findings.append(finding_copy)
        return all_findings

    def get_org_stats(self, org_id):
        now = int(time.time())
        one_day_ago = now - 86400
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(findings_count) as total_findings,
                    AVG(scan_time_ms) as avg_latency,
                    SUM(cache_hit) as total_cache_hits
                FROM scan_log 
                WHERE org_id=? AND scanned_at >= ?
            ''', (org_id, one_day_ago))
            
            log_row = cursor.fetchone()
            total_scans_today = log_row['total_scans'] or 0
            total_findings_today = log_row['total_findings'] or 0
            avg_latency = log_row['avg_latency'] or 0.0
            total_cache_hits = log_row['total_cache_hits'] or 0
            
            cache_hit_rate = (total_cache_hits / total_scans_today) if total_scans_today > 0 else 0.0
            
            org_findings = self.get_org_findings(org_id)
            
            severity_counts = {}
            cwe_counts = {}
            dev_counts = {}
            
            for f in org_findings:
                sev = f.get('severity', 'Unknown')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                cwe = f.get('cwe', 'Unknown')
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
                
                dev = f.get('dev_id', 'Unknown')
                dev_counts[dev] = dev_counts.get(dev, 0) + 1

            return {
                "total_scans_today": total_scans_today,
                "total_findings_today": total_findings_today,
                "findings_by_severity": severity_counts,
                "findings_by_cwe": cwe_counts,
                "findings_by_developer": dev_counts,
                "average_scan_latency": avg_latency,
                "cache_hit_rate": cache_hit_rate
            }

    def evict_lru_if_needed(self):
        while len(self._fingerprints_cache) > 50:
            self._fingerprints_cache.popitem(last=False)
        while len(self._findings_cache) > 50:
            self._findings_cache.popitem(last=False)

    def cleanup_stale_entries(self):
        cutoff = int(time.time()) - 86400
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM file_fingerprints WHERE last_updated < ?", (cutoff,))
            cursor.execute("DELETE FROM findings_cache WHERE last_updated < ?", (cutoff,))
            conn.commit()


if __name__ == "__main__":
    import os
    TEST_DB = "test_temp_chakra.db"
    if os.path.exists(TEST_DB): os.remove(TEST_DB)

    print("Test 1: Fingerprint persists across restart.")
    db1 = StateManager(TEST_DB)
    db1.set_fingerprint("test.py", "org1", "dev1", {1: "abc", 2: "def"})
    db2 = StateManager(TEST_DB)
    db2.load_all_into_memory()
    fp = db2.get_fingerprint("test.py", "org1", "dev1")
    assert fp == {1: "abc", 2: "def"}, f"Test 1 Failed — got {fp}"
    print("Test 1 PASS")

    print("Test 2: Dismissed findings filtered.")
    db1.set_findings("test.py", "org1", "dev1", [
        {"cwe": "CWE-89", "dismissal_fingerprint": "fp1"},
        {"cwe": "CWE-95", "dismissal_fingerprint": "fp2"}
    ])
    db1.add_dismissal("fp1", "org1", "dev1", "test.py")
    findings = db1.get_org_findings("org1")
    fps = [f["dismissal_fingerprint"] for f in findings]
    assert "fp1" not in fps, f"Test 2 Failed — dismissed finding still present"
    assert "fp2" in fps, f"Test 2 Failed — non-dismissed finding missing"
    print("Test 2 PASS")

    print("Test 3: Memory capped at 50 entries.")
    for i in range(52):
        db1.set_fingerprint(f"file{i}.py", "org1", "dev1", {1: f"hash{i}"})
    count = len(db1._fingerprints_cache)
    assert count <= 50, f"Test 3 Failed — memory has {count} entries"
    print("Test 3 PASS")

    print("Test 4: Scan log count correct.")
    db1.log_scan("org1", "dev1", "test.py", "file", 3, 1500, 0)
    stats = db1.get_org_stats("org1")
    assert stats["total_scans_today"] >= 1, f"Test 4 Failed — scan count is {stats['total_scans_today']}"
    print("Test 4 PASS")

    print("Test 5: Stale entries cleaned up.")
    import time
    conn = db1.get_connection()
    conn.execute("INSERT OR REPLACE INTO file_fingerprints VALUES (?,?,?,?,?)",
        ("old.py", "org1", "dev1", "{}", int(time.time()) - 90000))
    conn.commit()
    db1.cleanup_stale_entries()
    result = conn.execute("SELECT * FROM file_fingerprints WHERE filepath='old.py'").fetchone()
    assert result is None, "Test 5 Failed — stale entry not removed"
    conn.close()
    print("Test 5 PASS")

    if os.path.exists(TEST_DB): os.remove(TEST_DB)
    print("\nAll tests passed.")
