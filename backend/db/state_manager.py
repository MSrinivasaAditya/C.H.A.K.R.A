import sqlite3
import os
import json
import time
from pathlib import Path
from collections import OrderedDict

# The single database configuration
DB_PATH = os.environ.get("CHAKRA_DB_PATH", "chakra_state.db")

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
                self._fingerprints_cache[key] = json.loads(row['fingerprint_json'])
                
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
                data = json.loads(row['fingerprint_json'])
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

    def log_scan(self, org_id, dev_id, filepath, scan_type, findings_count, scan_time_ms, cache_hit):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_log (org_id, dev_id, filepath, scan_type, findings_count, scan_time_ms, cache_hit, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (org_id, dev_id, filepath, scan_type, findings_count, scan_time_ms, cache_hit, int(time.time())))
            conn.commit()

    def get_org_findings(self, org_id):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Retrieve dismissed fingerprints
            cursor.execute("SELECT fingerprint FROM dismissed_findings WHERE org_id=?", (org_id,))
            dismissed = {row['fingerprint'] for row in cursor.fetchall()}
            
            # Build findings across the org
            cursor.execute("SELECT filepath, dev_id, findings_json FROM findings_cache WHERE org_id=?", (org_id,))
            
            org_findings = []
            for row in cursor.fetchall():
                findings = json.loads(row['findings_json'])
                for f in findings:
                    fps = f.get('fingerprint')
                    if not fps or fps not in dismissed:
                        f_copy = dict(f)
                        if 'filepath' not in f_copy:
                            f_copy['filepath'] = row['filepath']
                        if 'dev_id' not in f_copy:
                            f_copy['dev_id'] = row['dev_id']
                        org_findings.append(f_copy)
                        
            return org_findings

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
    db_file = "test_chakra_state.db"
    if os.path.exists(db_file):
        os.remove(db_file)
        
    db = StateManager(db_file)
    
    print("Test 1: Write a fingerprint, restart the StateManager object, confirm it loads from SQLite correctly.")
    db.set_fingerprint("test1.py", "org1", "dev1", {"line1": "hash1"})
    db2 = StateManager(db_file)
    db2.load_all_into_memory()
    fp = db2.get_fingerprint("test1.py", "org1", "dev1")
    assert fp == {"line1": "hash1"}, "Test 1 Failed"
    print("Test 1 Passed")
    
    print("Test 2: Write findings, mark one as dismissed, call get_org_findings, confirm the dismissed one is absent.")
    db.set_findings("test2.py", "org1", "dev1", [
        {"fingerprint": "hashA", "severity": "high", "cwe": "CWE-79"},
        {"fingerprint": "hashB", "severity": "low", "cwe": "CWE-20"}
    ])
    db.add_dismissal("hashA", "org1", "dev1", "test2.py")
    findings = db.get_org_findings("org1")
    assert len(findings) == 1, f"Test 2 Failed: wrong length {len(findings)}"
    assert findings[0]["fingerprint"] == "hashB", "Test 2 Failed: wrong fingerprint retained"
    print("Test 2 Passed")
    
    print("Test 3: Write 52 different file entries, confirm memory never exceeds 50 entries.")
    for i in range(52):
        db.set_fingerprint(f"file_{i}.py", "org1", "dev1", {"l": "h"})
        db.set_findings(f"file_{i}.py", "org1", "dev1", [])
    assert len(db._fingerprints_cache) <= 50, "Test 3 Failed: fingerprints cache too large"
    assert len(db._findings_cache) <= 50, "Test 3 Failed: findings cache too large"
    print("Test 3 Passed")
    
    print("Test 4: Write a scan log entry, call get_org_stats, confirm the count is correct.")
    db.log_scan("org1", "dev1", "test.py", "file", 5, 120, 1)
    stats = db.get_org_stats("org1")
    assert stats["total_scans_today"] >= 1, "Test 4 Failed: scans missing"
    assert stats["total_findings_today"] >= 5, "Test 4 Failed: findings missing"
    assert stats["average_scan_latency"] == 120.0, "Test 4 Failed: avg latency mismatched"
    assert stats["cache_hit_rate"] == 1.0, "Test 4 Failed: cache hit rate mismatched"
    print("Test 4 Passed")
    
    print("Test 5: Write a row with last_updated set to 48 hours ago, call cleanup_stale_entries, confirm it is gone.")
    old_time = int(time.time()) - 48 * 3600
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE file_fingerprints SET last_updated=? WHERE filepath=?", (old_time, "test1.py"))
        conn.commit()
    db.cleanup_stale_entries()
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM file_fingerprints WHERE filepath=?", ("test1.py",))
        assert cursor.fetchone() is None, "Test 5 Failed: stale entry still exists"
    print("Test 5 Passed")
    
    print("All tests passed.")
