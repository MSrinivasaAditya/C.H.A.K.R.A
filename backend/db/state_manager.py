import sqlite3
import os
from pathlib import Path

# The single database configuration
DB_PATH = os.environ.get("CHAKRA_DB_PATH", "chakra_state.db")

class StateManager:
    """
    Manages all database operations. 
    Nothing outside this file touches the database directly.
    """
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
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
            # Purpose: Stores a line-by-line hash map for every scanned file.
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
            # Purpose: Stores the last known findings for each file.
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
            # Purpose: Permanent record of findings a developer has dismissed.
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
            # Purpose: Audit trail of every scan for the dashboard stats endpoint.
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
            # Purpose: Tracks full repository scans initiated from the dashboard.
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

if __name__ == "__main__":
    db = StateManager("test_chakra_state.db")
    print("Database schema defined and initialized successfully.")
