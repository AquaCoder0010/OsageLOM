import sqlite3
import os
from datetime import datetime
from typing import Optional, Dict, Any, List




class MalwareDatabase:
    def __init__(self, db_path: str = "malware_samples.db"):
        self.db_path = db_path
        self._init_db()


    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS samples (
                    sha256 TEXT PRIMARY KEY,
                    sha1 TEXT,
                    md5 TEXT,
                    file_name TEXT,
                    file_type TEXT,
                    file_arch TEXT,
                    file_size INTEGER,
                    signature TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    category TEXT,
                    opcode_text TEXT,
                    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_hashes (
                    sha1 TEXT PRIMARY KEY,
                    status TEXT,
                    reason TEXT,
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def sample_exists(self, sha256: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM samples WHERE sha256 = ?",
                (sha256,)
            )
            return cursor.fetchone() is not None

    def hash_processed(self, sha1: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM processed_hashes WHERE sha1 = ?",
                (sha1,)
            )
            return cursor.fetchone() is not None

    def add_sample(self, sample_data: Dict[str, Any]) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("""
                    INSERT INTO samples (
                        sha256, sha1, md5, file_name, file_type, file_arch,
                        file_size, signature, first_seen, last_seen, category, opcode_text
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sample_data.get("sha256"),
                    sample_data.get("sha1"),
                    sample_data.get("md5"),
                    sample_data.get("file_name"),
                    sample_data.get("file_type"),
                    sample_data.get("file_arch"),
                    sample_data.get("file_size"),
                    sample_data.get("signature"),
                    sample_data.get("first_seen"),
                    sample_data.get("last_seen"),
                    sample_data.get("category"),
                    sample_data.get("opcode_text"),
                ))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def mark_processed(self, sha1: str, status: str, reason: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO processed_hashes (sha1, status, reason)
                VALUES (?, ?, ?)
            """, (sha1, status, reason))
            conn.commit()

    def get_stats(self) -> Dict[str, int]:
        with sqlite3.connect(self.db_path) as conn:
            total_samples = conn.execute(
                "SELECT COUNT(*) FROM samples"
            ).fetchone()[0]
            
            total_processed = conn.execute(
                "SELECT COUNT(*) FROM processed_hashes"
            ).fetchone()[0]
            
            downloaded = conn.execute(
                "SELECT COUNT(*) FROM processed_hashes WHERE status = 'downloaded'"
            ).fetchone()[0]
            
            skipped_not_pe64 = conn.execute(
                "SELECT COUNT(*) FROM processed_hashes WHERE reason = 'not_pe64'"
            ).fetchone()[0]
            
            not_found = conn.execute(
                "SELECT COUNT(*) FROM processed_hashes WHERE reason = 'not_found'"
            ).fetchone()[0]
            
            return {
                "total_samples": total_samples,
                "total_processed": total_processed,
                "downloaded": downloaded,
                "skipped_not_pe64": skipped_not_pe64,
                "not_found": not_found,
            }
