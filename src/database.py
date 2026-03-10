import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from .config_loader import config

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = config.get('DATABASE_PATH')
        
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT UNIQUE NOT NULL,
                family TEXT NOT NULL,
                source TEXT NOT NULL,
                file_path TEXT,
                arch TEXT,
                file_size INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                vt_detections INTEGER DEFAULT 0,
                is_packed BOOLEAN DEFAULT 0,
                extraction_status TEXT DEFAULT 'pending',
                opcode_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_family ON samples(family)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sha256 ON samples(sha256)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_extraction_status ON samples(extraction_status)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS extraction_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id INTEGER,
                extraction_time REAL,
                opcode_count INTEGER,
                text_section_size INTEGER,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sample_id) REFERENCES samples(id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collection_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                family TEXT,
                target_count INTEGER,
                current_count INTEGER,
                status TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {self.db_path}")
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def add_sample(self, sha256: str, family: str, source: str, 
                   file_path: str = None, **kwargs) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO samples 
                (sha256, family, source, file_path, arch, file_size, 
                 first_seen, last_seen, vt_detections)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sha256, family, source, file_path,
                kwargs.get('arch'),
                kwargs.get('file_size'),
                kwargs.get('first_seen'),
                kwargs.get('last_seen'),
                kwargs.get('vt_detections', 0)
            ))
            conn.commit()
            sample_id = cursor.lastrowid
            
            if sample_id == 0:
                cursor.execute("SELECT id FROM samples WHERE sha256 = ?", (sha256,))
                sample_id = cursor.fetchone()[0]
            
            return sample_id
        finally:
            conn.close()
    
    def sample_exists(self, sha256: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM samples WHERE sha256 = ?", (sha256,))
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    
    def get_samples_by_family(self, family: str, limit: int = None) -> List[Dict]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM samples WHERE family = ?"
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query, (family,))
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_pending_extractions(self, limit: int = 100) -> List[Dict]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM samples 
            WHERE extraction_status = 'pending'
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_undownloaded_samples(self, family: str = None, limit: int = None) -> List[Dict]:
        """Get samples that haven't been downloaded yet (file_path is NULL)."""
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM samples WHERE file_path IS NULL OR file_path = ''"
        params = []
        
        if family:
            query += " AND family = ?"
            params.append(family)
        
        if limit:
            query += f" LIMIT {limit}"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def update_sample_path(self, sample_id: int, file_path: str, file_size: int = 0):
        """Update the file_path for a sample after download."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE samples 
            SET file_path = ?, file_size = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (file_path, file_size, sample_id))
        
        conn.commit()
        conn.close()
    
    def update_extraction_status(self, sample_id: int, status: str, 
                                  opcode_path: str = None, error: str = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE samples 
            SET extraction_status = ?, opcode_path = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (status, opcode_path, sample_id))
        
        if error:
            cursor.execute("""
                INSERT INTO extraction_logs (sample_id, error_message)
                VALUES (?, ?)
            """, (sample_id, error))
        
        conn.commit()
        conn.close()
    
    def log_extraction(self, sample_id: int, extraction_time: float, 
                       opcode_count: int, text_section_size: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO extraction_logs 
            (sample_id, extraction_time, opcode_count, text_section_size)
            VALUES (?, ?, ?, ?)
        """, (sample_id, extraction_time, opcode_count, text_section_size))
        
        conn.commit()
        conn.close()
    
    def get_family_counts(self) -> Dict[str, int]:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT family, COUNT(*) as count 
            FROM samples 
            GROUP BY family
        """)
        
        counts = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return counts
    
    def get_total_samples(self) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM samples")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def update_collection_stats(self, family: str, target: int, current: int, status: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO collection_stats 
            (family, target_count, current_count, status, last_updated)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (family, target, current, status))
        
        conn.commit()
        conn.close()
    
    def get_collection_stats(self) -> List[Dict]:
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM collection_stats")
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def add_batch(self, samples: List[Dict]) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        
        count = 0
        for sample in samples:
            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO samples 
                    (sha256, family, source, file_path, arch, file_size, 
                     first_seen, last_seen, vt_detections)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sample.get('sha256'),
                    sample.get('family'),
                    sample.get('source'),
                    sample.get('file_path'),
                    sample.get('arch'),
                    sample.get('file_size'),
                    sample.get('first_seen'),
                    sample.get('last_seen'),
                    sample.get('vt_detections', 0)
                ))
                if cursor.rowcount > 0:
                    count += 1
            except Exception as e:
                logger.debug(f"Skipped sample: {e}")
        
        conn.commit()
        conn.close()
        return count
