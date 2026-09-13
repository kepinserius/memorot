import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional
import json
import structlog

logger = structlog.get_logger()


class AuditStore:
    def __init__(self, db_path: str = "data/audit.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reads (
                    id TEXT PRIMARY KEY,
                    original_query TEXT,
                    processed_query TEXT,
                    result_count INTEGER,
                    session_id TEXT,
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    trust_level REAL NOT NULL,
                    session_id TEXT,
                    timestamp TEXT NOT NULL,
                    parent_event_id TEXT,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()

    def log_operation(
        self,
        operation: str,
        event_id: str,
        timestamp: datetime,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        import uuid
        
        op_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO operations (id, operation, event_id, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?)
                """,
                (op_id, operation, event_id, timestamp.isoformat(), json.dumps(metadata or {})),
            )
            conn.commit()

    def log_read(
        self,
        original_query: str,
        processed_query: str,
        result_count: int,
        session_id: str,
        timestamp: datetime,
    ) -> None:
        import uuid
        
        read_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO reads (id, original_query, processed_query, result_count, session_id, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (read_id, original_query, processed_query, result_count, session_id, timestamp.isoformat()),
            )
            conn.commit()

    def log_event(
        self,
        event_id: str,
        content: str,
        source_type: str,
        trust_level: float,
        session_id: str,
        timestamp: datetime,
        parent_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO events 
                (id, content, source_type, trust_level, session_id, timestamp, parent_event_id, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    content,
                    source_type,
                    trust_level,
                    session_id,
                    timestamp.isoformat(),
                    parent_event_id,
                    json.dumps(metadata or {}),
                ),
            )
            conn.commit()

    def get_events(self, session_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if session_id:
                cursor.execute(
                    """
                    SELECT * FROM events WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?
                    """,
                    (session_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM events ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,),
                )
            
            return [dict(row) for row in cursor.fetchall()]

    def get_operations(self, event_id: str) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM operations WHERE event_id = ? ORDER BY timestamp DESC
                """,
                (event_id,),
            )
            return [dict(row) for row in cursor.fetchall()]
