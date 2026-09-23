import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import uuid
import structlog
import yaml
from pathlib import Path

from src.audit.store import AuditStore
from src.vectorstore.chroma_client import VectorDBClient
from src.instrumentation.models import MemoryEvent, SourceType
from .models import SnapshotMetadata

logger = structlog.get_logger()


class SnapshotSystem:
    def __init__(
        self,
        audit_store: AuditStore,
        vector_db: VectorDBClient,
        snapshot_frequency_entries: int = 100,
        snapshot_frequency_hours: int = 24,
        max_snapshots: int = 10,
    ):
        self.audit_store = audit_store
        self.vector_db = vector_db
        self.snapshot_frequency_entries = snapshot_frequency_entries
        self.snapshot_frequency_hours = snapshot_frequency_hours
        self.max_snapshots = max_snapshots
        self.last_snapshot_time = None
        self.event_count_since_snapshot = 0

    def create_snapshot(self, reason: str = "periodic") -> Optional[SnapshotMetadata]:
        try:
            snapshot_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc)

            memory_state = self._capture_memory_state()
            checkpoint_event_ids = self._get_recent_event_ids(100)

            metadata = SnapshotMetadata(
                id=snapshot_id,
                timestamp=timestamp,
                event_count=len(checkpoint_event_ids),
                checkpoint_event_ids=checkpoint_event_ids,
                metadata={
                    "reason": reason,
                    "memory_entries_count": len(memory_state),
                    "created_at": timestamp.isoformat(),
                },
            )

            self._save_snapshot(snapshot_id, memory_state, metadata)

            self.last_snapshot_time = timestamp
            self.event_count_since_snapshot = 0

            self._log_snapshot_creation(snapshot_id, reason, metadata)

            logger.info(
                "snapshot_created",
                snapshot_id=snapshot_id,
                reason=reason,
                event_count=len(checkpoint_event_ids),
                memory_entries=len(memory_state),
            )

            return metadata

        except Exception as e:
            logger.error("snapshot_creation_failed", error=str(e))
            return None

    def should_create_snapshot(self, new_event: Optional[MemoryEvent] = None) -> bool:
        if new_event:
            self.event_count_since_snapshot += 1

        if self.event_count_since_snapshot >= self.snapshot_frequency_entries:
            return True

        if self.last_snapshot_time:
            hours_since_last = (datetime.now(timezone.utc) - self.last_snapshot_time).total_seconds() / 3600
            if hours_since_last >= self.snapshot_frequency_hours:
                return True

        return False

    def load_snapshot(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        try:
            snapshot_path = Path(f"data/snapshots/{snapshot_id}.json")
            if not snapshot_path.exists():
                logger.warning("snapshot_not_found", snapshot_id=snapshot_id)
                return None

            with open(snapshot_path, "r") as f:
                snapshot_data = json.load(f)

            logger.info("snapshot_loaded", snapshot_id=snapshot_id)
            return snapshot_data

        except Exception as e:
            logger.error("snapshot_load_failed", snapshot_id=snapshot_id, error=str(e))
            return None

    def get_available_snapshots(self) -> List[SnapshotMetadata]:
        snapshots = []
        snapshots_dir = Path("data/snapshots")

        if not snapshots_dir.exists():
            return snapshots

        for file_path in snapshots_dir.glob("*.json"):
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                
                metadata_data = data.get("metadata", {})
                metadata = SnapshotMetadata(
                    id=metadata_data.get("id", file_path.stem),
                    timestamp=datetime.fromisoformat(metadata_data.get("timestamp", datetime.now(timezone.utc).isoformat())),
                    event_count=metadata_data.get("event_count", 0),
                    checkpoint_event_ids=metadata_data.get("checkpoint_event_ids", []),
                    metadata=metadata_data.get("metadata", {}),
                )
                snapshots.append(metadata)
            except Exception as e:
                logger.error("snapshot_parse_failed", file_path=str(file_path), error=str(e))

        snapshots.sort(key=lambda x: x.timestamp, reverse=True)
        return snapshots[:self.max_snapshots]

    def _capture_memory_state(self) -> Dict[str, Any]:
        try:
            events = self.audit_store.get_events(limit=1000)
            
            memory_state = {
                "events": events,
                "total_events": len(events),
                "captured_at": datetime.now(timezone.utc).isoformat(),
            }

            return memory_state

        except Exception as e:
            logger.error("memory_state_capture_failed", error=str(e))
            return {"events": [], "total_events": 0, "captured_at": datetime.now(timezone.utc).isoformat()}

    def _get_recent_event_ids(self, limit: int = 100) -> List[str]:
        events = self.audit_store.get_events(limit=limit)
        return [event["id"] for event in events]

    def _save_snapshot(self, snapshot_id: str, memory_state: Dict[str, Any], metadata: SnapshotMetadata) -> None:
        snapshots_dir = Path("data/snapshots")
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        snapshot_data = {
            "id": snapshot_id,
            "memory_state": memory_state,
            "metadata": metadata.to_dict(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        snapshot_path = snapshots_dir / f"{snapshot_id}.json"
        with open(snapshot_path, "w") as f:
            json.dump(snapshot_data, f, indent=2, default=str)

    def _log_snapshot_creation(self, snapshot_id: str, reason: str, metadata: SnapshotMetadata) -> None:
        try:
            self.audit_store.log_operation(
                operation="snapshot_created",
                event_id=snapshot_id,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "snapshot_id": snapshot_id,
                    "reason": reason,
                    "event_count": metadata.event_count,
                    "checkpoint_event_ids_count": len(metadata.checkpoint_event_ids),
                },
            )
        except Exception as e:
            logger.error("snapshot_log_failed", error=str(e), snapshot_id=snapshot_id)
