from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
import uuid

from src.audit.store import AuditStore
from src.audit.snapshot import SnapshotSystem
from src.vectorstore.chroma_client import VectorDBClient
from .models import SnapshotMetadata

logger = structlog.get_logger()


class RollbackManager:
    def __init__(
        self,
        audit_store: AuditStore,
        snapshot_system: SnapshotSystem,
        vector_db: VectorDBClient,
    ):
        self.audit_store = audit_store
        self.snapshot_system = snapshot_system
        self.vector_db = vector_db

    def find_contamination_point(
        self,
        malicious_event_id: str,
        max_history_events: int = 500,
    ) -> Optional[str]:
        logger.info("finding_contamination_point", malicious_event_id=malicious_event_id)

        event_chain = self._get_event_chain(malicious_event_id, max_history_events)
        
        if not event_chain:
            logger.warning("no_event_chain_found", event_id=malicious_event_id)
            return None

        snapshots = self.snapshot_system.get_available_snapshots()
        
        if not snapshots:
            logger.warning("no_snapshots_available")
            return None

        contamination_event = self._find_first_malicious_event(event_chain)

        if contamination_event:
            timestamp = contamination_event["timestamp"]
            snapshot = self._find_nearest_snapshot_before(timestamp, snapshots)
            
            if snapshot:
                logger.info(
                    "contamination_point_found",
                    contamination_event_id=contamination_event["id"],
                    contamination_timestamp=timestamp,
                    snapshot_id=snapshot.id,
                    snapshot_timestamp=snapshot.timestamp.isoformat(),
                )
                return snapshot.id

        fallback_snapshot = snapshots[-1]
        logger.info(
            "using_fallback_snapshot",
            snapshot_id=fallback_snapshot.id,
            snapshot_timestamp=fallback_snapshot.timestamp.isoformat(),
        )
        
        return fallback_snapshot.id

    def rollback_to_snapshot(
        self,
        snapshot_id: str,
        replay_clean_events: bool = True,
        replay_limit: int = 100,
    ) -> Dict[str, Any]:
        logger.info("rollback_started", snapshot_id=snapshot_id)

        rollback_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        snapshot_data = self.snapshot_system.load_snapshot(snapshot_id)
        if not snapshot_data:
            logger.error("snapshot_not_found_for_rollback", snapshot_id=snapshot_id)
            return {"success": False, "error": "Snapshot not found"}

        events_removed = self._remove_events_after_snapshot(snapshot_data)
        vector_db_cleaned = self._clean_vector_db(snapshot_data)

        replayed_events = []
        if replay_clean_events:
            replayed_events = self._replay_clean_events(snapshot_data, replay_limit)

        duration = (datetime.utcnow() - start_time).total_seconds()

        result = {
            "success": True,
            "rollback_id": rollback_id,
            "snapshot_id": snapshot_id,
            "snapshot_timestamp": snapshot_data["metadata"].get("timestamp"),
            "events_removed": events_removed,
            "vector_db_cleaned": vector_db_cleaned,
            "events_replayed": len(replayed_events),
            "duration_seconds": duration,
        }

        self._log_rollback(rollback_id, snapshot_id, result)

        logger.info(
            "rollback_completed",
            rollback_id=rollback_id,
            snapshot_id=snapshot_id,
            events_removed=events_removed,
            events_replayed=len(replayed_events),
            duration_seconds=duration,
        )

        return result

    def _get_event_chain(self, event_id: str, max_events: int) -> List[Dict[str, Any]]:
        events = []
        current_event_id = event_id
        events_found = 0

        while current_event_id and events_found < max_events:
            event_data = self.audit_store.get_events_by_id(current_event_id)
            if not event_data:
                break

            events.append(event_data[0])
            current_event_id = event_data[0].get("parent_event_id")
            events_found += 1

        return events

    def _find_first_malicious_event(self, event_chain: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for event in reversed(event_chain):
            metadata = event.get("metadata", {})
            if isinstance(metadata, str):
                try:
                    import json
                    metadata = json.loads(metadata)
                except:
                    metadata = {}

            detection_result = metadata.get("detection_result", {})
            if detection_result.get("decision") == "malicious":
                return event

        return None

    def _find_nearest_snapshot_before(
        self,
        timestamp: str,
        snapshots: List[SnapshotMetadata],
    ) -> Optional[SnapshotMetadata]:
        target_time = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp

        for snapshot in snapshots:
            if snapshot.timestamp < target_time:
                return snapshot

        return None

    def _remove_events_after_snapshot(
        self,
        snapshot_data: Dict[str, Any],
    ) -> int:
        checkpoint_ids = set(snapshot_data["metadata"].get("checkpoint_event_ids", []))

        try:
            recent_events = self.audit_store.get_events(limit=1000)
            events_to_remove = [
                event for event in recent_events
                if event["id"] not in checkpoint_ids
            ]

            for event in events_to_remove:
                self.audit_store.log_operation(
                    operation="rollback_removed",
                    event_id=event["id"],
                    timestamp=datetime.utcnow(),
                    metadata={"snapshot_id": snapshot_data["id"], "reason": "post_snapshot_cleanup"},
                )

            return len(events_to_remove)

        except Exception as e:
            logger.error("event_removal_failed", error=str(e))
            return 0

    def _clean_vector_db(self, snapshot_data: Dict[str, Any]) -> bool:
        try:
            checkpoint_ids = set(snapshot_data["metadata"].get("checkpoint_event_ids", []))
            
            all_entries = self.vector_db.get_all_entries()
            entries_to_remove = [
                entry_id for entry_id in all_entries
                if entry_id not in checkpoint_ids
            ]

            for entry_id in entries_to_remove:
                self.vector_db.delete(entry_id)

            return True

        except Exception as e:
            logger.error("vector_db_cleanup_failed", error=str(e))
            return False

    def _replay_clean_events(
        self,
        snapshot_data: Dict[str, Any],
        limit: int,
    ) -> List[Dict[str, Any]]:
        replayed_events = []

        try:
            recent_events = self.audit_store.get_events(limit=limit * 2)
            checkpoint_ids = set(snapshot_data["metadata"].get("checkpoint_event_ids", []))

            clean_events = [
                event for event in recent_events
                if event["id"] not in checkpoint_ids
            ]

            for event in clean_events[:limit]:
                metadata = event.get("metadata", {})
                if isinstance(metadata, str):
                    try:
                        import json
                        metadata = json.loads(metadata)
                    except:
                        metadata = {}

                detection_result = metadata.get("detection_result", {})
                if detection_result.get("decision") in ["clean", None]:
                    replayed_events.append(event)

            return replayed_events

        except Exception as e:
            logger.error("event_replay_failed", error=str(e))
            return []

    def _log_rollback(self, rollback_id: str, snapshot_id: str, result: Dict[str, Any]) -> None:
        try:
            self.audit_store.log_operation(
                operation="rollback_completed",
                event_id=rollback_id,
                timestamp=datetime.utcnow(),
                metadata={
                    "rollback_id": rollback_id,
                    "snapshot_id": snapshot_id,
                    "result": result,
                },
            )
        except Exception as e:
            logger.error("rollback_log_failed", error=str(e), rollback_id=rollback_id)
