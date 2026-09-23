import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import uuid
import structlog

from src.audit.store import AuditStore
from src.instrumentation.models import MemoryEvent
from .models import EventLogEntry, SnapshotMetadata

logger = structlog.get_logger()


class EventSourcing:
    def __init__(self, audit_store: AuditStore):
        self.audit_store = audit_store

    def log_operation(
        self,
        operation: str,
        event: MemoryEvent,
        additional_metadata: Optional[Dict[str, Any]] = None,
    ) -> EventLogEntry:
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)

        metadata = {
            "event_content": event.content[:200],
            "event_source_type": event.source_type.value,
            "event_trust_level": event.trust_level,
            "event_session_id": event.session_id,
            "parent_event_id": event.parent_event_id,
            **(additional_metadata or {}),
        }

        self.audit_store.log_operation(
            operation=operation,
            event_id=event.id,
            timestamp=timestamp,
            metadata=metadata,
        )

        self.audit_store.log_event(
            event_id=event.id,
            content=event.content,
            source_type=event.source_type.value,
            trust_level=event.trust_level,
            session_id=event.session_id,
            timestamp=timestamp,
            parent_event_id=event.parent_event_id,
            metadata=event.metadata,
        )

        log_entry = EventLogEntry(
            id=event_id,
            operation=operation,
            event_id=event.id,
            timestamp=timestamp,
            metadata=metadata,
        )

        logger.info(
            "event_logged",
            operation=operation,
            event_id=event.id,
            content_length=len(event.content),
        )

        return log_entry

    def get_event_chain(self, event_id: str, max_depth: int = 100) -> List[EventLogEntry]:
        chain = []
        current_event_id = event_id
        depth = 0

        while current_event_id and depth < max_depth:
            operations = self.audit_store.get_operations(current_event_id)
            if not operations:
                break

            operation = operations[0]
            log_entry = EventLogEntry(
                id=operation["id"],
                operation=operation["operation"],
                event_id=operation["event_id"],
                timestamp=datetime.fromisoformat(operation["timestamp"]),
                metadata=json.loads(operation["metadata"]) if isinstance(operation["metadata"], str) else operation["metadata"],
            )

            chain.append(log_entry)

            metadata = log_entry.metadata
            current_event_id = metadata.get("parent_event_id")
            depth += 1

        return list(reversed(chain))

    def get_operations_by_session(self, session_id: str, limit: int = 100) -> List[EventLogEntry]:
        events = self.audit_store.get_events(session_id=session_id, limit=limit)
        event_ids = [event["id"] for event in events]

        log_entries = []
        for event_id in event_ids:
            operations = self.audit_store.get_operations(event_id)
            for operation in operations:
                log_entry = EventLogEntry(
                    id=operation["id"],
                    operation=operation["operation"],
                    event_id=operation["event_id"],
                    timestamp=datetime.fromisoformat(operation["timestamp"]),
                    metadata=json.loads(operation["metadata"]) if isinstance(operation["metadata"], str) else operation["metadata"],
                )
                log_entries.append(log_entry)

        log_entries.sort(key=lambda x: x.timestamp, reverse=True)
        return log_entries[:limit]
