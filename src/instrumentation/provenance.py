from typing import Optional, Dict, Any, List
import uuid
from datetime import datetime, timezone
from .models import MemoryEvent, SourceType
from .trust_level import TrustLevelCalculator


class ProvenanceTracker:
    def __init__(self):
        self.trust_calculator = TrustLevelCalculator()

    def create_event(
        self,
        content: str,
        source_type: SourceType,
        session_id: str = "",
        user_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        embedding: Optional[List[float]] = None,
    ) -> MemoryEvent:
        event_id = str(uuid.uuid4())
        trust_level = self.trust_calculator.calculate(source_type)

        event = MemoryEvent(
            id=event_id,
            content=content,
            embedding=embedding,
            source_type=source_type,
            trust_level=trust_level,
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            parent_event_id=parent_event_id,
            user_id=user_id,
            metadata=metadata or {},
        )

        return event

    def create_child_event(
        self,
        parent_event: MemoryEvent,
        content: str,
        source_type: SourceType,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryEvent:
        child_event = self.create_event(
            content=content,
            source_type=source_type,
            session_id=parent_event.session_id,
            user_id=parent_event.user_id,
            parent_event_id=parent_event.id,
            metadata=metadata,
        )

        child_event.metadata["parent_trust"] = parent_event.trust_level
        child_event.metadata["parent_content"] = parent_event.content[:100]

        return child_event

    def get_event_chain(self, event: MemoryEvent, max_depth: int = 10) -> List[MemoryEvent]:
        chain = [event]
        current = event
        depth = 0

        while current.parent_event_id and depth < max_depth:
            depth += 1
            current = self._get_event_by_id(current.parent_event_id)
            if current:
                chain.append(current)

        return list(reversed(chain))

    def _get_event_by_id(self, event_id: str) -> Optional[MemoryEvent]:
        # Implementation depends on storage backend
        # For now, return None - will be implemented with database
        return None
