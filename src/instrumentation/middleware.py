from typing import Callable, Optional, Dict, Any, List
import structlog
from datetime import datetime, timezone

from .models import MemoryEvent, SourceType
from .provenance import ProvenanceTracker
from .trust_level import TrustLevelCalculator

logger = structlog.get_logger()


class MemoryMiddleware:
    def __init__(
        self,
        vector_db_client: Any = None,
        audit_store: Any = None,
        detection_pipeline: Any = None,
    ):
        self.provenance_tracker = ProvenanceTracker()
        self.trust_calculator = TrustLevelCalculator()
        self.vector_db = vector_db_client
        self.audit_store = audit_store
        self.detection_pipeline = detection_pipeline
        
        # Hooks for external processing
        self.pre_write_hooks: List[Callable[[MemoryEvent], MemoryEvent]] = []
        self.post_write_hooks: List[Callable[[MemoryEvent], None]] = []
        self.pre_read_hooks: List[Callable[[str], str]] = []
        self.post_read_hooks: List[Callable[[List[Any]], List[Any]]] = []

    def intercept_write(
        self,
        content: str,
        source_type: SourceType,
        session_id: str = "",
        user_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        embedding: Optional[List[float]] = None,
    ) -> MemoryEvent:
        logger.info(
            "memory_write_intercepted",
            content_length=len(content),
            source_type=source_type.value,
            session_id=session_id[:8] if session_id else None,
        )

        event = self.provenance_tracker.create_event(
            content=content,
            source_type=source_type,
            session_id=session_id,
            user_id=user_id,
            parent_event_id=parent_event_id,
            metadata=metadata,
            embedding=embedding,
        )

        for hook in self.pre_write_hooks:
            event = hook(event)

        if self.vector_db and embedding:
            self._store_in_vector_db(event)

        if self.audit_store:
            self._audit_event(event, "write")

        if self.detection_pipeline:
            detection_result = self.detection_pipeline.process(event)
            event.metadata["detection_result"] = detection_result.to_dict()

        for hook in self.post_write_hooks:
            hook(event)

        return event

    def intercept_read(
        self,
        query: str,
        session_id: str = "",
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        query_vector: Optional[List[float]] = None,
    ) -> List[Any]:
        logger.info(
            "memory_read_intercepted",
            query=query[:50] if query else None,
            session_id=session_id[:8] if session_id else None,
            limit=limit,
        )

        processed_query = query
        for hook in self.pre_read_hooks:
            processed_query = hook(processed_query)

        results = []
        if self.vector_db:
            results = self.vector_db.search(
                query=processed_query,
                session_id=session_id,
                limit=limit,
                filters=filters,
            )

        for hook in self.post_read_hooks:
            results = hook(results)

        if self.audit_store:
            self._audit_read(query, processed_query, results, session_id)

        return results

    def _store_in_vector_db(self, event: MemoryEvent) -> None:
        try:
            if self.vector_db:
                self.vector_db.add(
                    id=event.id,
                    embedding=event.embedding,
                    metadata={
                        "content": event.content,
                        "source_type": event.source_type.value,
                        "trust_level": event.trust_level,
                        "session_id": event.session_id,
                        "timestamp": event.timestamp.isoformat(),
                    },
                )
        except Exception as e:
            logger.error("vector_db_store_failed", error=str(e), event_id=event.id)

    def _audit_event(self, event: MemoryEvent, operation: str) -> None:
        try:
            if self.audit_store:
                self.audit_store.log_operation(
                    operation=operation,
                    event_id=event.id,
                    timestamp=datetime.now(timezone.utc),
                    metadata={
                        "content_length": len(event.content),
                        "source_type": event.source_type.value,
                        "trust_level": event.trust_level,
                        "session_id": event.session_id,
                    },
                )
        except Exception as e:
            logger.error("audit_store_failed", error=str(e), event_id=event.id)

    def _audit_read(
        self,
        original_query: str,
        processed_query: str,
        results: List[Any],
        session_id: str,
    ) -> None:
        try:
            if self.audit_store:
                self.audit_store.log_read(
                    original_query=original_query,
                    processed_query=processed_query,
                    result_count=len(results),
                    session_id=session_id,
                    timestamp=datetime.now(timezone.utc),
                )
        except Exception as e:
            logger.error("audit_read_failed", error=str(e), session_id=session_id[:8])

    def add_pre_write_hook(self, hook: Callable[[MemoryEvent], MemoryEvent]) -> None:
        self.pre_write_hooks.append(hook)

    def add_post_write_hook(self, hook: Callable[[MemoryEvent], None]) -> None:
        self.post_write_hooks.append(hook)

    def add_pre_read_hook(self, hook: Callable[[str], str]) -> None:
        self.pre_read_hooks.append(hook)

    def add_post_read_hook(self, hook: Callable[[List[Any]], List[Any]]) -> None:
        self.post_read_hooks.append(hook)
