"""
Multi-Agent Graph Orchestrator
------------------------------
Orchestrates ResearcherAgent and WriterAgent with a shared Qdrant memory store.
All agents connect to the same QdrantVectorStore through MemoryMiddleware,
enabling cross-agent memory poisoning to propagate automatically.
"""
from typing import Optional
import structlog

from src.vectorstore.qdrant_client import QdrantVectorStore
from src.instrumentation.middleware import MemoryMiddleware
from src.instrumentation.models import SourceType
from src.audit.store import AuditStore
from src.detection.pipeline import DetectionPipeline
from .researcher_agent import ResearcherAgent
from .writer_agent import WriterAgent

logger = structlog.get_logger()


class MultiAgentSystem:
    """
    Shared-memory multi-agent system.
    Architecture:
        [ResearcherAgent] ---write-->
                                     [Shared QdrantVectorStore] --read--> [WriterAgent]
        Both go through the same MemoryMiddleware (instrumentation + detection).
    """

    def __init__(
        self,
        qdrant_host: str = ":memory:",
        qdrant_path: Optional[str] = None,
        qdrant_port: int = 6333,
        collection_name: str = "shared_memory",
        embed_model: str = "all-MiniLM-L6-v2",
        enable_detection: bool = True,
        writer_trust_threshold: float = 0.0,
    ):
        # Shared vector store
        self.vector_store = QdrantVectorStore(
            collection_name=collection_name,
            host=qdrant_host,
            port=qdrant_port,
            path=qdrant_path,
        )

        # Shared audit store
        self.audit_store = AuditStore()

        # Detection pipeline
        self.detection_pipeline = DetectionPipeline(audit_store=self.audit_store) if enable_detection else None

        # Shared middleware (single instance, both agents use it)
        self.middleware = MemoryMiddleware(
            vector_db_client=self.vector_store,
            audit_store=self.audit_store,
            detection_pipeline=self.detection_pipeline,
        )

        # Agents
        self.researcher = ResearcherAgent(
            agent_id="researcher-001",
            middleware=self.middleware,
            embed_model=embed_model,
        )
        self.writer = WriterAgent(
            agent_id="writer-001",
            middleware=self.middleware,
            embed_model=embed_model,
            trust_threshold=writer_trust_threshold,
        )

        logger.info(
            "multi_agent_system_initialized",
            collection=collection_name,
            detection_enabled=enable_detection,
        )

    def researcher_ingest(self, documents: list) -> list:
        """Researcher ingests external documents into shared memory."""
        logger.info("researcher_ingest_start", doc_count=len(documents))
        return self.researcher.ingest(documents)

    def writer_query(self, query: str) -> str:
        """Writer retrieves from shared memory and produces output."""
        logger.info("writer_query_start", query=query[:60])
        return self.writer.write(query)

    def inject_poison(self, poison_content: str, source_type: SourceType = SourceType.WEB_DOCUMENT) -> str:
        """
        Directly inject a poisoned memory entry (for attack simulation).
        Returns the event ID.
        """
        from sentence_transformers import SentenceTransformer
        embedder = SentenceTransformer("all-MiniLM-L6-v2")
        embedding = embedder.encode(poison_content).tolist()
        event = self.middleware.intercept_write(
            content=poison_content,
            source_type=source_type,
            session_id="poison-injector",
            metadata={"is_poison": True, "source": "attack_simulation"},
            embedding=embedding,
        )
        logger.warning("poison_injected", event_id=event.id[:8], content_preview=poison_content[:60])
        return event.id

    def get_memory_stats(self) -> dict:
        return {
            "total_vectors": self.vector_store.count(),
            "audit_events": len(self.audit_store.get_events(limit=10000)),
            "detection_enabled": self.detection_pipeline is not None,
        }
