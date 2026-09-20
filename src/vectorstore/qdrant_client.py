"""Qdrant Vector Store Client - drop-in replacement for Chroma/ChromaDB client.

Compatible with qdrant-client >= 1.9 (uses query_points API, not legacy search).
"""
from typing import Optional, Dict, Any, List
import structlog
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams, PointStruct, Filter,
    FieldCondition, MatchValue, PointIdsList,
)

logger = structlog.get_logger()
VECTOR_DIM = 384  # all-MiniLM-L6-v2


class QdrantVectorStore:
    """
    Thin wrapper over QdrantClient with the same interface as the old VectorDBClient:
        add(id, embedding, metadata)
        search(query, session_id, limit, filters, query_vector) -> list
        get_by_id(id) -> dict | None
        delete(id)
        count() -> int
    """

    def __init__(
        self,
        collection_name: str = "memory_events",
        host: str = ":memory:",
        port: int = 6333,
        path: Optional[str] = None,
        vector_size: int = VECTOR_DIM,
    ):
        self.collection_name = collection_name
        self.vector_size = vector_size
        if host == ":memory:":
            self.client = QdrantClient(":memory:")
            logger.info("qdrant_in_memory_mode")
        elif path:
            self.client = QdrantClient(path=path)
            logger.info("qdrant_local_path_mode", path=path)
        else:
            self.client = QdrantClient(host=host, port=port)
            logger.info("qdrant_remote_mode", host=host, port=port)
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        existing = [c.name for c in self.client.get_collections().collections]
        if self.collection_name not in existing:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
            )
            logger.info("qdrant_collection_created", collection=self.collection_name)

    def _build_filter(self, session_id=None, extra=None):
        conditions = []
        if session_id:
            conditions.append(FieldCondition(key="session_id", match=MatchValue(value=session_id)))
        if extra:
            for k, v in extra.items():
                if isinstance(v, (str, int, float, bool)):
                    conditions.append(FieldCondition(key=k, match=MatchValue(value=v)))
        return Filter(must=conditions) if conditions else None

    def add(self, id: str, embedding: List[float], metadata: Dict[str, Any]) -> None:
        """Upsert a single memory event as a Qdrant point."""
        try:
            self.client.upsert(
                collection_name=self.collection_name,
                points=[PointStruct(id=id, vector=embedding, payload=metadata)],
            )
            logger.info("qdrant_upsert_success", id=id[:8])
        except Exception as e:
            logger.error("qdrant_upsert_failed", id=id, error=str(e))
            raise

    def search(
        self,
        query: str = "",
        session_id: str = "",
        limit: int = 10,
        filters=None,
        query_vector: Optional[List[float]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Similarity search via query_points (qdrant-client >= 1.9).
        Requires query_vector (embed upstream).
        Returns list of {id, score, metadata} dicts.
        """
        if query_vector is None:
            logger.warning("qdrant_search_no_vector", hint="Provide query_vector")
            return []
        try:
            response = self.client.query_points(
                collection_name=self.collection_name,
                query=query_vector,
                query_filter=self._build_filter(session_id or None, filters),
                limit=limit,
                with_payload=True,
            )
            return [
                {"id": str(p.id), "score": p.score, "metadata": p.payload or {}}
                for p in response.points
            ]
        except Exception as e:
            logger.error("qdrant_search_failed", error=str(e))
            return []

    def get_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        try:
            pts = self.client.retrieve(
                collection_name=self.collection_name,
                ids=[id],
                with_payload=True,
                with_vectors=True,
            )
            if not pts:
                return None
            p = pts[0]
            return {"id": str(p.id), "embedding": p.vector, "metadata": p.payload or {}}
        except Exception as e:
            logger.error("qdrant_get_failed", id=id, error=str(e))
            return None

    def delete(self, id: str) -> None:
        try:
            self.client.delete(
                collection_name=self.collection_name,
                points_selector=PointIdsList(points=[id]),
            )
            logger.info("qdrant_delete_success", id=id[:8])
        except Exception as e:
            logger.error("qdrant_delete_failed", id=id, error=str(e))
            raise

    def count(self) -> int:
        return self.client.get_collection(self.collection_name).points_count or 0
