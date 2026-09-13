from typing import Optional, Dict, Any
import chromadb
from chromadb.config import Settings
import structlog

logger = structlog.get_logger()


class VectorDBClient:
    def __init__(self, persist_directory: str = "data/chroma_db", collection_name: str = "memory_events"):
        self.persist_directory = persist_directory
        self.collection_name = collection_name
        self.client = chromadb.PersistentClient(path=persist_directory)
        self.collection = self.client.get_or_create_collection(name=collection_name)

    def add(
        self,
        id: str,
        embedding: list,
        metadata: Dict[str, Any],
    ) -> None:
        try:
            self.collection.add(
                ids=[id],
                embeddings=[embedding],
                metadatas=[metadata],
            )
            logger.info("vector_db_add_success", id=id)
        except Exception as e:
            logger.error("vector_db_add_failed", id=id, error=str(e))
            raise

    def search(
        self,
        query: str,
        session_id: str = "",
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None,
    ) -> list:
        try:
            where_filter = {}
            if session_id:
                where_filter["session_id"] = session_id
            if filters:
                where_filter.update(filters)

            results = self.collection.query(
                query_texts=[query] if isinstance(query, str) else None,
                n_results=limit,
                where=where_filter if where_filter else None,
            )
            
            return results
        except Exception as e:
            logger.error("vector_db_search_failed", error=str(e))
            return []

    def get_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        try:
            result = self.collection.get(ids=[id])
            if result and result["ids"]:
                return {
                    "id": result["ids"][0],
                    "embedding": result["embeddings"][0] if result.get("embeddings") else None,
                    "metadata": result["metadatas"][0] if result.get("metadatas") else {},
                }
            return None
        except Exception as e:
            logger.error("vector_db_get_failed", id=id, error=str(e))
            return None

    def delete(self, id: str) -> None:
        try:
            self.collection.delete(ids=[id])
            logger.info("vector_db_delete_success", id=id)
        except Exception as e:
            logger.error("vector_db_delete_failed", id=id, error=str(e))
            raise
