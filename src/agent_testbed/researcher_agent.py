"""
ResearcherAgent - LangGraph-based agent that reads external documents/web
and stores results into the shared Qdrant memory via the instrumentation middleware.
This agent simulates the INDIRECT INJECTION attack vector:
external content -> agent reads -> stores into shared memory.
"""
from typing import Any, Dict, List, TypedDict, Annotated
import uuid
import operator
import structlog
from sentence_transformers import SentenceTransformer
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage

from src.instrumentation import MemoryMiddleware, SourceType

logger = structlog.get_logger()


class ResearcherState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    documents: List[str]            # raw documents/web content to ingest
    stored_event_ids: List[str]     # IDs of events stored this run
    agent_id: str


class ResearcherAgent:
    """
    LangGraph-based Researcher Agent.
    Reads a list of external documents and stores each chunk into
    the shared Qdrant memory with SourceType.WEB_DOCUMENT (trust_level ~0.3).
    """

    def __init__(
        self,
        agent_id: str = "researcher-001",
        middleware: MemoryMiddleware = None,
        embed_model: str = "all-MiniLM-L6-v2",
    ):
        self.agent_id = agent_id
        self.middleware = middleware
        self.embedder = SentenceTransformer(embed_model)
        self.graph = self._build_graph()
        logger.info("researcher_agent_initialized", agent_id=agent_id)

    # ------------------------------------------------------------------
    # Graph nodes
    # ------------------------------------------------------------------

    def _node_embed_and_store(self, state: ResearcherState) -> Dict[str, Any]:
        """Embed each document chunk and write to shared memory via middleware."""
        stored_ids = []
        for doc in state["documents"]:
            embedding = self.embedder.encode(doc).tolist()
            event = self.middleware.intercept_write(
                content=doc,
                source_type=SourceType.WEB_DOCUMENT,
                session_id=state["agent_id"],
                metadata={"agent_id": state["agent_id"], "chunk_id": str(uuid.uuid4())[:8]},
                embedding=embedding,
            )
            stored_ids.append(event.id)
            logger.info("researcher_stored_chunk", event_id=event.id[:8],
                        trust=event.trust_level, content_preview=doc[:60])

        summary_msg = AIMessage(
            content=f"ResearcherAgent stored {len(stored_ids)} document chunks into shared memory."
        )
        return {"stored_event_ids": stored_ids, "messages": [summary_msg]}

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> Any:
        g = StateGraph(ResearcherState)
        g.add_node("embed_and_store", self._node_embed_and_store)
        g.set_entry_point("embed_and_store")
        g.add_edge("embed_and_store", END)
        return g.compile()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, documents: List[str]) -> List[str]:
        """
        Ingest a list of document strings into shared memory.
        Returns list of stored MemoryEvent IDs.
        """
        initial_state: ResearcherState = {
            "messages": [HumanMessage(content=f"Ingest {len(documents)} documents.")],
            "documents": documents,
            "stored_event_ids": [],
            "agent_id": self.agent_id,
        }
        result = self.graph.invoke(initial_state)
        return result["stored_event_ids"]
