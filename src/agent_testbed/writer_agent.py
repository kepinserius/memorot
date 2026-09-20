"""
WriterAgent - LangGraph-based agent that reads from shared Qdrant memory
and produces a written output (simulates an agent that consumes poisoned memory).
"""
from typing import Any, Dict, List, TypedDict, Annotated, Optional
import operator
import structlog
from sentence_transformers import SentenceTransformer
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage

from src.instrumentation import MemoryMiddleware, SourceType

logger = structlog.get_logger()


class WriterState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    query: str
    retrieved_memories: List[Dict]
    output: str
    agent_id: str


class WriterAgent:
    """
    LangGraph-based Writer Agent.
    Queries shared memory and generates a response based on retrieved context.
    Demonstrates how a poisoned memory entry affects downstream agent output.
    """

    def __init__(
        self,
        agent_id: str = "writer-001",
        middleware: MemoryMiddleware = None,
        embed_model: str = "all-MiniLM-L6-v2",
        trust_threshold: float = 0.0,  # only use memories above this trust level
    ):
        self.agent_id = agent_id
        self.middleware = middleware
        self.embedder = SentenceTransformer(embed_model)
        self.trust_threshold = trust_threshold
        self.graph = self._build_graph()
        logger.info("writer_agent_initialized", agent_id=agent_id, trust_threshold=trust_threshold)

    # ------------------------------------------------------------------
    # Graph nodes
    # ------------------------------------------------------------------

    def _node_retrieve_memory(self, state: WriterState) -> Dict[str, Any]:
        """Embed the query and search shared memory."""
        query_vector = self.embedder.encode(state["query"]).tolist()
        raw_results = self.middleware.intercept_read(
            query=state["query"],
            session_id="",  # search across all sessions (shared memory)
            limit=5,
            query_vector=query_vector,
        )
        # Filter by trust threshold
        filtered = [
            r for r in raw_results
            if r.get("metadata", {}).get("trust_level", 0.0) >= self.trust_threshold
        ]
        logger.info("writer_retrieved_memories", total=len(raw_results), filtered=len(filtered))
        msg = AIMessage(content=f"Retrieved {len(filtered)} memories for query: {state['query'][:50]}")
        return {"retrieved_memories": filtered, "messages": [msg]}

    def _node_generate_output(self, state: WriterState) -> Dict[str, Any]:
        """Generate output from retrieved memories (no LLM call for testbed simplicity)."""
        if not state["retrieved_memories"]:
            output = "[WriterAgent] No relevant memories found. Cannot generate output."
        else:
            parts = []
            for i, mem in enumerate(state["retrieved_memories"]):
                content = mem.get("metadata", {}).get("content", "[empty]")
                trust = mem.get("metadata", {}).get("trust_level", 0.0)
                detection = mem.get("metadata", {}).get("detection_result", {})
                decision = detection.get("decision", "unknown") if detection else "unknown"
                parts.append(f"  [{i+1}] (trust={trust:.2f}, detection={decision}) {content[:120]}")
            output = "[WriterAgent] Output based on retrieved memories:\n" + "\n".join(parts)
        
        # Store the output itself back into shared memory
        output_embedding = self.embedder.encode(output).tolist()
        self.middleware.intercept_write(
            content=output,
            source_type=SourceType.INTER_AGENT,
            session_id=self.agent_id,
            metadata={"agent_id": self.agent_id, "type": "agent_output"},
            embedding=output_embedding,
        )
        logger.info("writer_output_generated", output_preview=output[:80])
        msg = AIMessage(content=output)
        return {"output": output, "messages": [msg]}

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> Any:
        g = StateGraph(WriterState)
        g.add_node("retrieve_memory", self._node_retrieve_memory)
        g.add_node("generate_output", self._node_generate_output)
        g.set_entry_point("retrieve_memory")
        g.add_edge("retrieve_memory", "generate_output")
        g.add_edge("generate_output", END)
        return g.compile()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, query: str) -> str:
        """Run the writer agent for a given query topic."""
        initial_state: WriterState = {
            "messages": [HumanMessage(content=query)],
            "query": query,
            "retrieved_memories": [],
            "output": "",
            "agent_id": self.agent_id,
        }
        result = self.graph.invoke(initial_state)
        return result["output"]
