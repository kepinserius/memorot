from typing import List, Dict, Any, Optional
import structlog
from langchain.memory import ConversationBufferMemory

from src.instrumentation import MemoryMiddleware, MemoryEvent, SourceType
from src.vectorstore.chroma_client import VectorDBClient

logger = structlog.get_logger()


class InstrumentedMemory:
    def __init__(
        self,
        middleware: MemoryMiddleware,
        session_id: str = "default-session",
        user_id: Optional[str] = None,
    ):
        self.middleware = middleware
        self.session_id = session_id
        self.user_id = user_id
        
        self.buffer_memory = ConversationBufferMemory(memory_key="chat_history")
        
        logger.info("instrumented_memory_initialized", session_id=session_id[:8])

    def save_memory(
        self,
        content: str,
        source_type: SourceType = SourceType.USER_ANONYMOUS,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryEvent:
        event = self.middleware.intercept_write(
            content=content,
            source_type=source_type,
            session_id=self.session_id,
            user_id=self.user_id,
            metadata=metadata,
        )

        self.buffer_memory.save_context(
            {"input": f"[Memory: {source_type.value}]"},
            {"output": content},
        )

        logger.info(
            "memory_saved",
            event_id=event.id[:8],
            content_length=len(content),
            source_type=source_type.value,
            trust_level=event.trust_level,
        )

        return event

    def search_memory(
        self,
        query: str,
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        results = self.middleware.intercept_read(
            query=query,
            session_id=self.session_id,
            limit=limit,
            filters=filters,
        )

        logger.info(
            "memory_searched",
            query=query[:50],
            results_count=len(results),
            session_id=self.session_id[:8],
        )

        return results

    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        buffer_vars = self.buffer_memory.load_memory_variables(inputs)
        
        recent_memories = self.search_memory(query="", limit=5)
        
        memory_text = buffer_vars.get("chat_history", "")
        
        if recent_memories:
            memory_text += "\n\nRecent persistent memories:\n"
            for i, result in enumerate(recent_memories[:3]):
                metadata = result.get("metadata", {})
                content = metadata.get("content", "")
                memory_text += f"{i+1}. {content[:100]}\n"

        return {"chat_history": memory_text}

    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]) -> None:
        self.buffer_memory.save_context(inputs, outputs)

        if "input" in inputs and "output" in outputs:
            content = f"Q: {inputs['input']}\nA: {outputs['output']}"
            
            self.save_memory(
                content=content,
                source_type=SourceType.INTER_AGENT,
                metadata={"context_type": "conversation"},
            )

    def clear(self) -> None:
        self.buffer_memory.clear()
        
        logger.info("memory_cleared", session_id=self.session_id[:8])

    def get_conversation_history(self) -> List[Dict[str, Any]]:
        variables = self.load_memory_variables({})
        history_text = variables.get("chat_history", "")

        if not history_text:
            return []

        lines = history_text.split("\n")
        conversation = []
        current_q = None

        for line in lines:
            if line.startswith("Human:") or line.startswith("Q:"):
                current_q = line.split(":", 1)[1].strip()
            elif line.startswith("AI:") or line.startswith("A:") and current_q:
                current_a = line.split(":", 1)[1].strip()
                conversation.append({"question": current_q, "answer": current_a})
                current_q = None

        return conversation
