from typing import List, Dict, Any, Optional
import structlog
from langchain.memory import ConversationBufferMemory
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate

from src.instrumentation import MemoryMiddleware, SourceType
from src.vectorstore.chroma_client import VectorDBClient
from src.audit.store import AuditStore
from src.detection.pipeline import DetectionPipeline
from .memory_instrumented import InstrumentedMemory

logger = structlog.get_logger()


class BaseAgent:
    def __init__(
        self,
        agent_id: str = "test-agent-001",
        use_instrumentation: bool = True,
        llm_model: str = "gpt-3.5-turbo",
    ):
        self.agent_id = agent_id
        self.use_instrumentation = use_instrumentation

        self.vector_db = VectorDBClient(collection_name=f"agent_{agent_id}")
        self.audit_store = AuditStore()

        if use_instrumentation:
            self.detection_pipeline = DetectionPipeline(audit_store=self.audit_store)
            self.middleware = MemoryMiddleware(
                vector_db_client=self.vector_db,
                audit_store=self.audit_store,
                detection_pipeline=self.detection_pipeline,
            )
            self.memory = InstrumentedMemory(
                middleware=self.middleware,
                session_id=agent_id,
            )
        else:
            self.middleware = None
            self.detection_pipeline = None
            self.memory = ConversationBufferMemory(memory_key="chat_history")

        self.llm = ChatOpenAI(temperature=0.7, model_name=llm_model)

        self.tools = self._create_tools()
        self.agent_executor = self._create_agent()

        logger.info(
            "base_agent_initialized",
            agent_id=agent_id,
            instrumented=use_instrumentation,
        )

    def _create_tools(self) -> List[Tool]:
        tools = [
            Tool(
                name="remember",
                func=self._remember_tool,
                description="Store information in long-term memory. Input should be a statement to remember.",
            ),
            Tool(
                name="recall",
                func=self._recall_tool,
                description="Retrieve information from long-term memory. Input should be a query.",
            ),
        ]
        return tools

    def _remember_tool(self, content: str) -> str:
        try:
            if self.use_instrumentation:
                event = self.memory.save_memory(content, SourceType.TOOL_RESULT)
                return f"Stored in memory (ID: {event.id[:8]}, Trust: {event.trust_level:.2f})"
            else:
                self.memory.save_context({"input": content}, {"output": "remembered"})
                return "Stored in memory"
        except Exception as e:
            logger.error("remember_tool_failed", error=str(e))
            return f"Failed to store: {str(e)}"

    def _recall_tool(self, query: str) -> str:
        try:
            if self.use_instrumentation:
                results = self.memory.search_memory(query, limit=3)
                if not results:
                    return "No relevant memories found"
                
                memories = []
                for result in results:
                    metadata = result.get("metadata", {})
                    content = metadata.get("content", "")
                    trust = metadata.get("trust_level", 0.0)
                    memories.append(f"[Trust: {trust:.2f}] {content[:100]}")
                
                return "\n".join(memories)
            else:
                return self.memory.load_memory_variables({}).get("chat_history", "No memories")
        except Exception as e:
            logger.error("recall_tool_failed", error=str(e))
            return f"Failed to recall: {str(e)}"

    def _create_agent(self) -> AgentExecutor:
        template = """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}"""

        prompt = PromptTemplate.from_template(template)
        
        agent = create_react_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=prompt,
        )

        return AgentExecutor(
            agent=agent,
            tools=self.tools,
            verbose=True,
            handle_parsing_errors=True,
        )

    def run(self, query: str) -> str:
        try:
            result = self.agent_executor.invoke({"input": query})
            return result.get("output", "No output generated")
        except Exception as e:
            logger.error("agent_run_failed", error=str(e), query=query[:50])
            return f"Error: {str(e)}"

    def chat(self, message: str, source_type: SourceType = SourceType.USER_VERIFIED) -> str:
        logger.info("agent_chat", message=message[:50])

        if self.use_instrumentation:
            self.memory.save_memory(f"User: {message}", source_type)

        response = self.run(message)

        if self.use_instrumentation:
            self.memory.save_memory(f"Assistant: {response}", SourceType.SYSTEM)

        return response

    def get_memory_stats(self) -> Dict[str, Any]:
        if not self.use_instrumentation:
            return {"instrumented": False}

        events = self.audit_store.get_events(limit=1000)
        
        return {
            "instrumented": True,
            "total_events": len(events),
            "agent_id": self.agent_id,
        }
