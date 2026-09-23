from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
import uuid


class SourceType(Enum):
    USER_VERIFIED = "user_verified"
    USER_ANONYMOUS = "user_anonymous"
    TOOL_RESULT = "tool_result"
    WEB_DOCUMENT = "web_document"
    INTER_AGENT = "inter_agent"
    SYSTEM = "system"


@dataclass
class MemoryEvent:
    id: str
    content: str
    embedding: Optional[List[float]] = None
    source_type: SourceType = SourceType.USER_ANONYMOUS
    trust_level: float = 0.5
    session_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    parent_event_id: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "embedding": self.embedding,
            "source_type": self.source_type.value,
            "trust_level": self.trust_level,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "parent_event_id": self.parent_event_id,
            "user_id": self.user_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MemoryEvent":
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            content=data["content"],
            embedding=data.get("embedding"),
            source_type=SourceType(data.get("source_type", "user_anonymous")),
            trust_level=data.get("trust_level", 0.5),
            session_id=data.get("session_id", ""),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else data.get("timestamp", datetime.now(timezone.utc)),
            parent_event_id=data.get("parent_event_id"),
            user_id=data.get("user_id"),
            metadata=data.get("metadata", {}),
        )
