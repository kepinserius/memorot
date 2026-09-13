from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
import json


@dataclass
class EventLogEntry:
    id: str
    operation: str
    event_id: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "operation": self.operation,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class SnapshotMetadata:
    id: str
    timestamp: datetime
    event_count: int
    checkpoint_event_ids: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_count": self.event_count,
            "checkpoint_event_ids": self.checkpoint_event_ids,
            "metadata": self.metadata,
        }
