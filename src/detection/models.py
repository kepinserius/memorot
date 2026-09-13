from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum


class DecisionType(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class DetectionResult:
    event_id: str
    detector_type: str
    suspicion_score: float
    decision: DecisionType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "detector_type": self.detector_type,
            "suspicion_score": self.suspicion_score,
            "decision": self.decision.value,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionResult":
        return cls(
            event_id=data["event_id"],
            detector_type=data["detector_type"],
            suspicion_score=data["suspicion_score"],
            decision=DecisionType(data["decision"]),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if isinstance(data.get("timestamp"), str)
            else data.get("timestamp", datetime.utcnow()),
            details=data.get("details", {}),
            confidence=data.get("confidence", 1.0),
        )
