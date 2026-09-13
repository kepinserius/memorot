from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from enum import Enum


class VerificationStatus(Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class QuarantineEntry:
    id: str
    event_id: str
    suspicion_reason: str
    suspicion_score: float
    verification_status: VerificationStatus = VerificationStatus.PENDING
    ttl_days: int = 7
    created_at: datetime = field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def expiry_time(self) -> datetime:
        return self.created_at + timedelta(days=self.ttl_days)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expiry_time

    @property
    def hours_remaining(self) -> float:
        if self.is_expired:
            return 0.0
        delta = self.expiry_time - datetime.utcnow()
        return delta.total_seconds() / 3600

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "suspicion_reason": self.suspicion_reason,
            "suspicion_score": self.suspicion_score,
            "verification_status": self.verification_status.value,
            "ttl_days": self.ttl_days,
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "expiry_time": self.expiry_time.isoformat(),
            "is_expired": self.is_expired,
            "hours_remaining": self.hours_remaining,
            "metadata": self.metadata,
        }
