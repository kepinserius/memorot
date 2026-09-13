from typing import List, Dict, Any, Optional
import structlog
from src.instrumentation.models import MemoryEvent
from src.audit.store import AuditStore
from .models import DetectionResult, DecisionType

logger = structlog.get_logger()


class ProvenanceRuleChecker:
    def __init__(self, audit_store: Optional[AuditStore] = None, trust_differential_threshold: float = 0.5):
        self.audit_store = audit_store
        self.trust_differential_threshold = trust_differential_threshold

    def check(self, event: MemoryEvent, historical_events: List[MemoryEvent]) -> DetectionResult:
        if not historical_events:
            return DetectionResult(
                event_id=event.id,
                detector_type="provenance_rules",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "no_historical_events"},
            )

        suspicion_scores = []
        flagged_conflicts = []

        for hist_event in historical_events:
            if hist_event.id == event.id:
                continue

            trust_diff = abs(hist_event.trust_level - event.trust_level)

            if (
                event.trust_level < self.trust_differential_threshold
                and hist_event.trust_level > (1.0 - self.trust_differential_threshold)
                and trust_diff > self.trust_differential_threshold
            ):
                suspicion_scores.append(trust_diff)
                flagged_conflicts.append(
                    {
                        "conflicting_event_id": hist_event.id,
                        "event_trust": event.trust_level,
                        "historical_trust": hist_event.trust_level,
                        "trust_differential": trust_diff,
                    }
                )

        if not suspicion_scores:
            return DetectionResult(
                event_id=event.id,
                detector_type="provenance_rules",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "no_trust_conflicts"},
            )

        avg_suspicion = sum(suspicion_scores) / len(suspicion_scores)
        decision = DecisionType.SUSPICIOUS if avg_suspicion > 0.5 else DecisionType.CLEAN

        return DetectionResult(
            event_id=event.id,
            detector_type="provenance_rules",
            suspicion_score=min(avg_suspicion, 1.0),
            decision=decision,
            details={
                "conflicting_events": flagged_conflicts,
                "avg_trust_differential": avg_suspicion,
            },
            confidence=1.0,
        )
