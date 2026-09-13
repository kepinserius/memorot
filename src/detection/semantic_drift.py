from typing import List, Optional
import structlog
from sentence_transformers import SentenceTransformer
from transformers import pipeline
import numpy as np

from src.instrumentation.models import MemoryEvent
from .models import DetectionResult, DecisionType

logger = structlog.get_logger()


class SemanticDriftDetector:
    def __init__(
        self,
        embedding_model_name: str = "all-MiniLM-L6-v2",
        nli_model_name: str = "microsoft/deberta-base-mnli",
        contradiction_threshold: float = 0.7,
        top_k: int = 10,
    ):
        self.embedding_model = SentenceTransformer(embedding_model_name)
        self.nli_classifier = pipeline("text-classification", model=nli_model_name)
        self.contradiction_threshold = contradiction_threshold
        self.top_k = top_k

    def detect(self, event: MemoryEvent, historical_events: List[MemoryEvent]) -> DetectionResult:
        if not historical_events:
            return DetectionResult(
                event_id=event.id,
                detector_type="semantic_drift",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "no_historical_events"},
            )

        if not event.embedding:
            event.embedding = self.embedding_model.encode(event.content).tolist()

        similar_events = self._find_similar_events(event, historical_events)

        if not similar_events:
            return DetectionResult(
                event_id=event.id,
                detector_type="semantic_drift",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "no_similar_events"},
            )

        contradiction_scores = []
        contradictions = []

        for similar_event in similar_events:
            nli_result = self.nli_classifier(
                f"{event.content} [SEP] {similar_event.content}",
                truncation=True,
                max_length=512,
            )[0]

            if nli_result["label"] == "CONTRADICTION":
                score = nli_result["score"]
                contradiction_scores.append(score)
                contradictions.append(
                    {
                        "historical_event_id": similar_event.id,
                        "contradiction_score": score,
                        "historical_content": similar_event.content[:100],
                    }
                )

        if not contradiction_scores:
            return DetectionResult(
                event_id=event.id,
                detector_type="semantic_drift",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"similar_events_checked": len(similar_events)},
            )

        avg_contradiction = sum(contradiction_scores) / len(contradiction_scores)
        decision = (
            DecisionType.SUSPICIOUS
            if avg_contradiction > self.contradiction_threshold
            else DecisionType.CLEAN
        )

        return DetectionResult(
            event_id=event.id,
            detector_type="semantic_drift",
            suspicion_score=min(avg_contradiction, 1.0),
            decision=decision,
            details={
                "contradictions": contradictions,
                "avg_contradiction_score": avg_contradiction,
                "similar_events_checked": len(similar_events),
            },
            confidence=0.8,
        )

    def _find_similar_events(
        self, event: MemoryEvent, historical_events: List[MemoryEvent]
    ) -> List[MemoryEvent]:
        if not event.embedding:
            return []

        similarities = []
        for hist_event in historical_events:
            if hist_event.id == event.id:
                continue

            if not hist_event.embedding:
                hist_event.embedding = self.embedding_model.encode(hist_event.content).tolist()

            similarity = self._cosine_similarity(event.embedding, hist_event.embedding)
            similarities.append((similarity, hist_event))

        similarities.sort(reverse=True, key=lambda x: x[0])
        return [event for _, event in similarities[: self.top_k]]

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        vec1_np = np.array(vec1)
        vec2_np = np.array(vec2)
        return float(np.dot(vec1_np, vec2_np) / (np.linalg.norm(vec1_np) * np.linalg.norm(vec2_np)))
