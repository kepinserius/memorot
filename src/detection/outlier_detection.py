from typing import List, Dict, Any
import structlog
from sentence_transformers import SentenceTransformer
import numpy as np
import scipy.stats as stats

from src.instrumentation.models import MemoryEvent
from .models import DetectionResult, DecisionType

logger = structlog.get_logger()


class OutlierDetector:
    def __init__(
        self,
        embedding_model_name: str = "all-MiniLM-L6-v2",
        anomaly_threshold: float = 2.0,
        min_historical_events: int = 100,
    ):
        self.embedding_model = SentenceTransformer(embedding_model_name)
        self.anomaly_threshold = anomaly_threshold
        self.min_historical_events = min_historical_events
        self.historical_profile: Dict[str, Any] = {
            "perplexities": [],
            "sentence_lengths": [],
            "vocabulary_counts": [],
            "embeddings_mean": None,
            "embeddings_std": None,
        }

    def detect(self, event: MemoryEvent, historical_events: List[MemoryEvent]) -> DetectionResult:
        if len(historical_events) < self.min_historical_events:
            self._update_profile(event, historical_events)
            return DetectionResult(
                event_id=event.id,
                detector_type="outlier_detection",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "insufficient_historical_data"},
            )

        features = self._extract_features(event)
        anomaly_scores = self._calculate_anomaly_scores(features)
        avg_anomaly_score = sum(anomaly_scores.values()) / len(anomaly_scores)

        is_outlier = any(
            score > self.anomaly_threshold for score in anomaly_scores.values()
        )

        self._update_profile(event, historical_events)

        return DetectionResult(
            event_id=event.id,
            detector_type="outlier_detection",
            suspicion_score=min(avg_anomaly_score / self.anomaly_threshold, 1.0),
            decision=DecisionType.SUSPICIOUS if is_outlier else DecisionType.CLEAN,
            details={
                "feature_anomaly_scores": anomaly_scores,
                "is_outlier": is_outlier,
                "extracted_features": features,
            },
            confidence=0.7,
        )

    def _extract_features(self, event: MemoryEvent) -> Dict[str, Any]:
        content = event.content

        perplexity = self._calculate_perplexity(content)
        sentence_length = len(content.split())
        vocabulary_count = len(set(content.lower().split()))

        if not event.embedding:
            event.embedding = self.embedding_model.encode(content).tolist()

        return {
            "perplexity": perplexity,
            "sentence_length": sentence_length,
            "vocabulary_count": vocabulary_count,
            "embedding": event.embedding,
        }

    def _calculate_perplexity(self, text: str) -> float:
        words = text.split()
        if len(words) < 2:
            return 0.0

        word_counts = {}
        for word in words:
            word_counts[word] = word_counts.get(word, 0) + 1

        total_words = len(words)
        entropy = 0.0
        for count in word_counts.values():
            prob = count / total_words
            entropy += prob * np.log2(prob)

        perplexity = 2 ** (-entropy)
        return perplexity

    def _calculate_anomaly_scores(self, features: Dict[str, Any]) -> Dict[str, float]:
        scores = {}

        perplexity_scores = self.historical_profile["perplexities"]
        if perplexity_scores:
            scores["perplexity"] = self._z_score(
                features["perplexity"], perplexity_scores
            )

        sentence_lengths = self.historical_profile["sentence_lengths"]
        if sentence_lengths:
            scores["sentence_length"] = self._z_score(
                features["sentence_length"], sentence_lengths
            )

        vocabulary_counts = self.historical_profile["vocabulary_counts"]
        if vocabulary_counts:
            scores["vocabulary_count"] = self._z_score(
                features["vocabulary_count"], vocabulary_counts
            )

        if (
            self.historical_profile["embeddings_mean"] is not None
            and self.historical_profile["embeddings_std"] is not None
        ):
            embedding_z = self._embedding_distance(
                features["embedding"],
                self.historical_profile["embeddings_mean"],
                self.historical_profile["embeddings_std"],
            )
            scores["embedding_distance"] = embedding_z

        return scores

    def _z_score(self, value: float, data: List[float]) -> float:
        if len(data) < 2:
            return 0.0
        mean = np.mean(data)
        std = np.std(data)
        if std == 0:
            return 0.0
        return abs((value - mean) / std)

    def _embedding_distance(
        self, embedding: List[float], mean: np.ndarray, std: np.ndarray
    ) -> float:
        embedding_np = np.array(embedding)
        normalized = (embedding_np - mean) / (std + 1e-8)
        return float(np.linalg.norm(normalized))

    def _update_profile(self, event: MemoryEvent, historical_events: List[MemoryEvent]) -> None:
        features = self._extract_features(event)

        self.historical_profile["perplexities"].append(features["perplexity"])
        self.historical_profile["sentence_lengths"].append(features["sentence_length"])
        self.historical_profile["vocabulary_counts"].append(features["vocabulary_count"])

        embeddings = [e.embedding for e in historical_events if e.embedding]
        if embeddings:
            self.historical_profile["embeddings_mean"] = np.mean(embeddings, axis=0)
            self.historical_profile["embeddings_std"] = np.std(embeddings, axis=0)
