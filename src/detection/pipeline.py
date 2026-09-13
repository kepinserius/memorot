from typing import List, Dict, Any, Optional
import structlog
import yaml
from pathlib import Path

from src.instrumentation.models import MemoryEvent
from src.audit.store import AuditStore

from .provenance_rules import ProvenanceRuleChecker
from .semantic_drift import SemanticDriftDetector
from .outlier_detection import OutlierDetector
from .injection_classifier import InjectionPatternClassifier
from .models import DetectionResult, DecisionType

logger = structlog.get_logger()


class DetectionPipeline:
    def __init__(
        self,
        config_path: str = "config/detector_config.yaml",
        thresholds_path: str = "config/thresholds.yaml",
        audit_store: Optional[AuditStore] = None,
    ):
        self.config = self._load_config(config_path)
        self.thresholds = self._load_config(thresholds_path)
        self.audit_store = audit_store

        detector_weights = self.config.get("detector_weights", {})
        self.weights = {
            "provenance_rules": detector_weights.get("provenance_rules", 0.3),
            "semantic_drift": detector_weights.get("semantic_drift", 0.4),
            "outlier_detection": detector_weights.get("outlier_detection", 0.2),
            "injection_classifier": detector_weights.get("injection_classifier", 0.1),
        }

        self.provenance_checker = ProvenanceRuleChecker(
            audit_store=audit_store,
            trust_differential_threshold=self.thresholds.get("detection_thresholds", {}).get("provenance_rule", 0.5),
        )

        self.semantic_drift = SemanticDriftDetector(
            contradiction_threshold=self.thresholds.get("detection_thresholds", {}).get("semantic_contradiction", 0.7),
        )

        self.outlier_detector = OutlierDetector(
            anomaly_threshold=self.thresholds.get("detection_thresholds", {}).get("outlier_anomaly", 2.0),
        )

        self.injection_classifier = InjectionPatternClassifier(
            use_llm_as_judge=self.config.get("models", {}).get("injection_classifier", {}).get("type") == "llm_as_judge"
        )

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        path = Path(config_path)
        if not path.exists():
            return {}
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def process(self, event: MemoryEvent, historical_events: Optional[List[MemoryEvent]] = None) -> DetectionResult:
        logger.info("detection_pipeline_start", event_id=event.id, content_length=len(event.content))

        if historical_events is None:
            historical_events = []

        all_results = []

        provenance_result = self.provenance_checker.check(event, historical_events)
        all_results.append(provenance_result)

        semantic_result = self.semantic_drift.detect(event, historical_events)
        all_results.append(semantic_result)

        outlier_result = self.outlier_detector.detect(event, historical_events)
        all_results.append(outlier_result)

        suspicion_aggregate = self._calculate_aggregate_suspicion(all_results)
        classifier_threshold = self.thresholds.get("detection_thresholds", {}).get("classifier_threshold", 0.5)

        if suspicion_aggregate > classifier_threshold:
            classifier_result = self.injection_classifier.classify(event)
            all_results.append(classifier_result)
        else:
            classifier_result = DetectionResult(
                event_id=event.id,
                detector_type="injection_classifier",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "skipped_low_suspicion", "suspicion_aggregate": suspicion_aggregate},
            )
            all_results.append(classifier_result)

        final_result = self._aggregate_results(all_results)

        if self.audit_store:
            self._log_detection_results(event.id, all_results, final_result)

        logger.info(
            "detection_pipeline_complete",
            event_id=event.id,
            final_decision=final_result.decision.value,
            final_suspicion=final_result.suspicion_score,
            detectors_used=len(all_results),
        )

        return final_result

    def _calculate_aggregate_suspicion(self, results: List[DetectionResult]) -> float:
        if not results:
            return 0.0

        weighted_sum = 0.0
        weight_sum = 0.0

        for result in results:
            weight = self.weights.get(result.detector_type, 0.25)
            weighted_sum += result.suspicion_score * weight
            weight_sum += weight

        return weighted_sum / weight_sum if weight_sum > 0 else 0.0

    def _aggregate_results(self, results: List[DetectionResult]) -> DetectionResult:
        if not results:
            return DetectionResult(
                event_id="unknown",
                detector_type="pipeline",
                suspicion_score=0.0,
                decision=DecisionType.CLEAN,
                details={"reason": "no_detector_results"},
            )

        aggregate_suspicion = self._calculate_aggregate_suspicion(results)

        decisions_count = {
            DecisionType.CLEAN: 0,
            DecisionType.SUSPICIOUS: 0,
            DecisionType.MALICIOUS: 0,
        }

        for result in results:
            decisions_count[result.decision] += 1

        if decisions_count[DecisionType.MALICIOUS] > 0:
            final_decision = DecisionType.MALICIOUS
        elif decisions_count[DecisionType.SUSPICIOUS] > 0:
            final_decision = DecisionType.SUSPICIOUS
        else:
            final_decision = DecisionType.CLEAN

        quarantine_threshold = self.thresholds.get("quarantine", {}).get("suspicion_threshold", 0.6)

        if final_decision == DecisionType.CLEAN and aggregate_suspicion > quarantine_threshold:
            final_decision = DecisionType.SUSPICIOUS

        return DetectionResult(
            event_id=results[0].event_id,
            detector_type="pipeline",
            suspicion_score=aggregate_suspicion,
            decision=final_decision,
            details={
                "individual_results": [r.to_dict() for r in results],
                "decisions_count": {k.value: v for k, v in decisions_count.items()},
                "aggregate_suspicion": aggregate_suspicion,
            },
            confidence=0.9,
        )

    def _log_detection_results(
        self,
        event_id: str,
        individual_results: List[DetectionResult],
        final_result: DetectionResult,
    ) -> None:
        if not self.audit_store:
            return

        try:
            from datetime import datetime
            import json

            metadata = {
                "final_decision": final_result.decision.value,
                "final_suspicion": final_result.suspicion_score,
                "detectors_used": len(individual_results),
                "individual_results": [r.to_dict() for r in individual_results],
            }

            self.audit_store.log_operation(
                operation="detection_completed",
                event_id=event_id,
                timestamp=datetime.utcnow(),
                metadata=metadata,
            )
        except Exception as e:
            logger.error("detection_log_failed", error=str(e), event_id=event_id)
