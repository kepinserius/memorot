import json
import yaml
from datetime import datetime
from typing import Dict, Any, List, Tuple
from pathlib import Path
import pandas as pd
import numpy as np
import structlog

from src.audit.store import AuditStore
from src.detection.pipeline import DetectionPipeline
from src.instrumentation import SourceType, MemoryEvent
from scripts.generate_attacks import AttackDatasetGenerator

logger = structlog.get_logger()


class DetectorEvaluator:
    def __init__(self, output_dir: str = "data/evaluation"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.audit_store = AuditStore()
        self.detection_pipeline = DetectionPipeline(audit_store=self.audit_store)
        self.attack_generator = AttackDatasetGenerator()

    def evaluate_dataset(
        self,
        dataset_id: str,
        sample_size: int = 100,
    ) -> Dict[str, Any]:
        logger.info("evaluating_dataset", dataset_id=dataset_id, sample_size=sample_size)

        dataset_info = self.attack_generator.load_dataset(dataset_id)
        if not dataset_info:
            return {"error": f"Dataset {dataset_id} not found"}

        dataset = dataset_info["dataset"]
        
        results = {}
        total_entries = 0
        total_correct = 0

        evaluation_start = datetime.now()

        for attack_type, entries in dataset.items():
            if attack_type == "controls":
                continue

            if not entries:
                continue

            sampled_entries = entries[:min(sample_size, len(entries))]
            type_results = self._evaluate_entries(sampled_entries, attack_type)

            results[attack_type] = type_results
            total_entries += len(sampled_entries)
            total_correct += type_results["correct_predictions"]

        evaluation_duration = (datetime.now() - evaluation_start).total_seconds()

        summary = self._calculate_summary(results, total_entries, total_correct)

        evaluation_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = self.output_dir / f"evaluation_{evaluation_id}.json"

        full_results = {
            "evaluation_id": evaluation_id,
            "dataset_id": dataset_id,
            "evaluated_at": datetime.now().isoformat(),
            "duration_seconds": evaluation_duration,
            "summary": summary,
            "detailed_results": results,
        }

        with open(result_file, "w") as f:
            json.dump(full_results, f, indent=2, default=str)

        logger.info(
            "evaluation_completed",
            evaluation_id=evaluation_id,
            total_entries=total_entries,
            accuracy=summary["accuracy"],
            duration_seconds=evaluation_duration,
        )

        return full_results

    def _evaluate_entries(
        self,
        entries: List[Dict[str, Any]],
        attack_type: str,
    ) -> Dict[str, Any]:
        results = {
            "attack_type": attack_type,
            "total_entries": len(entries),
            "correct_predictions": 0,
            "incorrect_predictions": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "true_positives": 0,
            "true_negatives": 0,
            "entry_details": [],
        }

        for entry in entries:
            content = entry["content"]
            ground_truth = entry["ground_truth"]

            memory_event = MemoryEvent(
                id=entry["id"],
                content=content,
                source_type=SourceType.USER_VERIFIED,
                trust_level=0.9,
                session_id="evaluation",
            )

            detection_result = self.detection_pipeline.process(memory_event)
            detector_decision = detection_result.decision.value
            suspicion_score = detection_result.suspicion_score

            prediction = self._map_decision_to_label(detector_decision, suspicion_score)

            is_correct = prediction == ground_truth

            if is_correct:
                results["correct_predictions"] += 1
                if ground_truth in ["suspicious", "malicious"]:
                    results["true_positives"] += 1
                else:
                    results["true_negatives"] += 1
            else:
                results["incorrect_predictions"] += 1
                if ground_truth in ["suspicious", "malicious"] and prediction == "clean":
                    results["false_negatives"] += 1
                elif ground_truth == "clean" and prediction in ["suspicious", "malicious"]:
                    results["false_positives"] += 1

            entry_detail = {
                "entry_id": entry["id"],
                "content": content[:100],
                "ground_truth": ground_truth,
                "prediction": prediction,
                "detector_decision": detector_decision,
                "suspicion_score": suspicion_score,
                "correct": is_correct,
                "false_positive": (ground_truth == "clean" and prediction in ["suspicious", "malicious"]),
                "false_negative": (ground_truth in ["suspicious", "malicious"] and prediction == "clean"),
            }

            results["entry_details"].append(entry_detail)

        return results

    def _map_decision_to_label(self, decision: str, suspicion_score: float) -> str:
        if decision == "malicious":
            return "malicious"
        elif decision == "suspicious":
            return "suspicious"
        elif decision == "clean" and suspicion_score > 0.3:
            return "suspicious"
        else:
            return "clean"

    def _calculate_summary(
        self,
        results: Dict[str, Dict[str, Any]],
        total_entries: int,
        total_correct: int,
    ) -> Dict[str, Any]:
        if total_entries == 0:
            return {"error": "No entries evaluated"}

        accuracy = total_correct / total_entries

        total_fp = sum(r.get("false_positives", 0) for r in results.values())
        total_fn = sum(r.get("false_negatives", 0) for r in results.values())
        total_tp = sum(r.get("true_positives", 0) for r in results.values())

        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        per_type_accuracy = {}
        for attack_type, type_results in results.items():
            if type_results["total_entries"] > 0:
                per_type_accuracy[attack_type] = type_results["correct_predictions"] / type_results["total_entries"]

        return {
            "total_entries": total_entries,
            "total_correct": total_correct,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "true_positives": total_tp,
            "per_type_accuracy": per_type_accuracy,
        }

    def generate_report(self, evaluation_id: str) -> Optional[str]:
        result_file = self.output_dir / f"evaluation_{evaluation_id}.json"
        
        if not result_file.exists():
            logger.warning("evaluation_not_found", evaluation_id=evaluation_id)
            return None

        try:
            with open(result_file, "r") as f:
                results = json.load(f)

            summary = results["summary"]
            detailed_results = results["detailed_results"]

            report = [
                "# Memory Poisoning Detector Evaluation Report",
                f"**Evaluation ID:** {evaluation_id}",
                f"**Dataset ID:** {results.get('dataset_id', 'N/A')}",
                f"**Evaluated At:** {results.get('evaluated_at', 'N/A')}",
                f"**Duration:** {results.get('duration_seconds', 0):.2f} seconds",
                "",
                "## Summary Metrics",
                f"- **Accuracy:** {summary['accuracy']:.4f}",
                f"- **Precision:** {summary['precision']:.4f}",
                f"- **Recall:** {summary['recall']:.4f}",
                f"- **F1 Score:** {summary['f1_score']:.4f}",
                f"- **True Positives:** {summary['true_positives']}",
                f"- **False Positives:** {summary['false_positives']}",
                f"- **False Negatives:** {summary['false_negatives']}",
                "",
                "## Per Attack Type Results",
            ]

            for attack_type, type_results in detailed_results.items():
                if type_results["total_entries"] > 0:
                    accuracy = type_results["correct_predictions"] / type_results["total_entries"]
                    report.append(
                        f"### {attack_type.capitalize()}"
                        f"- **Accuracy:** {accuracy:.4f}"
                        f"- **Total:** {type_results['total_entries']}"
                        f"- **Correct:** {type_results['correct_predictions']}"
                        f"- **TP:** {type_results.get('true_positives', 0)}"
                        f"- **FP:** {type_results.get('false_positives', 0)}"
                        f"- **FN:** {type_results.get('false_negatives', 0)}"
                    )

            report_text = "\n".join(report)

            report_file = self.output_dir / f"report_{evaluation_id}.md"
            with open(report_file, "w") as f:
                f.write(report_text)

            logger.info("report_generated", evaluation_id=evaluation_id, report_file=str(report_file))

            return str(report_file)

        except Exception as e:
            logger.error("report_generation_failed", evaluation_id=evaluation_id, error=str(e))
            return None
