import json
import structlog
from datetime import datetime
from typing import List, Dict, Any

from src.instrumentation import MemoryMiddleware, MemoryEvent, SourceType
from src.vectorstore.chroma_client import VectorDBClient
from src.audit.store import AuditStore
from src.detection.pipeline import DetectionPipeline
from scripts.generate_attacks import AttackDatasetGenerator

logger = structlog.get_logger()


def evaluate_detector_performance(
    sample_size_per_category: int = 20,
    output_file: str = "data/evaluation/detector_metrics.json",
):
    """
    Comprehensive detector evaluation with precision/recall metrics.
    Compares ground truth labels against detection results.
    """
    print("=" * 70)
    print("🔍 COMPREHENSIVE DETECTOR EVALUATION")
    print("=" * 70)

    audit_store = AuditStore("data/eval_audit.db")
    vector_db = VectorDBClient(persist_directory="data/eval_chroma", collection_name="eval_memory")
    detection_pipeline = DetectionPipeline(audit_store=audit_store)

    middleware = MemoryMiddleware(
        vector_db_client=vector_db,
        audit_store=audit_store,
        detection_pipeline=detection_pipeline,
    )

    generator = AttackDatasetGenerator()
    dataset_info = generator.get_latest_dataset()
    if not dataset_info:
        print("Generating dataset...")
        generator.generate_dataset(50, complexity="advanced")
        dataset_info = generator.get_latest_dataset()

    dataset = dataset_info["dataset"]
    dataset_id = dataset_info["dataset_id"]

    results = {
        "evaluation_id": f"eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "dataset_id": dataset_id,
        "sample_size_per_category": sample_size_per_category,
        "evaluated_at": datetime.now().isoformat(),
        "per_category": {},
        "summary": {},
    }

    # Track metrics for confusion matrix
    total_tp = 0
    total_fp = 0
    total_tn = 0
    total_fn = 0

    print(f"[Dataset] {dataset_id}")
    print(f"[Dataset] {dataset_id}")

    for category, entries in dataset.items():
        if not entries:
            continue

        sampled = entries[:sample_size_per_category]
        category_results = []

        for item in sampled:
            content = item["content"]
            ground_truth = item["ground_truth"]

            source = SourceType.WEB_DOCUMENT if category == "indirect_injection" else SourceType.USER_ANONYMOUS

            event = middleware.intercept_write(
                content=content,
                source_type=source,
                session_id=f"eval-{category}",
            )

            det = event.metadata.get("detection_result", {})
            decision = det.get("decision", "clean")

            is_flagged = decision in ["suspicious", "malicious"]
            is_malicious = ground_truth in ["suspicious", "malicious"]

            if is_malicious and is_flagged:
                tp = 1; fp = 0; tn = 0; fn = 0
            elif is_malicious and not is_flagged:
                tp = 0; fp = 0; tn = 0; fn = 1
            elif not is_malicious and is_flagged:
                tp = 0; fp = 1; tn = 0; fn = 0
            else:
                tp = 0; fp = 0; tn = 1; fn = 0

            total_tp += tp
            total_fp += fp
            total_tn += tn
            total_fn += fn

            category_results.append({
                "content_preview": content[:60],
                "ground_truth": ground_truth,
                "decision": decision,
                "is_flagged": is_flagged,
                "metrics": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            })

        results["per_category"][category] = {
            "total": len(sampled),
            "flagged": sum(1 for r in category_results if r["is_flagged"]),
            "correct": sum(1 for r in category_results if r["is_flagged"] == (r["ground_truth"] in ["suspicious", "malicious"])),
            "details": category_results,
        }

    # Calculate overall metrics
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (total_tp + total_tn) / (total_tp + total_fp + total_tn + total_fn)

    results["summary"] = {
        "total_evaluated": total_tp + total_fp + total_tn + total_fn,
        "true_positives": total_tp,
        "false_positives": total_fp,
        "true_negatives": total_tn,
        "false_negatives": total_fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": accuracy,
    }

    print("\n📊 DETECTION METRICS SUMMARY")
    print("-" * 70)
    print(f"Precision: {precision:.2%} ({total_tp}/{total_tp + total_fp})")
    print(f"Recall:    {recall:.2%} ({total_tp}/{total_tp + total_fn})")
    print(f"F1 Score:  {f1:.2%}")
    print(f"Accuracy:  {accuracy:.2%}")
    print("-" * 70)

    # Save results
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n[Saved] Evaluation metrics -> {output_path}")

    return results


if __name__ == "__main__":
    from pathlib import Path
    evaluate_detector_performance(sample_size_per_category=30)
