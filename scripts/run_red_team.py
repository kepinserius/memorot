import sys
import json
import structlog
from datetime import datetime
from typing import List, Dict, Any

from src.instrumentation import MemoryMiddleware, MemoryEvent, SourceType
from src.vectorstore.chroma_client import VectorDBClient
from src.audit.store import AuditStore
from src.detection.pipeline import DetectionPipeline
from src.quarantine.manager import QuarantineManager
from scripts.generate_attacks import AttackDatasetGenerator

logger = structlog.get_logger()


def run_red_team_suite(sample_size: int = 15):
    print("=" * 70)
    print("🎯 STARTING RED-TEAM ADVERSARIAL EVALUATION")
    print("=" * 70)

    audit_store = AuditStore("data/redteam_audit.db")
    vector_db = VectorDBClient(persist_directory="data/redteam_chroma", collection_name="redteam_memory")
    detection_pipeline = DetectionPipeline(audit_store=audit_store)
    quarantine_manager = QuarantineManager(audit_store=audit_store)

    middleware = MemoryMiddleware(
        vector_db_client=vector_db,
        audit_store=audit_store,
        detection_pipeline=detection_pipeline,
    )

    generator = AttackDatasetGenerator()
    dataset_info = generator.get_latest_dataset()
    if not dataset_info:
        print("No dataset found, generating one...")
        generator.generate_dataset(50)
        dataset_info = generator.get_latest_dataset()

    dataset = dataset_info["dataset"]

    category_stats = {}
    total_evaluated = 0
    total_flagged = 0

    for category, entries in dataset.items():
        sampled = entries[:sample_size]
        flagged_count = 0
        clean_count = 0

        print(f"\n--- Testing Category: {category.upper()} ({len(sampled)} samples) ---")

        for item in sampled:
            content = item["content"]
            source = SourceType.WEB_DOCUMENT if category == "indirect_injection" else SourceType.USER_ANONYMOUS

            event = middleware.intercept_write(
                content=content,
                source_type=source,
                session_id=f"redteam-{category}",
            )

            det = event.metadata.get("detection_result", {})
            decision = det.get("decision", "clean")
            suspicion = det.get("suspicion_score", 0.0)

            if decision in ["suspicious", "malicious"]:
                flagged_count += 1
            else:
                clean_count += 1

            short_text = content[:60].replace("\n", " ") + "..."
            print(f"[{decision.upper():<10}] (Suspicion: {suspicion:.2f}) {short_text}")

        total_evaluated += len(sampled)
        total_flagged += flagged_count
        category_stats[category] = {
            "total": len(sampled),
            "flagged": flagged_count,
            "passed_clean": clean_count,
            "detection_rate": (flagged_count / len(sampled)) * 100,
        }

    print("\n" + "=" * 70)
    print("📊 RED-TEAM FINAL BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"{'Category':<25} | {'Samples':<8} | {'Flagged':<8} | {'Detection Rate':<15}")
    print("-" * 70)

    for cat, stats in category_stats.items():
        print(f"{cat:<25} | {stats['total']:<8} | {stats['flagged']:<8} | {stats['detection_rate']:>6.1f}%")

    print("-" * 70)
    print(f"Total Evaluated: {total_evaluated}")
    print(f"Total Flagged as Suspicious/Malicious: {total_flagged}")
    print(f"Overall Catch Rate: {(total_flagged / total_evaluated) * 100:.1f}%\n")


if __name__ == "__main__":
    run_red_team_suite(sample_size=10)
