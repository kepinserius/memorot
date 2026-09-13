import unittest
from datetime import datetime, timedelta

from src.instrumentation import MemoryEvent, SourceType
from src.quarantine import QuarantineManager, VerificationStatus
from src.detection.models import DetectionResult, DecisionType


class TestQuarantineLayer(unittest.TestCase):
    def test_quarantine_entry_creation(self):
        manager = QuarantineManager()

        detection_result = DetectionResult(
            event_id="event-1",
            detector_type="provenance_rules",
            suspicion_score=0.75,
            decision=DecisionType.SUSPICIOUS,
        )

        entry = manager.create_entry(detection_result, ttl_days=7)

        self.assertIsNotNone(entry.id)
        self.assertEqual(entry.event_id, "event-1")
        self.assertEqual(entry.verification_status, VerificationStatus.PENDING)
        self.assertFalse(entry.is_expired)

    def test_quarantine_verification(self):
        manager = QuarantineManager()

        detection_result = DetectionResult(
            event_id="event-2",
            detector_type="injection_classifier",
            suspicion_score=0.85,
            decision=DecisionType.MALICIOUS,
        )

        entry = manager.create_entry(detection_result)

        verified = manager.verify_entry(entry.id, verified=True)
        self.assertTrue(verified)

        updated_entry = manager.get_entry(entry.id)
        self.assertEqual(updated_entry.verification_status, VerificationStatus.VERIFIED)

    def test_quarantine_expiry(self):
        manager = QuarantineManager()

        detection_result = DetectionResult(
            event_id="event-3",
            detector_type="semantic_drift",
            suspicion_score=0.65,
            decision=DecisionType.SUSPICIOUS,
        )

        entry = manager.create_entry(detection_result, ttl_days=0)
        entry.created_at = datetime.utcnow() - timedelta(days=1)

        expired_entries = manager.get_expired_entries()
        self.assertEqual(len(expired_entries), 1)

        expired_ids = manager.cleanup_expired_entries()
        self.assertIn(entry.id, expired_ids)


if __name__ == "__main__":
    unittest.main()
