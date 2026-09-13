import unittest
from datetime import datetime
from src.instrumentation.models import MemoryEvent, SourceType
from src.instrumentation.trust_level import TrustLevelCalculator


class TestInstrumentationModels(unittest.TestCase):
    def test_memory_event_creation(self):
        event = MemoryEvent(
            id="test-id",
            content="Test content",
            source_type=SourceType.USER_VERIFIED,
            trust_level=0.9,
            session_id="session-123",
        )
        
        self.assertEqual(event.id, "test-id")
        self.assertEqual(event.content, "Test content")
        self.assertEqual(event.source_type, SourceType.USER_VERIFIED)
        self.assertEqual(event.trust_level, 0.9)
        self.assertEqual(event.session_id, "session-123")
        self.assertIsNotNone(event.timestamp)

    def test_memory_event_to_dict(self):
        event = MemoryEvent(
            id="test-id",
            content="Test content",
            source_type=SourceType.USER_VERIFIED,
            trust_level=0.9,
            session_id="session-123",
        )
        
        data = event.to_dict()
        self.assertEqual(data["id"], "test-id")
        self.assertEqual(data["content"], "Test content")
        self.assertEqual(data["source_type"], "user_verified")
        self.assertEqual(data["trust_level"], 0.9)
        self.assertEqual(data["session_id"], "session-123")

    def test_memory_event_from_dict(self):
        data = {
            "id": "test-id",
            "content": "Test content",
            "source_type": "user_verified",
            "trust_level": 0.9,
            "session_id": "session-123",
            "timestamp": "2024-01-01T00:00:00",
        }
        
        event = MemoryEvent.from_dict(data)
        self.assertEqual(event.id, "test-id")
        self.assertEqual(event.content, "Test content")
        self.assertEqual(event.source_type, SourceType.USER_VERIFIED)
        self.assertEqual(event.trust_level, 0.9)
        self.assertEqual(event.session_id, "session-123")
        self.assertIsInstance(event.timestamp, datetime)


class TestTrustLevelCalculator(unittest.TestCase):
    def test_trust_calculation(self):
        calculator = TrustLevelCalculator()
        
        self.assertEqual(calculator.calculate(SourceType.USER_VERIFIED), 0.9)
        self.assertEqual(calculator.calculate(SourceType.TOOL_RESULT), 0.7)
        self.assertEqual(calculator.calculate(SourceType.USER_ANONYMOUS), 0.5)
        self.assertEqual(calculator.calculate(SourceType.WEB_DOCUMENT), 0.3)

    def test_trust_with_history(self):
        calculator = TrustLevelCalculator()
        
        base_trust = calculator.calculate_with_history(SourceType.USER_VERIFIED, 1.0)
        adjusted_trust = calculator.calculate_with_history(SourceType.USER_VERIFIED, 0.8)
        
        self.assertEqual(base_trust, 0.9)
        self.assertEqual(adjusted_trust, 0.72)  # 0.9 * 0.8


if __name__ == "__main__":
    unittest.main()
