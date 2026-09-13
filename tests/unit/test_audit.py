import unittest
import tempfile
import json
from pathlib import Path

from src.instrumentation import MemoryEvent, SourceType
from src.audit.store import AuditStore
from src.audit.event_sourcing import EventSourcing
from src.audit.snapshot import SnapshotSystem


class TestAuditLayer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_audit.db"
        self.audit_store = AuditStore(str(self.db_path))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_event_sourcing(self):
        event_sourcing = EventSourcing(self.audit_store)

        event = MemoryEvent(
            id="event-1",
            content="Test event",
            source_type=SourceType.USER_VERIFIED,
            trust_level=0.9,
            session_id="session-1",
        )

        log_entry = event_sourcing.log_operation("write", event)

        self.assertIsNotNone(log_entry.id)
        self.assertEqual(log_entry.event_id, event.id)
        self.assertEqual(log_entry.operation, "write")

    def test_event_chain(self):
        event_sourcing = EventSourcing(self.audit_store)

        parent_event = MemoryEvent(
            id="parent-1",
            content="Parent event",
            source_type=SourceType.USER_VERIFIED,
            trust_level=0.9,
            session_id="session-1",
        )

        event_sourcing.log_operation("write", parent_event)

        child_event = MemoryEvent(
            id="child-1",
            content="Child event",
            source_type=SourceType.TOOL_RESULT,
            trust_level=0.7,
            session_id="session-1",
            parent_event_id="parent-1",
        )

        event_sourcing.log_operation("write", child_event)

        chain = event_sourcing.get_event_chain("child-1")
        self.assertGreater(len(chain), 0)

    def test_snapshot_creation(self):
        snapshot_system = SnapshotSystem(
            self.audit_store,
            None,
            snapshot_frequency_entries=10,
        )

        snapshot = snapshot_system.create_snapshot(reason="test")
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.metadata["reason"], "test")

    def test_snapshot_should_trigger(self):
        snapshot_system = SnapshotSystem(
            self.audit_store,
            None,
            snapshot_frequency_entries=5,
        )

        self.assertFalse(snapshot_system.should_create_snapshot())

        for i in range(5):
            event = MemoryEvent(
                id=f"event-{i}",
                content=f"Test event {i}",
                source_type=SourceType.USER_VERIFIED,
                trust_level=0.9,
                session_id="session-1",
            )
            self.audit_store.log_event(
                event_id=event.id,
                content=event.content,
                source_type=event.source_type.value,
                trust_level=event.trust_level,
                session_id=event.session_id,
                timestamp=event.timestamp,
            )
            if snapshot_system.should_create_snapshot(event):
                break

        self.assertTrue(snapshot_system.should_create_snapshot())


if __name__ == "__main__":
    unittest.main()
