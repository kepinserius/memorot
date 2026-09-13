from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import structlog

from src.audit.store import AuditStore
from src.detection.models import DetectionResult
from .models import QuarantineEntry, VerificationStatus

logger = structlog.get_logger()


class QuarantineManager:
    def __init__(self, audit_store: Optional[AuditStore] = None, verification_timeout_hours: int = 24):
        self.audit_store = audit_store
        self.verification_timeout_hours = verification_timeout_hours
        self.entries: Dict[str, QuarantineEntry] = {}

    def create_entry(self, detection_result: DetectionResult, ttl_days: int = 7) -> QuarantineEntry:
        entry_id = str(uuid.uuid4())

        reason = f"Detected by {detection_result.detector_type}: {detection_result.decision.value}"

        entry = QuarantineEntry(
            id=entry_id,
            event_id=detection_result.event_id,
            suspicion_reason=reason,
            suspicion_score=detection_result.suspicion_score,
            verification_status=VerificationStatus.PENDING,
            ttl_days=ttl_days,
            metadata={
                "detection_details": detection_result.details,
                "confidence": detection_result.confidence,
                "detectors_used": detection_result.details.get("detectors_used", 1),
            },
        )

        self.entries[entry_id] = entry

        if self.audit_store:
            self._log_quarantine_action("entry_created", entry_id, detection_result.event_id)

        logger.info(
            "quarantine_entry_created",
            entry_id=entry_id,
            event_id=detection_result.event_id,
            suspicion_score=detection_result.suspicion_score,
            ttl_days=ttl_days,
        )

        return entry

    def verify_entry(self, entry_id: str, verified: bool = True, user_id: Optional[str] = None) -> bool:
        if entry_id not in self.entries:
            logger.warning("quarantine_entry_not_found", entry_id=entry_id)
            return False

        entry = self.entries[entry_id]

        if entry.verification_status != VerificationStatus.PENDING:
            logger.warning(
                "quarantine_entry_already_processed",
                entry_id=entry_id,
                current_status=entry.verification_status.value,
            )
            return False

        if entry.is_expired:
            entry.verification_status = VerificationStatus.EXPIRED
        else:
            entry.verification_status = VerificationStatus.VERIFIED if verified else VerificationStatus.REJECTED
            entry.verified_at = datetime.utcnow()
            entry.metadata["user_id"] = user_id

        if self.audit_store:
            self._log_quarantine_action(
                f"entry_{'verified' if verified else 'rejected'}",
                entry_id,
                entry.event_id,
                {"user_id": user_id},
            )

        logger.info(
            "quarantine_entry_processed",
            entry_id=entry_id,
            event_id=entry.event_id,
            status=entry.verification_status.value,
            user_id=user_id,
        )

        return True

    def get_pending_entries(self) -> List[QuarantineEntry]:
        return [
            entry
            for entry in self.entries.values()
            if entry.verification_status == VerificationStatus.PENDING
        ]

    def get_expired_entries(self) -> List[QuarantineEntry]:
        return [
            entry
            for entry in self.entries.values()
            if entry.verification_status == VerificationStatus.PENDING and entry.is_expired
        ]

    def cleanup_expired_entries(self) -> List[str]:
        expired_ids = []
        for entry in self.get_expired_entries():
            entry.verification_status = VerificationStatus.EXPIRED
            expired_ids.append(entry.id)

            if self.audit_store:
                self._log_quarantine_action("entry_expired", entry.id, entry.event_id)

            logger.info("quarantine_entry_expired", entry_id=entry.id, event_id=entry.event_id)

        return expired_ids

    def get_entry(self, entry_id: str) -> Optional[QuarantineEntry]:
        return self.entries.get(entry_id)

    def get_entries_by_event_id(self, event_id: str) -> List[QuarantineEntry]:
        return [
            entry
            for entry in self.entries.values()
            if entry.event_id == event_id
        ]

    def remove_entry(self, entry_id: str) -> bool:
        if entry_id not in self.entries:
            return False

        entry = self.entries.pop(entry_id)

        if self.audit_store:
            self._log_quarantine_action("entry_removed", entry_id, entry.event_id)

        logger.info("quarantine_entry_removed", entry_id=entry_id, event_id=entry.event_id)
        return True

    def _log_quarantine_action(
        self, action: str, entry_id: str, event_id: str, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        if not self.audit_store:
            return

        try:
            self.audit_store.log_operation(
                operation=f"quarantine_{action}",
                event_id=event_id,
                timestamp=datetime.utcnow(),
                metadata={
                    "quarantine_entry_id": entry_id,
                    "event_id": event_id,
                    **(metadata or {}),
                },
            )
        except Exception as e:
            logger.error("quarantine_audit_failed", error=str(e), entry_id=entry_id)
