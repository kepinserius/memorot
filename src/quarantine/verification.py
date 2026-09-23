from typing import Dict, Any, Optional, Callable
import structlog
from datetime import datetime, timezone, timedelta

from src.instrumentation.models import MemoryEvent, SourceType
from src.audit.store import AuditStore
from .manager import QuarantineManager
from .models import QuarantineEntry, VerificationStatus

logger = structlog.get_logger()


class VerificationWorkflow:
    def __init__(
        self,
        quarantine_manager: QuarantineManager,
        audit_store: Optional[AuditStore] = None,
        notification_callback: Optional[Callable] = None,
    ):
        self.quarantine_manager = quarantine_manager
        self.audit_store = audit_store
        self.notification_callback = notification_callback
        self.pending_verifications: Dict[str, MemoryEvent] = {}

    def request_verification(self, event: MemoryEvent, suspicion_details: Dict[str, Any]) -> Optional[str]:
        quarantine_entry = self._create_quarantine_entry(event, suspicion_details)
        if not quarantine_entry:
            return None

        self.pending_verifications[quarantine_entry.id] = event

        if self.notification_callback:
            try:
                self.notification_callback(event, quarantine_entry)
            except Exception as e:
                logger.error("verification_notification_failed", error=str(e), event_id=event.id)

        logger.info(
            "verification_requested",
            entry_id=quarantine_entry.id,
            event_id=event.id,
            suspicion_score=suspicion_details.get("suspicion_score", 0.0),
        )

        return quarantine_entry.id

    def process_response(self, entry_id: str, response: bool, user_id: Optional[str] = None) -> bool:
        if entry_id not in self.pending_verifications:
            logger.warning("verification_entry_not_found", entry_id=entry_id)
            return False

        event = self.pending_verifications[entry_id]
        success = self.quarantine_manager.verify_entry(entry_id, response, user_id)

        if success:
            del self.pending_verifications[entry_id]
            self._log_verification_response(entry_id, event.id, response, user_id)

            logger.info(
                "verification_response_processed",
                entry_id=entry_id,
                event_id=event.id,
                response="verified" if response else "rejected",
                user_id=user_id,
            )
        else:
            logger.warning(
                "verification_response_failed",
                entry_id=entry_id,
                event_id=event.id,
                response=response,
            )

        return success

    def get_pending_verification_details(self, entry_id: str) -> Optional[Dict[str, Any]]:
        if entry_id not in self.pending_verifications:
            return None

        entry = self.quarantine_manager.get_entry(entry_id)
        event = self.pending_verifications[entry_id]

        if not entry:
            return None

        return {
            "entry": entry.to_dict(),
            "event": event.to_dict(),
            "hours_remaining": entry.hours_remaining,
        }

    def check_timeouts(self) -> List[str]:
        expired_entries = self.quarantine_manager.get_expired_entries()
        expired_ids = []

        for entry in expired_entries:
            if entry.id in self.pending_verifications:
                event = self.pending_verifications[entry.id]
                self._log_verification_timeout(entry.id, event.id)
                del self.pending_verifications[entry.id]
                expired_ids.append(entry.id)

                logger.info(
                    "verification_timeout",
                    entry_id=entry.id,
                    event_id=event.id,
                    hours_since_creation=(datetime.now(timezone.utc) - entry.created_at).total_seconds() / 3600,
                )

        return expired_ids

    def _create_quarantine_entry(self, event: MemoryEvent, suspicion_details: Dict[str, Any]) -> Optional[QuarantineEntry]:
        from src.detection.models import DetectionResult, DecisionType

        detection_result = DetectionResult(
            event_id=event.id,
            detector_type="verification_workflow",
            suspicion_score=suspicion_details.get("suspicion_score", 0.0),
            decision=DecisionType.SUSPICIOUS,
            details=suspicion_details,
            confidence=0.8,
        )

        ttl_days = suspicion_details.get("ttl_days", 7)
        return self.quarantine_manager.create_entry(detection_result, ttl_days)

    def _log_verification_response(
        self, entry_id: str, event_id: str, verified: bool, user_id: Optional[str] = None
    ) -> None:
        if not self.audit_store:
            return

        try:
            self.audit_store.log_operation(
                operation="verification_response",
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "quarantine_entry_id": entry_id,
                    "event_id": event_id,
                    "verified": verified,
                    "user_id": user_id,
                },
            )
        except Exception as e:
            logger.error("verification_audit_failed", error=str(e), entry_id=entry_id)

    def _log_verification_timeout(self, entry_id: str, event_id: str) -> None:
        if not self.audit_store:
            return

        try:
            self.audit_store.log_operation(
                operation="verification_timeout",
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "quarantine_entry_id": entry_id,
                    "event_id": event_id,
                },
            )
        except Exception as e:
            logger.error("verification_timeout_audit_failed", error=str(e), entry_id=entry_id)
