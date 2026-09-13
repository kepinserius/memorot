import structlog
from datetime import datetime, timedelta
from typing import List, Dict, Any
import threading
import time

from src.audit.store import AuditStore
from .manager import QuarantineManager
from .models import QuarantineEntry, VerificationStatus

logger = structlog.get_logger()


class TimeDecayQuarantine:
    def __init__(
        self,
        quarantine_manager: QuarantineManager,
        audit_store: Optional[AuditStore] = None,
        cleanup_interval_hours: int = 6,
        auto_expire_days: int = 7,
    ):
        self.quarantine_manager = quarantine_manager
        self.audit_store = audit_store
        self.cleanup_interval_hours = cleanup_interval_hours
        self.auto_expire_days = auto_expire_days
        self.running = False
        self.cleanup_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.running:
            logger.warning("time_decay_already_running")
            return

        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        logger.info("time_decay_started", interval_hours=self.cleanup_interval_hours)

    def stop(self) -> None:
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=10)
            self.cleanup_thread = None

        logger.info("time_decay_stopped")

    def _cleanup_loop(self) -> None:
        while self.running:
            try:
                self.cleanup_expired_entries()
                time.sleep(self.cleanup_interval_hours * 3600)
            except Exception as e:
                logger.error("cleanup_loop_error", error=str(e))
                time.sleep(60)

    def cleanup_expired_entries(self) -> List[str]:
        expired_entries = self.quarantine_manager.get_expired_entries()
        expired_ids = []

        for entry in expired_entries:
            if entry.is_expired:
                self._auto_process_expired_entry(entry)
                expired_ids.append(entry.id)

        if expired_ids:
            logger.info(
                "time_decay_cleanup_completed",
                expired_count=len(expired_ids),
                entry_ids=expired_ids[:5],
            )

        return expired_ids

    def _auto_process_expired_entry(self, entry: QuarantineEntry) -> None:
        if entry.verification_status != VerificationStatus.PENDING:
            return

        entry.verification_status = VerificationStatus.EXPIRED
        entry.metadata["auto_expired_at"] = datetime.utcnow().isoformat()

        if self.audit_store:
            try:
                self.audit_store.log_operation(
                    operation="time_decay_expired",
                    event_id=entry.event_id,
                    timestamp=datetime.utcnow(),
                    metadata={
                        "quarantine_entry_id": entry.id,
                        "event_id": entry.event_id,
                        "hours_in_quarantine": (datetime.utcnow() - entry.created_at).total_seconds() / 3600,
                        "suspicion_score": entry.suspicion_score,
                    },
                )
            except Exception as e:
                logger.error("time_decay_audit_failed", error=str(e), entry_id=entry.id)

        logger.info(
            "quarantine_entry_auto_expired",
            entry_id=entry.id,
            event_id=entry.event_id,
            hours_in_quarantine=(datetime.utcnow() - entry.created_at).total_seconds() / 3600,
        )

    def get_aging_statistics(self) -> Dict[str, Any]:
        pending_entries = self.quarantine_manager.get_pending_entries()

        aging_groups = {
            "0-24h": 0,
            "24-48h": 0,
            "48-72h": 0,
            "72h+": 0,
        }

        total_hours = 0
        max_hours = 0
        min_hours = float("inf") if pending_entries else 0

        for entry in pending_entries:
            hours_in_quarantine = (datetime.utcnow() - entry.created_at).total_seconds() / 3600
            total_hours += hours_in_quarantine
            max_hours = max(max_hours, hours_in_quarantine)
            min_hours = min(min_hours, hours_in_quarantine)

            if hours_in_quarantine <= 24:
                aging_groups["0-24h"] += 1
            elif hours_in_quarantine <= 48:
                aging_groups["24-48h"] += 1
            elif hours_in_quarantine <= 72:
                aging_groups["48-72h"] += 1
            else:
                aging_groups["72h+"] += 1

        return {
            "total_pending": len(pending_entries),
            "aging_distribution": aging_groups,
            "avg_hours_in_quarantine": total_hours / len(pending_entries) if pending_entries else 0,
            "max_hours_in_quarantine": max_hours,
            "min_hours_in_quarantine": min_hours if pending_entries else 0,
        }
