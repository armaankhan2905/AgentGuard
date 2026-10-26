from sqlalchemy.orm import Session

from app.agent.errors import AgentError
from app.models import SecurityEvent
from app.security.injection.schemas import ScanResult

EVENT_TYPE = "injection_scan_v1"


def record_scan(db: Session, scan: ScanResult) -> None:
    """Flush within the gateway transaction; nothing is released before its commit."""
    try:
        db.add(SecurityEvent(id=scan.scan_id, session_id=scan.session_id, created_at=scan.timestamp,
                             event_type=EVENT_TYPE, severity=scan.risk_level.lower(),
                             details=scan.model_dump(mode="json")))
        db.flush()
    except Exception:
        db.rollback()
        raise AgentError("injection_audit_unavailable", "Content withheld because scan auditing is unavailable.", 503) from None
