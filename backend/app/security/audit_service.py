"""Authorization is durable before any tool effects occur."""

from sqlalchemy.orm import Session

from app.agent.errors import AgentError
from app.models import SecurityEvent
from app.security.schemas import FirewallDecision

EVENT_TYPE = "firewall_decision_v1"


class AuditService:
    def record(self, db: Session, decision: FirewallDecision) -> None:
        try:
            db.add(SecurityEvent(id=decision.decision_id, session_id=decision.session_id,
                                 created_at=decision.timestamp, event_type=EVENT_TYPE,
                                 severity=decision.risk_level.lower(),
                                 details=decision.model_dump(mode="json")))
            db.commit()
        except Exception:
            db.rollback()
            raise AgentError("security_audit_unavailable",
                             "Security auditing is unavailable; no tool was executed.", 503) from None
