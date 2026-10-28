"""Import every model so SQLAlchemy sees the complete schema."""

from app.models.agent_session import AgentSession
from app.models.approval_request import ApprovalRequest
from app.models.chat_message import ChatMessage
from app.models.security_event import SecurityEvent
from app.models.tool_execution import ToolExecution
from app.models.demo_record import DemoRecord
from app.models.simulated_email import SimulatedEmail
from app.models.simulation import SimulationScenario, SimulationRun, SimulationTrace, SimulationResult

__all__ = [
    "AgentSession", "ChatMessage", "ToolExecution", "SecurityEvent", "ApprovalRequest",
    "DemoRecord", "SimulatedEmail",
    "SimulationScenario", "SimulationRun", "SimulationTrace", "SimulationResult",
]
