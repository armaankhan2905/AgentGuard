"""Protocol history retains structure without copying proposed email bodies."""

import json

from app.core.redaction import SecretRedactor
from app.security.policies import reject_constant, unique_object
from app.tools.schemas import ARGUMENT_SCHEMAS


def history_arguments(name: str, arguments: str, redactor: SecretRedactor) -> str:
    if name not in ARGUMENT_SCHEMAS or len(arguments) > 12000:
        return "{}"
    try:
        raw = json.loads(arguments, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if not isinstance(raw, dict):
            return "{}"
        safe = redactor.clean(raw)
        if name == "send_email":
            # Keep the protocol keys, but not rejected/sensitive content in history.
            safe = {key: ("[REDACTED]" if value == "[REDACTED]" else "[OMITTED]")
                    for key, value in safe.items() if key in {"to", "subject", "body"}}
        return json.dumps(safe)
    except (ValueError, TypeError, RecursionError):
        return "{}"
