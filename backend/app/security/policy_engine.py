"""Ordered-independent matching: explicit deny wins, absence of allow denies."""

from app.security.policies import PolicySet


class PolicyEngine:
    def __init__(self, policies: PolicySet | None) -> None:
        self.policies = policies

    def decide(self, tool: str, classification: str | None) -> tuple[str, str, str]:
        if self.policies is None:
            return "DENY", "INVALID_POLICY_CONFIGURATION", "Security policy configuration is unavailable."
        matches = [rule for rule in self.policies.rules if rule.tool == tool
                   and (rule.classification is None or rule.classification == classification)]
        denied = sorted((r for r in matches if r.effect == "DENY"), key=lambda r: r.id)
        allowed = sorted((r for r in matches if r.effect == "ALLOW"), key=lambda r: r.id)
        if denied:
            return "DENY", denied[0].id, "An explicit server policy denies this action."
        if allowed:
            return "ALLOW", allowed[0].id, "The action satisfies an explicit server policy."
        return "DENY", "DEFAULT_DENY", "No server policy authorizes this action."
