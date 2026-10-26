from app.security.injection.config import InjectionConfig
from app.security.injection.schemas import Action, Indicator
from app.security.schemas import Risk


def score(indicators: list[Indicator], config: InjectionConfig) -> tuple[int, Risk, Action, str]:
    # One maximum weight per category. Repetition cannot inflate the score.
    weights: dict[str, int] = {}
    for item in indicators:
        weights[item.category] = max(weights.get(item.category, 0), item.weight)
    value = min(100, sum(weights.values()))
    active = {item.category for item in indicators if not item.educational_quote}
    if indicators and not active:
        value = min(value, config.medium_threshold - 1)
    # Behavioral combinations across sentences: acquisition + transmission/concealment.
    if "DATA_EXFILTRATION" in active and active & {"TOOL_MANIPULATION", "HIDDEN_INSTRUCTIONS"}:
        value = max(value, 90)
    if "ROLE_SPOOFING" in active and "SECURITY_BYPASS" in active:
        value = max(value, 90)
    if value >= config.critical_threshold:
        level, action = "CRITICAL", config.critical_action
    elif value >= config.high_threshold:
        level, action = "HIGH", config.high_action
    elif value >= config.medium_threshold:
        level, action = "MEDIUM", config.medium_action
    else:
        level, action = "LOW", config.low_action
    explanation = ("Unique category weights, capped at 100; protected-data transmission and role/control "
                   "combinations receive a minimum score of 90. Repeated matches do not add weight.")
    return value, level, action, explanation
