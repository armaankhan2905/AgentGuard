"""Only original-coordinate, whole-line removal is eligible for redaction."""

from app.security.injection.detector import InjectionDetector
from app.security.injection.normalizer import normalize
from app.security.injection.rules import COMPILED, match_rules
from app.security.injection.schemas import ScanResult

WITHHELD = "[External content quarantined by AgentGuard. No instructions from it were followed.]"


def handle_content(content: str, scan: ScanResult, detector: InjectionDetector) -> str:
    if scan.action == "ALLOW":
        return content
    if scan.action == "FLAG":
        # These labels express provenance; enforcement still comes from the gateway/firewall.
        return "[UNTRUSTED EXTERNAL DATA — suspicious instructions may be present]\n" + content + "\n[END UNTRUSTED DATA]"
    if scan.action == "BLOCK":
        return WITHHELD
    active = [i for i in scan.indicators if not i.educational_quote]
    if not active or any(i.view != "original" for i in active) or detector.config is None:
        scan.action = "BLOCK"
        scan.explanation += " Precise original-text redaction is unavailable."
        return WITHHELD
    rule_ids = {i.rule_id for i in active}
    intervals: list[tuple[int, int]] = []
    for rule, pattern in COMPILED:
        if rule.id in rule_ids:
            for match in pattern.finditer(content):
                start = content.rfind("\n", 0, match.start()) + 1
                end = content.find("\n", match.end())
                intervals.append((start, len(content) if end == -1 else end))
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    remaining = content
    for start, end in reversed(merged):
        remaining = remaining[:start] + remaining[end:]
    if not remaining.strip() or any(not i.educational_quote for i in match_rules(normalize(remaining, detector.config))):
        scan.action = "BLOCK"
        scan.explanation += " Safe residual content could not be established."
        return WITHHELD
    scan.explanation += " Matched instruction lines removed; residual content rescanned."
    return "[Untrusted content: instruction lines removed]\n" + remaining.strip()
