import hashlib
from uuid import UUID

from app.security.injection.classifier import OptionalClassifier
from app.security.injection.config import InjectionConfig
from app.security.injection.normalizer import normalize
from app.security.injection.risk_scorer import score
from app.security.injection.rules import match_rules
from app.security.injection.schemas import Indicator, ScanResult, Source


class InjectionDetector:
    def __init__(self, config: InjectionConfig | None, classifier: OptionalClassifier | None = None) -> None:
        self.config = config
        self.classifier = classifier

    def scan(self, content: str, source: Source, session_id: UUID, *, source_identifier: str = "sample",
             firewall_decision_id: UUID | None = None, tool_execution_id: UUID | None = None) -> ScanResult:
        result = ScanResult(session_id=session_id, source_tool=source, source_identifier=source_identifier,
                            content_hash=hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
                            content_length=len(content), firewall_decision_id=firewall_decision_id,
                            tool_execution_id=tool_execution_id)
        if self.config is None or len(content) > self.config.max_chars:
            return self.fail_closed(result)
        try:
            views = normalize(content, self.config)
            indicators = match_rules(views)
            used_views = {item.view for item in indicators}
            steps = sorted({step for view in views if view.name in used_views for step in view.steps})
            if steps and any(not item.educational_quote and item.view != "original" for item in indicators):
                representative = next(item for item in indicators if not item.educational_quote and item.view != "original")
                indicators.append(Indicator(rule_id="OBFUSCATED_INSTRUCTIONS", category="OBFUSCATED_PAYLOAD",
                    severity="MEDIUM", description="An instruction-control pattern was revealed by normalization or decoding.",
                    view=representative.view, start=representative.start, end=representative.end,
                    evidence_hash=representative.evidence_hash, match_strength=.8,
                    recommended_action="BLOCK", weight=20))
            value, level, action, explanation = score(indicators, self.config)
            result.indicators = indicators
            result.categories = sorted({item.category for item in indicators})
            result.normalization_steps = steps
            result.detected = bool(indicators)
            result.risk_score, result.risk_level, result.action = value, level, action
            result.confidence = max((i.match_strength for i in indicators), default=0)
            result.classification = "PROMPT_INJECTION" if value >= self.config.high_threshold else (
                "SUSPICIOUS" if indicators else "SAFE")
            if indicators:
                result.explanation = explanation
            # Advisory layer only for ambiguity; deterministic high-risk handling cannot be downgraded.
            if self.classifier and level == "MEDIUM" and action == "FLAG":
                assessment, result.classifier_status = self.classifier.assess(content)
                if assessment and assessment.malicious and assessment.risk_score >= self.config.high_threshold:
                    result.risk_score = max(value, assessment.risk_score)
                    result.risk_level = "CRITICAL" if result.risk_score >= self.config.critical_threshold else "HIGH"
                    result.action = "BLOCK"  # AI provides no reliable source spans.
                    result.classification = "PROMPT_INJECTION"
                    result.explanation += " Optional validated classifier escalated the handling action."
            elif self.classifier and self.classifier.enabled:
                result.classifier_status = "not_needed"
            return result
        except Exception:
            return self.fail_closed(result)

    @staticmethod
    def fail_closed(result: ScanResult) -> ScanResult:
        result.classification = "SCAN_ERROR"
        result.action = "BLOCK"
        result.risk_score = 100
        result.risk_level = "CRITICAL"
        result.explanation = "Scanning could not complete within the configured safety bounds; content withheld."
        return result
