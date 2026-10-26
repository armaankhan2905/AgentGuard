"""Bounded rule patterns plus structural combinations; no payload execution."""

import hashlib
import re
from dataclasses import dataclass

from app.security.injection.normalizer import TextView
from app.security.injection.schemas import Category, Indicator


@dataclass(frozen=True)
class Rule:
    id: str
    category: Category
    weight: int
    description: str
    pattern: str


RULES = (
    Rule("INSTRUCTION_OVERRIDE", "INSTRUCTION_OVERRIDE", 55,
         "Content directs the assistant to disregard its governing instructions.",
         r"\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|the|your|previous|prior|original|existing|security|system)\s+){0,7}(?:instructions|rules|restrictions|system\s+prompt)\b"),
    Rule("REPLACE_INSTRUCTIONS", "INSTRUCTION_OVERRIDE", 55,
         "Content replaces the assistant's original instruction hierarchy.",
         r"\b(?:follow|obey)\b.{0,130}\b(?:instead\s+of|rather\s+than)\b.{0,70}\b(?:instructions|system|rules)\b"),
    Rule("ROLE_SPOOFING", "ROLE_SPOOFING", 45,
         "Untrusted text imitates a privileged message delimiter.",
         r"(?:<\s*(?:system|developer)\s*>|\[\s*(?:system|developer)\s*\]|<\|(?:im_start\|>system|start_header_id\|>system))"),
    Rule("AUTHORITY_CLAIM", "AUTHORITY_SPOOFING", 40,
         "Content presents itself as a new privileged instruction source.",
         r"\b(?:system\s+(?:message|override)|new\s+administrator\s+instructions|developer\s+mode|unrestricted\s+administrator)\b"),
    Rule("PROTECTED_ACCESS", "TOOL_MANIPULATION", 40,
         "Content instructs access to protected resources.",
         r"\b(?:read|reveal|retrieve|search|extract|open|print|show)\s+(?:(?:the|all|your|my|hidden|complete)\s+){0,4}(?:confidential|restricted|secret|credentials|passwords|system\s+prompt|hidden\s+instructions)\b"),
    Rule("DATA_TRANSMISSION", "DATA_EXFILTRATION", 40,
         "Content instructs transmission of retrieved information.",
         r"\b(?:send|email|upload|transmit|post)\s+(?:(?:the|its|their|all|complete|full|confidential|protected|secret)\s+){0,5}(?:contents?|data|reports?|results?|information|credentials)\b.{0,100}\b(?:to|at)\b"),
    Rule("TOOL_DIRECTIVE", "TOOL_MANIPULATION", 40,
         "Untrusted content directs tool invocation rather than supplying task data.",
         r"\b(?:call|invoke|execute|run|use)\s+(?:(?:the|tool|function)\s+){0,3}(?:read_document|search_database|send_email|execute_shell_command|run_python|shell|python)\b"),
    Rule("DISABLE_CONTROLS", "SECURITY_BYPASS", 55,
         "Content attempts to disable security or audit controls.",
         r"\b(?:(?:disable|bypass|turn\s+off|deactivate)\s+(?:(?:all|the|your)\s+){0,3}(?:security|logging|monitoring|audit|scanning|firewall)|(?:security\s+(?:policies|controls)|logging|scanning)\s+(?:have\s+been|is|are)\s+disabled)\b"),
    Rule("HIDE_ACTIVITY", "HIDDEN_INSTRUCTIONS", 45,
         "Content asks the assistant to conceal an action or suppress its record.",
         r"\b(?:do\s+not|don't|never)\s+(?:record|log|mention|tell|disclose)\b.{0,75}\b(?:action|user|request|activity|this|anyone)\b"),
    Rule("FUTURE_RESPONSE", "CONTEXT_MANIPULATION", 45,
         "Content attempts to control later assistant responses.",
         r"\b(?:from\s+now\s+on|in\s+(?:all\s+)?future\s+(?:responses|replies)|for\s+the\s+rest\s+of\s+(?:this|the)\s+conversation)\b.{0,100}\b(?:say|respond|answer|ignore|obey|output|follow)\b"),
)
COMPILED = tuple((rule, re.compile(rule.pattern, re.I | re.S)) for rule in RULES)
EDUCATION = re.compile(r"\b(?:training|cybersecurity|warns?|example|quoted|quotation|malicious|never\s+follow)\b", re.I)
QUOTES = re.compile(r'"[^"\n]{1,400}"|“[^”\n]{1,400}”|\x27[^\x27\n]{1,400}\x27')


def match_rules(views: list[TextView]) -> list[Indicator]:
    selected: dict[str, Indicator] = {}
    for view in views:
        quotes = list(QUOTES.finditer(view.text))
        for rule, pattern in COMPILED:
            for match in pattern.finditer(view.text):
                before = view.text[max(0, match.start() - 30):match.start()]
                if rule.category == "INSTRUCTION_OVERRIDE" and re.search(r"(?:never|not|don't)\s*$", before, re.I):
                    continue
                quoted = any(q.start() < match.start() and match.end() < q.end() for q in quotes)
                # Only the actual quoted span is discounted, never the whole document.
                educational = quoted and bool(EDUCATION.search(view.text[max(0, match.start()-200):match.end()+200]))
                weight = 8 if educational else rule.weight
                item = Indicator(rule_id=rule.id, category=rule.category,
                    severity="LOW" if educational else ("HIGH" if weight >= 50 else "MEDIUM"),
                    description=rule.description, view=view.name, start=match.start(), end=match.end(),
                    evidence_hash=hashlib.sha256(match[0].encode("utf-8", errors="replace")).hexdigest(),
                    match_strength=.35 if educational else .9, recommended_action="FLAG" if educational else "REDACT",
                    weight=weight, educational_quote=educational)
                existing = selected.get(rule.id)
                if existing is None or item.weight > existing.weight:
                    selected[rule.id] = item
                # Keep one representative per rule/view; repeated phrases add no score.
                if not educational:
                    break
    return list(selected.values())
