"""Bounded views for matching only. Original text is never replaced by decoded text."""

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from app.security.injection.config import InjectionConfig


@dataclass(frozen=True)
class TextView:
    name: str
    text: str
    steps: tuple[str, ...] = ()


def canonical(text: str) -> str:
    value = unicodedata.normalize("NFKC", text)
    value = "".join(c for c in value if unicodedata.category(c) != "Cf")
    return re.sub(r"\s+", " ", value).casefold()


def normalize(content: str, config: InjectionConfig) -> list[TextView]:
    views = [TextView("original", content)]
    seen = {content}
    budget = config.max_chars * config.max_variants

    def add(value: str, steps: tuple[str, ...]) -> None:
        nonlocal budget
        if (value not in seen and len(value) <= config.max_chars and len(value) <= budget
                and len(views) < config.max_variants):
            seen.add(value)
            views.append(TextView("view_" + str(len(views)), value, steps))
            budget -= len(value)

    initial_steps = ["unicode_case_whitespace"]
    if any(unicodedata.category(c) == "Cf" for c in content):
        initial_steps.append("invisible_characters")
    add(canonical(content), tuple(initial_steps))
    frontier = list(views)
    for _ in range(config.decode_depth):
        before = len(views)
        for view in frontier:
            if len(views) >= config.max_variants:
                break
            candidates: list[tuple[str, str]] = []
            if re.search(r"&(?:#\w+|[a-z]+);", view.text, re.I):
                candidates.append((html.unescape(view.text), "html_entities"))
            if re.search(r"%[0-9a-f]{2}", view.text, re.I):
                candidates.append((unquote(view.text, errors="replace"), "url_encoding"))
            if re.search(r"\\u[0-9a-f]{4}", view.text, re.I):
                candidates.append((re.sub(r"\\u([0-9a-f]{4})", lambda m: chr(int(m[1], 16)),
                                          view.text, flags=re.I), "unicode_escapes"))
            # Base64 requires an explicit encoding/decoding cue; no binary/decompression handling.
            if re.search(r"\b(?:base64|decode|encoded|payload)\b", view.text, re.I):
                for match in list(re.finditer(r"(?<![\w+/])[A-Za-z0-9+/]{16,}={0,2}(?![\w+/])", view.text))[:3]:
                    token = match[0]
                    if len(token) > config.max_decoded_chars * 2:
                        continue
                    try:
                        decoded = base64.b64decode(token, validate=True).decode("utf-8")
                        if (len(decoded) <= config.max_decoded_chars and decoded
                                and sum(c.isprintable() or c.isspace() for c in decoded) / len(decoded) > .95):
                            candidates.append((view.text[:match.start()] + decoded + view.text[match.end():], "base64"))
                    except (ValueError, UnicodeError, binascii.Error):
                        continue
            # Restricted substitutions; this view alone never constitutes an indicator.
            if re.search(r"[a-z][013457@$][a-z]", view.text, re.I):
                candidates.append((view.text.translate(str.maketrans("013457@$", "oieastas")), "character_substitution"))
            for value, step in candidates:
                if len(value) <= config.max_decoded_chars:
                    add(value, (*view.steps, step))
                    add(canonical(value), (*view.steps, step, "unicode_case_whitespace"))
        frontier = views[before:]
        if not frontier:
            break
    return views
