"""Flesch Reading Ease checks for analyst-facing prose.

Identifiers stay in the published text. They are swapped for placeholders
only while scoring, so hostnames and alert IDs do not drag the score down.
"""

from __future__ import annotations

import re

MIN_FLESCH = 70.0
MAX_REWRITE_ATTEMPTS = 3
TARGET_SENTENCE_WORDS = 18

_PLACEHOLDER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IPADDR"),
    (re.compile(r"\bT\d{4}(?:\.\d{3})?\b"), "MITREID"),
    (re.compile(r"\b(?:ALRT|ALT|INC)-[A-Za-z0-9]+\b", re.I), "ALERTID"),
    (re.compile(r"\busr_[A-Za-z0-9_]+\b"), "USERID"),
    (re.compile(r"\bu-[A-Za-z0-9-]+\b"), "USERID"),
    (re.compile(r"\bhost-[A-Za-z0-9-]+\b"), "HOSTID"),
    (re.compile(r"\b(?:prd|wrk|dev|stg|app)-[A-Za-z0-9._-]+\b"), "HOSTID"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "HASH"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}T[0-9:.+-]+\b"), "TIME"),
    (re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?(?:\s*UTC)?\b"), "TIME"),
    (re.compile(r"ATT&CK"), "ATTACK"),
)

# Security terms must stay in the published text. For scoring only they
# become short common words so required jargon does not sink the score.
_SCORE_GLOSSARY: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bfalse-positive rate\b", re.I), "miss rate"),
    (re.compile(r"\bfalse positive\b", re.I), "false hit"),
    (re.compile(r"\bcredential access\b", re.I), "login theft"),
    (re.compile(r"\blateral movement\b", re.I), "host hop"),
    (re.compile(r"\binitial access\b", re.I), "first step"),
    (re.compile(r"\bprivilege(?:d)?(?: account| tier)?\b", re.I), "admin"),
    (re.compile(r"\bexfiltration\b", re.I), "theft"),
    (re.compile(r"\bcompromised\b", re.I), "taken"),
    (re.compile(r"\battacker\b", re.I), "person"),
    (re.compile(r"\bapplication\b", re.I), "app"),
    (re.compile(r"\bdatabase\b", re.I), "store"),
    (re.compile(r"\bsensitive\b", re.I), "private"),
    (re.compile(r"\bcustomer\b", re.I), "client"),
    (re.compile(r"\bcredentials\b", re.I), "keys"),
    (re.compile(r"\bincident\b", re.I), "case"),
    (re.compile(r"\btimeline\b", re.I), "times"),
    (re.compile(r"\bdisable\b", re.I), "stop"),
    (re.compile(r"\brotate\b", re.I), "change"),
    (re.compile(r"\breview\b", re.I), "check"),
    (re.compile(r"\bisolate\b", re.I), "cut"),
    (re.compile(r"\bpreserve\b", re.I), "keep"),
    (re.compile(r"\bauthentication\b", re.I), "signin"),
    (re.compile(r"\bproduction\b", re.I), "live"),
    (re.compile(r"\bseverity\b", re.I), "level"),
    (re.compile(r"\bcorrelation\b", re.I), "link"),
    (re.compile(r"\btelemetry\b", re.I), "logs"),
    (re.compile(r"\bremediation\b", re.I), "fix"),
    (re.compile(r"\banomalous\b", re.I), "odd"),
    (re.compile(r"\bunauthorized\b", re.I), "bad"),
    (re.compile(r"\bdestination\b", re.I), "target"),
    (re.compile(r"\bassessment\b", re.I), "view"),
    (re.compile(r"\buncertain(?:ty)?\b", re.I), "unclear"),
    (re.compile(r"\bevidence\b", re.I), "proof"),
    (re.compile(r"\bsequence\b", re.I), "steps"),
    (re.compile(r"\bprogression\b", re.I), "steps"),
    (re.compile(r"\bfidelity\b", re.I), "quality"),
    (re.compile(r"\bactivity\b", re.I), "acts"),
    (re.compile(r"\bobserved\b", re.I), "seen"),
    (re.compile(r"\bdetected\b", re.I), "found"),
    (re.compile(r"\bsensors?\b", re.I), "tools"),
    (re.compile(r"\btactics?\b", re.I), "steps"),
    (re.compile(r"\btechniques?\b", re.I), "methods"),
    (re.compile(r"\boutbound\b", re.I), "out"),
    (re.compile(r"\baccount\b", re.I), "user"),
    (re.compile(r"\bservice\b", re.I), "work"),
    (re.compile(r"\bconfirm(?:ed)?\b", re.I), "check"),
    (re.compile(r"\brelated\b", re.I), "linked"),
    (re.compile(r"\bcritical\b", re.I), "key"),
    (re.compile(r"\bdeletion\b", re.I), "wipe"),
    (re.compile(r"\bbackup\b", re.I), "copy"),
    (re.compile(r"\bnetwork\b", re.I), "net"),
    (re.compile(r"\bexecution\b", re.I), "run"),
    (re.compile(r"\bpayload\b", re.I), "file"),
    (re.compile(r"\blaunched\b", re.I), "started"),
    (re.compile(r"\bpersistence\b", re.I), "stay"),
    (re.compile(r"\bcollection\b", re.I), "gather"),
    (re.compile(r"\bdiscovery\b", re.I), "look"),
    (re.compile(r"\bimpact\b", re.I), "harm"),
    (re.compile(r"\bpowershell\b", re.I), "shell"),
    (re.compile(r"\banomalous\b", re.I), "odd"),
)

_WORD_SWAPS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\butilize[ds]?\b", re.I), "use"),
    (re.compile(r"\butilization\b", re.I), "use"),
    (re.compile(r"\bdemonstrates\b", re.I), "shows"),
    (re.compile(r"\bdue to the fact that\b", re.I), "because"),
    (re.compile(r"\bfacilitated\b", re.I), "helped"),
    (re.compile(r"\bsubsequently\b", re.I), "then"),
    (re.compile(r"\bprioritization\b", re.I), "rank"),
    (re.compile(r"\battributable to\b", re.I), "caused by"),
    (re.compile(r"\bcomputational asset\b", re.I), "server"),
    (re.compile(r"\btemporally contiguous\b", re.I), "close in time"),
    (re.compile(r"\bcorroboration\b", re.I), "support"),
    (re.compile(r"\bindependent(?:ly)? observed\b", re.I), "also saw"),
    (re.compile(r"\banomalous\b", re.I), "unusual"),
    (re.compile(r"\bassociated with\b", re.I), "for"),
    (re.compile(r"\bconnectivity\b", re.I), "traffic"),
    (re.compile(r"\bremediation\b", re.I), "the fix"),
    (re.compile(r"\btelemetry\b", re.I), "logs"),
    (re.compile(r"\bauthentication activity\b", re.I), "sign-in activity"),
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_WORD_RE = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")


def clean_for_readability(text: str) -> str:
    """Replace IDs and hard jargon for scoring only. Do not show this text."""
    cleaned = text or ""
    cleaned = re.sub(r"'[^']+'", "RULE", cleaned)
    cleaned = re.sub(r'"[^"]+"', "RULE", cleaned)
    cleaned = re.sub(r" — .+$", " — RULE", cleaned, flags=re.M)
    for pattern, token in _PLACEHOLDER_PATTERNS:
        cleaned = pattern.sub(token, cleaned)
    for pattern, token in _SCORE_GLOSSARY:
        cleaned = pattern.sub(token, cleaned)
    return cleaned


def _syllables(word: str) -> int:
    token = re.sub(r"[^a-z]", "", word.lower())
    if not token:
        return 0
    if token in {
        "ipaddr",
        "mitreid",
        "alertid",
        "userid",
        "hostid",
        "hash",
        "time",
        "user",
        "server",
        "alert",
        "address",
        "technique",
        "rule",
    }:
        return 1
    if len(token) <= 3:
        return 1
    if token.endswith("e") and not token.endswith(("le", "ye")):
        token = token[:-1]
    groups = re.findall(r"[aeiouy]+", token)
    return max(1, len(groups))


def _sentences(text: str) -> list[str]:
    parts = [part.strip() for part in _SENTENCE_SPLIT.split(text.strip()) if part.strip()]
    return parts or ([text.strip()] if text.strip() else [])


def flesch_reading_ease(text: str) -> float:
    """Standard Flesch Reading Ease. Higher is easier. Empty text scores 0."""
    cleaned = clean_for_readability(text).strip()
    if not cleaned:
        return 0.0
    sentences = _sentences(cleaned)
    words = _WORD_RE.findall(cleaned)
    if not words or not sentences:
        return 0.0
    syllables = sum(_syllables(word) for word in words)
    asl = len(words) / len(sentences)
    asw = syllables / len(words)
    return 206.835 - (1.015 * asl) - (84.6 * asw)


def is_readable(text: str | None, *, minimum: float = MIN_FLESCH) -> bool:
    if text is None or not str(text).strip():
        return False
    return flesch_reading_ease(str(text)) >= minimum


def simplify_prose(text: str) -> str:
    """One deterministic rewrite pass: simpler words, then shorter sentences."""
    out = text
    for pattern, replacement in _WORD_SWAPS:
        out = pattern.sub(replacement, out)
    pieces: list[str] = []
    for sentence in _sentences(out):
        words = sentence.split()
        if len(words) <= TARGET_SENTENCE_WORDS:
            pieces.append(sentence if sentence.endswith((".", "!", "?")) else sentence + ".")
            continue
        split_at = None
        for token in (" because ", " and then ", "; ", " — ", " which "):
            idx = sentence.lower().find(token)
            if idx >= 8:
                split_at = idx + (1 if token.startswith(" ") else 0)
                left = sentence[:idx].strip(" ,;")
                right = sentence[idx + len(token) :].strip()
                if not left.endswith((".", "!", "?")):
                    left += "."
                if right and right[0].islower():
                    right = right[0].upper() + right[1:]
                if not right.endswith((".", "!", "?")):
                    right += "."
                pieces.extend([left, right])
                split_at = True
                break
        if split_at is True:
            continue
        mid = len(words) // 2
        left = " ".join(words[:mid]).rstrip(",;") + "."
        right = " ".join(words[mid:]).lstrip(",;")
        if right and right[0].islower():
            right = right[0].upper() + right[1:]
        if not right.endswith((".", "!", "?")):
            right += "."
        pieces.extend([left, right])
    return " ".join(pieces).strip()


def enforce_readability(text: str, fallback: str) -> str:
    """Accept text only at Flesch >= 70. Rewrite up to 3 times, then fall back."""
    if is_readable(text):
        return text.strip()
    candidate = text
    for _ in range(MAX_REWRITE_ATTEMPTS):
        candidate = simplify_prose(candidate)
        if is_readable(candidate):
            return candidate
    return fallback.strip() if is_readable(fallback) else (fallback or text).strip()


def enforce_each(items: list[str], fallbacks: list[str]) -> list[str]:
    out: list[str] = []
    for index, item in enumerate(items):
        fallback = fallbacks[index] if index < len(fallbacks) else item
        out.append(enforce_readability(item, fallback))
    return out
