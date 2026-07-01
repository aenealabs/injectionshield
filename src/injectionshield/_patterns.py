"""The built-in prompt-injection pattern library.

Pure regex + string heuristics — no ML, no network. Patterns are grouped by
threat category and compiled once at import. The library is versioned with the
package; add rules here (and tests) rather than at call sites.

Categories:
    instruction_override — override/ignore the system's instructions
    role_confusion       — coerce the model into a new, unconstrained persona
    data_exfiltration    — extract the system prompt / hidden instructions
    jailbreak_persona    — known jailbreak modes and social-engineering framings
    indirect_injection   — instructions smuggled inside external content
    pii_extraction       — pull another user's data or prior messages
"""

from __future__ import annotations

import re

from ._types import Pattern, PatternSet, RiskLevel

_DOTALL = re.IGNORECASE | re.DOTALL
_MULTILINE = re.IGNORECASE | re.MULTILINE

_PATTERNS = [
    # ── instruction_override (CRITICAL) ──────────────────────────────────
    Pattern(
        "ignore_previous_instructions",
        r"\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+|your\s+)?"
        r"(previous|prior|above|earlier|preceding|foregoing)\s+"
        r"(instructions?|prompts?|messages?|context|directives?|rules?)",
        "instruction_override", RiskLevel.CRITICAL,
    ),
    Pattern(
        "forget_what_told",
        r"\bforget\s+(everything|all|what)\s+(you|i)\s+"
        r"(were|was|have\s+been|had\s+been)\s+told",
        "instruction_override", RiskLevel.CRITICAL,
    ),
    Pattern(
        "override_your_rules",
        r"\b(override|bypass|nullify|ignore|disable)\s+(your|the|all|any)\s+"
        r"(instructions?|rules?|restrictions?|guidelines?|guardrails?|filters?|policies)",
        "instruction_override", RiskLevel.CRITICAL,
    ),
    Pattern(
        "new_instructions_marker",
        r"\b(new|updated|revised|real|actual)\s+instructions?\s*:",
        "instruction_override", RiskLevel.HIGH,
    ),

    # ── role_confusion (HIGH) ────────────────────────────────────────────
    Pattern(
        "you_are_now",
        r"\byou\s+are\s+now\s+(a\s+|an\s+|the\s+)?(?:\w+\s+){0,2}?"
        r"(assistant|ai|bot|dan|model|persona|character|entity)\b",
        "role_confusion", RiskLevel.HIGH,
    ),
    Pattern(
        "act_as_unconstrained",
        r"\bact\s+as\s+(an?\s+)?(unconstrained|unrestricted|unfiltered|jailbroken|"
        r"evil|amoral|lawless|uncensored)\b",
        "role_confusion", RiskLevel.HIGH,
    ),
    Pattern(
        "pretend_no_rules",
        r"\bpretend\s+(that\s+)?(you|to)\s+(are|have|has|had)\s+no\s+"
        r"(rules?|restrictions?|limits?|limitations?|guidelines?|filters?)",
        "role_confusion", RiskLevel.HIGH,
    ),
    Pattern(
        "you_have_no_restrictions",
        r"\byou\s+(have|now\s+have)\s+no\s+"
        r"(restrictions?|rules?|limitations?|limits?|guidelines?|filters?|guardrails?)",
        "role_confusion", RiskLevel.HIGH,
    ),

    # ── data_exfiltration (CRITICAL) ─────────────────────────────────────
    Pattern(
        "reveal_system_prompt",
        r"\b(output|print|show|reveal|repeat|display|tell\s+me|give\s+me|share)\s+"
        r"(me\s+)?(your|the)\s+(full\s+|complete\s+|entire\s+|original\s+|initial\s+)?"
        r"(system\s+prompt|instructions?|initial\s+prompt|prompt|configuration|directives?)",
        "data_exfiltration", RiskLevel.CRITICAL,
    ),
    Pattern(
        "repeat_everything_above",
        r"\brepeat\s+(everything|all|the\s+text|the\s+words)\s+"
        r"(you\s+were\s+(told|given)|above|before|prior)",
        "data_exfiltration", RiskLevel.CRITICAL,
    ),
    Pattern(
        "what_are_your_instructions",
        r"\bwhat\s+(is|are|were)\s+your\s+(original\s+|initial\s+|exact\s+)?"
        r"(instructions?|system\s+prompt|rules?|directives?|guidelines?)",
        "data_exfiltration", RiskLevel.HIGH,
    ),

    # ── jailbreak_persona (HIGH) ─────────────────────────────────────────
    Pattern(
        "special_mode",
        # Require activation/state framing so benign nouns like "the developer
        # mode in the app" don't trip the rule.
        r"\b(enter|enable|activate|switch\s+to|turn\s+on|go\s+into|going\s+into|"
        r"you\s+are\s+in|now\s+in|into)\s+"
        r"(developer|debug|god|admin|root|sudo|maintenance|unrestricted|"
        r"unfiltered|jailbreak)\s+mode\b",
        "jailbreak_persona", RiskLevel.HIGH,
    ),
    Pattern(
        "dan_do_anything_now",
        r"\b(do\s+anything\s+now|DAN\s+mode|DAN\s+prompt)\b",
        "jailbreak_persona", RiskLevel.HIGH,
        flags=re.IGNORECASE,
    ),
    Pattern(
        "jailbreak_word",
        r"\bjailbr(eak|oken|eaking)\b",
        "jailbreak_persona", RiskLevel.HIGH,
    ),
    Pattern(
        "deceased_grandma",
        # The exploit is the *roleplay framing*, not any mention of a late
        # relative — require a pretend/be-my cue near the grandma reference.
        r"\b(pretend|act\s+as|roleplay|role-play|imagine\s+you|you\s+are|be\s+my)\b"
        r"[^.]{0,40}?\b(deceased|late|dead)\s+grand(ma|mother|pa|father)\b",
        "jailbreak_persona", RiskLevel.MEDIUM,
    ),

    # ── indirect_injection (MEDIUM) — smuggled in external content ────────
    Pattern(
        "html_comment_injection",
        r"<!--[^>]*?\b(ignore|instruction|system\s*prompt|assistant|you\s+are|"
        r"disregard)\b[^>]*?-->",
        "indirect_injection", RiskLevel.MEDIUM, flags=_DOTALL,
    ),
    Pattern(
        "role_prefix_injection",
        r"^\s*(system|assistant)\s*:\s*\S",
        "indirect_injection", RiskLevel.MEDIUM, flags=_MULTILINE,
    ),
    Pattern(
        "zero_width_obfuscation",
        "[\u200b\u200c\u200d\u2060\ufeff]",  # zero-width space/joiner/no-break etc.
        "indirect_injection", RiskLevel.MEDIUM, flags=0,
    ),
    Pattern(
        "attention_ai_marker",
        r"\b(important|urgent|attention|note\s+to)\s*[:!-]*\s*"
        r"(ai|assistant|llm|language\s+model|system|chatbot)\b",
        "indirect_injection", RiskLevel.LOW,
    ),

    # ── pii_extraction (HIGH) ────────────────────────────────────────────
    Pattern(
        "ask_user_secret",
        r"\bwhat\s+(is|was)\s+the\s+(previous\s+)?user('s)?\s+"
        r"(email|password|name|address|phone|ssn|credit\s+card|api\s+key|token)",
        "pii_extraction", RiskLevel.HIGH,
    ),
    Pattern(
        "reveal_previous_message",
        r"\b(output|show|reveal|repeat|print)\s+the\s+(previous|prior|last|other)\s+"
        r"(user('s)?\s+)?(message|input|conversation|prompt|query)",
        "pii_extraction", RiskLevel.HIGH,
    ),
    Pattern(
        "dump_all_secrets",
        r"\b(list|show|dump|output|print)\s+(all\s+|every\s+)?"
        r"(users?|passwords?|api\s+keys?|secrets?|credentials?|tokens?)\b",
        "pii_extraction", RiskLevel.HIGH,
    ),
]

DEFAULT_PATTERNS = PatternSet(_PATTERNS)
