"""Answer checks: citation provenance, injection indicators, privacy and arithmetic.

These helpers must be invoked by answer assembly; Gateway does not receive ANSWER.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

# kit.world.anchor is a collaborator's file (workspace hard rule 2). Present
# and stable as of this writing; degraded gracefully so `check_grounding`
# still runs (with the anchor-syntax leg of the check skipped, not silently
# treated as passing) if it is ever briefly unimportable.
try:
    from kit.world.anchor import Anchor, AnchorSyntaxError
    _ANCHOR_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    Anchor = None  # type: ignore[assignment]
    AnchorSyntaxError = ValueError  # type: ignore[assignment, misc]
    _ANCHOR_AVAILABLE = False

__all__ = [
    "GroundingResult",
    "check_grounding",
    "InjectionScanResult",
    "scan_for_injected_instructions",
    "RedactionResult",
    "redact",
    "ArithmeticCheckResult",
    "verify_arithmetic",
    "abstention_policy",
]


# ---------------------------------------------------------------------------
# 1. GROUNDING — real, working.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GroundingResult:
    grounded: bool
    cited: tuple[str, ...]
    ungrounded: tuple[str, ...]  # cited, syntactically valid, but never retrieved this exchange
    malformed: tuple[str, ...]  # cited but not even valid Anchor syntax


def check_grounding(
    answer: Mapping[str, Any],
    retrieved_anchors: Iterable[str],
    *,
    require_citation: bool = True,
) -> GroundingResult:
    """"Every claim traces to a returned anchor" (this task's own brief),
    made concrete: every string in `answer["cited_anchors"]` must (a) parse
    as valid `ns:slug[/rev][/idx][#span]` syntax (`kit.world.anchor.Anchor`)
    and (b) be a member of `retrieved_anchors` — the anchors YOUR exchange
    actually got back from a `tool_result` this round, not anchors you
    recognise from having seen them before, and not anchors you are
    inferring exist.

    `retrieved_anchors` is YOUR responsibility to assemble honestly — the
    right source is the union of every `tool_result.anchors` your agent
    received this exchange (CONTRACTS.md 5.2's `tool_result` event field),
    never something wider like "every anchor this world index contains".
    Passing a wider set than what you actually retrieved makes this
    function agree with citations that are `ungrounded` in the sense that
    actually matters (CONTRACTS.md 6.1's rubric class) even though this
    function would call them grounded.

    Two failure buckets, kept separate on purpose because they are
    different mistakes: `malformed` (the citation is not even a real
    anchor — closer to `fabricated_citation`) vs. `ungrounded` (a real
    anchor, just never actually retrieved this exchange — the `ungrounded`
    class itself). `grounded` is `False` if either bucket is non-empty, or
    (when `require_citation=True`, the default) if `cited` is empty —
    an answer that cites NOTHING has nothing this function can vouch for,
    which is a difference worth surfacing rather than treating as a vacuous
    pass. Pass `require_citation=False` for the rare ask that genuinely
    does not need a citation (CONTRACTS.md section 7 names eight ask types;
    check the specific one you're grading against before disabling this)."""
    cited = tuple(answer.get("cited_anchors") or ())
    retrieved = frozenset(retrieved_anchors)

    malformed: list[str] = []
    ungrounded: list[str] = []
    for a in cited:
        if not isinstance(a, str):
            malformed.append(str(a))
            continue
        if _ANCHOR_AVAILABLE:
            try:
                Anchor.parse(a)
            except AnchorSyntaxError:
                malformed.append(a)
                continue
        if a not in retrieved:
            ungrounded.append(a)

    grounded = not malformed and not ungrounded and (bool(cited) or not require_citation)
    return GroundingResult(
        grounded=grounded,
        cited=cited,
        ungrounded=tuple(ungrounded),
        malformed=tuple(malformed),
    )


# ---------------------------------------------------------------------------
# 2. INJECTED-INSTRUCTION REFUSAL.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InjectionScanResult:
    suspicious: bool
    matched_patterns: tuple[str, ...]


_INJECTION_PATTERNS = (
    r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|the above)\s+instructions?",
    r"\bsystem\s+override\b",
    r"\byou must now\s+(?:reveal|print|send|record|delete|ignore)",
    r"\b(?:reveal|print|exfiltrate)\s+(?:the\s+)?(?:api[_ ]?key|secrets?|access token|system prompt)",
    r"\b(?:also|instead[, ]*)\s*record\s+(?:this\s+)?for\s+learner:",
    r"bỏ qua\s+(?:mọi|tất cả|các)\s+(?:hướng dẫn|chỉ dẫn)",
    r"(?:tiết lộ|in ra|gửi đi)\s+(?:khóa api|mật khẩu|bí mật|system prompt)",
)


def scan_for_injected_instructions(text: str) -> InjectionScanResult:
    """Conservative pattern detector, not a proof that unmatched text is safe."""
    hits = tuple(p for p in _INJECTION_PATTERNS if re.search(p, text, re.IGNORECASE))
    return InjectionScanResult(suspicious=bool(hits), matched_patterns=hits)


# ---------------------------------------------------------------------------
# 3. REDACTION.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RedactionResult:
    redacted_text: str
    hits: tuple[str, ...]


def redact(text: str, private_values: Iterable[str] = ()) -> RedactionResult:
    """Redact supplied private values and common contact/credential formats."""
    hits = []
    for value in sorted(set(private_values), key=lambda v: (-len(v), v)):
        if value and value in text:
            text = text.replace(value, "[REDACTED]")
            hits.append("private_value")
    patterns = (
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ("phone", r"(?<![\w/])(?:\+84|0)(?:[ .-]?\d){9,10}(?![\w/])"),
        ("credential", r"(?i)\b(?:api[_ -]?key|password|access[_ -]?token|secret)\s*[:=]\s*[\"']?[^\s,;\"']+"),
    )
    for label, pattern in patterns:
        text, count = re.subn(pattern, "[REDACTED]", text)
        if count:
            hits.append(label)
    return RedactionResult(redacted_text=text, hits=tuple(hits))


# ---------------------------------------------------------------------------
# 4. ARITHMETIC VERIFICATION.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ArithmeticCheckResult:
    checked: bool
    ok: bool | None
    detail: str


_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")


def verify_arithmetic(text: str, sources: Iterable[str] | None = None) -> ArithmeticCheckResult:
    """Check simple explicit equations and, when supplied, source-backed numbers.

    No general expression execution. Unsupported expressions remain unchecked.
    """
    from decimal import Decimal, InvalidOperation
    equation = re.compile(r"(-?\d+(?:\.\d+)?)\s*([+*/×÷−-])\s*(-?\d+(?:\.\d+)?)\s*=\s*(-?\d+(?:\.\d+)?)")
    matches = list(equation.finditer(text))
    derived = set()
    for match in matches:
        left, op, right, result = match.groups()
        x, y, z = Decimal(left), Decimal(right), Decimal(result)
        if op in ("/", "÷") and y == 0:
            return ArithmeticCheckResult(True, False, "division by zero")
        expected = x + y if op == "+" else x - y if op in ("-", "−") else x * y if op in ("*", "×") else x / y
        if expected != z:
            return ArithmeticCheckResult(True, False, "equation does not hold: " + match.group())
        derived.add(result)
    if sources is not None:
        def numbers(value):
            # Citation IDs and their frame numbers are identifiers, not factual precision.
            value = re.sub(r"\b[A-Z][A-Za-z]*:[^\s,;]+", "", value)
            return _NUMBER_RE.findall(value)
        supported = {}
        for source in sources:
            for value in numbers(source):
                try:
                    number = Decimal(value)
                    supported[number] = min(supported.get(number, 0), Decimal(value).as_tuple().exponent)
                except InvalidOperation:
                    continue
        for value in numbers(text):
            if value in derived:
                continue
            number = Decimal(value)
            if number not in supported or number.as_tuple().exponent < supported[number]:
                return ArithmeticCheckResult(True, False, "number or precision lacks retrieved support: " + value)
        return ArithmeticCheckResult(True, True, "equations and numeric precision checked against supplied sources")
    return ArithmeticCheckResult(bool(matches), True if matches else None,
                                 "explicit equations checked" if matches else "no supported explicit equation; source grounding not checked")


# ---------------------------------------------------------------------------
# 5. ABSTENTION POLICY — real, naive.
# ---------------------------------------------------------------------------


def abstention_policy(grounding: GroundingResult) -> bool:
    """`True` iff you should abstain (answer with an honest "insufficient
    grounding" rather than submit this ANSWER as-is). Naive on purpose: it
    reuses the ONE guardrail this file can actually vouch for
    (`check_grounding`) and nothing else — your own confidence, a
    conflicting second source (`unflagged_conflict`, CONTRACTS.md 6.1),
    and the ask's own `require`d fields (CONTRACTS.md section 7) all go
    completely unweighed here. CONTRACTS.md's own prompt guidance
    (kit/loop/prompt.py's `SYSTEM_PROMPT`) puts it plainly: "a wrong answer
    costs more than an honest 'insufficient grounding'" — this function is
    the bare floor of that policy, not the ceiling."""
    return not grounding.grounded
