"""Optional answer assembly guard, called before emitting an ANSWER action.

The arena does not route ANSWER through Gateway. Callers must explicitly use
this helper; prompt.md supplies the corresponding policy for model-only callers.
"""
from __future__ import annotations

from agent.guardrails import check_grounding, redact, scan_for_injected_instructions, verify_arithmetic


def prepare_answer(answer, observations, *, required=(), private_values=()):
    """Return (sanitized_answer, errors). Never fabricate required facts or receipts."""
    output = dict(answer)
    anchors = []
    sources = []
    errors = []
    for result in observations:
        if not result.get("ok"):
            continue
        safe_rows = []
        rows = result.get("rows", ())
        for row in rows:
            if not isinstance(row, dict):
                continue
            body = str(row.get("body") or row.get("definition") or row.get("snippet") or "")
            if row.get("private") or scan_for_injected_instructions(body).suspicious:
                errors.append("unsafe retrieved content excluded")
                continue
            safe_rows.append(row)
            sources.append(" ".join(str(v) for v in row.values()))
        # Rows and anchors need not be one-to-one. Do not assume an unsafe row's
        # anchor can be isolated when an observation doesn't identify it explicitly.
        if len(safe_rows) != len(rows):
            continue
        if result.get("partial"):
            errors.append("partial result: complete retrieval before treating it as exhaustive")
            continue
        anchors.extend(result.get("anchors", ()))
    grounding = check_grounding(output, anchors)
    if not grounding.grounded:
        errors.append("citation missing, malformed, or not retrieved from safe complete results")
    if any(key not in output or output[key] is None for key in required):
        errors.append("required structured answer fields missing")
    text = str(output.get("text", ""))
    arithmetic = verify_arithmetic(text, sources=sources)
    if arithmetic.ok is False:
        errors.append(arithmetic.detail)
    redacted = redact(text, private_values)
    if redacted.hits:
        errors.append("private data was redacted")
    output["text"] = redacted.redacted_text
    # Sentence refs must address the text actually emitted, after redaction.
    import re
    output["spans"] = re.split(r"[.!?]\s+", output["text"]) if output["text"] else []
    return output, tuple(errors)
