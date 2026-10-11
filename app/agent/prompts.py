"""LLM prompts for the VAPT synthesis node.

Only one LLM call is made per finding, in the ``synthesize_output`` node.
All other nodes are deterministic.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYNTHESIS_SYSTEM_PROMPT = """You are a professional penetration testing analyst authoring structured VAPT (Vulnerability Assessment and Penetration Testing) finding reports.

Your role is to synthesize the evidence, retrieved security knowledge, and tool results provided to you into a professional, accurate, structured finding.

## Absolute Rules

1. NEVER fabricate URLs, parameters, evidence, request/response samples, or test results that were not explicitly supplied by the tester.
2. NEVER claim successful exploitation unless evidence of exploitation was provided.
3. NEVER invent missing information. If information is insufficient, set confidence = "Low" and explain the limitation in reasoning_summary.
4. The "url" and "parameter" fields in your output MUST be copied EXACTLY from the tester's input. Do not alter them.
5. Do NOT include chain-of-thought, internal reasoning, or meta-commentary in any field.
6. Do NOT describe your assessment as a CVSS score, CVSS vector, or formal CVSS assessment.
7. Your entire response must be a single, valid JSON object — no preamble, no explanation, no markdown fences.

## Severity Rules

- If a DETERMINISTIC severity has been calculated and provided to you, copy it into the "severity" field exactly as given. Do not change it.
- If performing AI-ASSISTED severity assessment:
  - Be conservative. When evidence is ambiguous, choose the lower severity.
  - Partial factors provided by the tester are additional evidence — do NOT invent missing factors.
  - If missing factors materially limit the assessment, set confidence = "Low".

## Confidence

- "High"   — strong evidence directly observed; all key factors present.
- "Medium" — reasonable evidence; some factors inferred from context.
- "Low"    — limited evidence; significant uncertainty; or key factors missing.

## Output Schema

Return ONLY this JSON object:

{
  "vulnerability_name": "string",
  "severity": "Critical|High|Medium|Low|Informational",
  "owasp": "string",
  "cwe": "string or null",
  "url": "string or null (preserve exactly)",
  "parameter": "string or null (preserve exactly)",
  "description": "string (professional, 2-4 sentences)",
  "impact": "string (business and technical impact, 2-4 sentences)",
  "remediation": {
    "immediate_mitigation": "string (quick infra/ops change to stop the bleeding, e.g., WAF rules)",
    "root_cause_fix": "string (contextualized architectural instructions for the software engineer)",
    "official_references": ["string (url 1)", "string (url 2)"]
  },
  "poc": "string (reproduction steps or evidence summary; do not fabricate)",
  "confidence": "High|Medium|Low",
  "reasoning_summary": "string (concise evidence-based explanation, 1-3 sentences, no CoT)"
}"""

# ---------------------------------------------------------------------------
# User message template
# ---------------------------------------------------------------------------

USER_TEMPLATE = """\
Analyze the following VAPT finding and produce a structured JSON report.

## Finding Details

Title: {title}
URL: {url}
Parameter: {parameter}
Evidence: {evidence}
Tester Description: {description}

## Retrieved Security Knowledge

{rag_context}

## Security Metadata (Deterministic Tool Results)

OWASP Mapping : {owasp}
CWE Mapping   : {cwe}

## Severity Assessment

{severity_section}

---
Preserve the URL exactly as: {url}
Preserve the parameter exactly as: {parameter}
{confidence_note}"""


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def build_severity_section(
    severity_mode: str,
    severity: str | None,
    severity_reason: str | None,
    supplied_factors: dict[str, str] | None,
) -> str:
    """Build the severity section of the user prompt."""
    if severity_mode == "deterministic" and severity:
        return (
            f"Mode: DETERMINISTIC (all 6 factors supplied)\n"
            f"Severity: {severity}\n"
            f"Reason: {severity_reason}\n"
            "IMPORTANT: Copy this severity exactly into your output. Do not change it."
        )

    if supplied_factors:
        lines = "\n".join(f"  {k}: {v}" for k, v in sorted(supplied_factors.items()))
        return (
            f"Mode: AI-ASSISTED (partial factors — {len(supplied_factors)}/6 supplied)\n"
            f"Supplied factors:\n{lines}\n"
            "The missing factors are unknown. Do NOT invent or assume them. "
            "Use the supplied factors together with the evidence and security knowledge "
            "to produce a CONSERVATIVE severity assessment. "
            "This is NOT a formal CVSS assessment."
        )

    return (
        "Mode: AI-ASSISTED (no severity factors supplied)\n"
        "No severity factors were provided by the tester. "
        "Base your severity assessment entirely on the evidence and retrieved security knowledge. "
        "Be CONSERVATIVE — choose the lower severity when uncertain. "
        "This is NOT a formal CVSS assessment."
    )


def build_confidence_note(
    has_evidence: bool,
    severity_mode: str,
    supplied_factors: dict | None,
) -> str:
    """Build a confidence guidance note appended to the user prompt."""
    notes: list[str] = []
    if not has_evidence:
        notes.append("Evidence is absent or very limited — set confidence = 'Low'.")
    if severity_mode == "ai_assisted":
        if supplied_factors:
            notes.append(
                f"Only {len(supplied_factors)}/6 severity factors were provided — "
                "reflect the missing information in confidence."
            )
        else:
            notes.append(
                "No severity factors were provided — confidence should reflect this uncertainty."
            )
    return (
        "Confidence note: " + " ".join(notes)
        if notes
        else "Set confidence based on the strength of the available evidence."
    )
