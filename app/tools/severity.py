"""Deterministic severity assessment tool.

This module provides a simple severity calculator based on six CVSS-inspired
factors.  It is NOT a formal CVSS implementation and does NOT produce CVSS
scores or vectors.  Call ``assess_severity`` only when ALL six factors are
present; for partial or missing factors, use LLM-assisted assessment instead.

.. warning::
    Severity produced by this tool is a simplified evidence-based assessment
    and is NOT a replacement for a formal CVSS assessment.
"""

from __future__ import annotations

from typing import Literal

SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]

# Numeric weights per factor value
_EXPLOITABILITY: dict[str, int] = {"High": 3, "Medium": 2, "Low": 1}
_AUTH: dict[str, int] = {"None": 3, "Low": 2, "High": 1}
_IMPACT: dict[str, int] = {"High": 3, "Low": 1, "None": 0}
_USER_INTERACTION: dict[str, int] = {"None": 2, "Required": 1}

# Maximum achievable score (for ratio calculation)
_MAX_SCORE: int = (3 * 2) + 3 + 3 + 3 + 3 + 2  # = 20

REQUIRED_FACTORS: frozenset[str] = frozenset(
    {
        "exploitability",
        "authentication_required",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
        "user_interaction",
    }
)


def assess_severity(factors: dict[str, str]) -> dict[str, str]:
    """Compute a severity level from the six supplied factors.

    Args:
        factors: Must contain all six keys defined in ``REQUIRED_FACTORS``.

    Returns:
        A dict with keys ``"severity"`` (SeverityLevel) and ``"reason"``
        (human-readable justification).

    Raises:
        ValueError: If any of the six required factors is missing.
    """
    missing = REQUIRED_FACTORS - factors.keys()
    if missing:
        raise ValueError(f"assess_severity requires all 6 factors; missing: {sorted(missing)}")

    exploitability = factors["exploitability"]
    auth_required = factors["authentication_required"]
    confidentiality = factors["confidentiality_impact"]
    integrity = factors["integrity_impact"]
    availability = factors["availability_impact"]
    user_interaction = factors["user_interaction"]

    exp_score = _EXPLOITABILITY.get(exploitability, 0)
    auth_score = _AUTH.get(auth_required, 0)
    conf_score = _IMPACT.get(confidentiality, 0)
    integ_score = _IMPACT.get(integrity, 0)
    avail_score = _IMPACT.get(availability, 0)
    ui_score = _USER_INTERACTION.get(user_interaction, 0)

    # Exploitability is weighted double (dominant factor)
    total = (exp_score * 2) + auth_score + conf_score + integ_score + avail_score + ui_score
    ratio = total / _MAX_SCORE

    if ratio >= 0.85:
        level: SeverityLevel = "Critical"
    elif ratio >= 0.65:
        level = "High"
    elif ratio >= 0.45:
        level = "Medium"
    elif ratio >= 0.20:
        level = "Low"
    else:
        level = "Informational"

    reason = (
        f"Exploitability={exploitability}, "
        f"AuthenticationRequired={auth_required}, "
        f"ConfidentialityImpact={confidentiality}, "
        f"IntegrityImpact={integrity}, "
        f"AvailabilityImpact={availability}, "
        f"UserInteraction={user_interaction}. "
        f"Score={total}/{_MAX_SCORE} ({ratio:.0%}). "
        "Note: This is a simplified evidence-based assessment; "
        "it is NOT a formal CVSS score."
    )

    return {"severity": level, "reason": reason}
