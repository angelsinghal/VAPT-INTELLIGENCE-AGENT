"""Pydantic models for VAPT request and result schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Severity factors (CVSS-inspired, NOT a formal CVSS implementation)
# ---------------------------------------------------------------------------


class SeverityFactors(BaseModel):
    """Six-factor severity input.

    All six fields must be supplied for the deterministic severity calculator
    to run.  If fewer than six are provided the LLM performs a conservative
    AI-assisted assessment instead.

    .. note::
        This is a simplified evidence-based model and is NOT a replacement
        for a formal CVSS assessment.
    """

    exploitability: Literal["Low", "Medium", "High"]
    authentication_required: Literal["None", "Low", "High"]
    confidentiality_impact: Literal["None", "Low", "High"]
    integrity_impact: Literal["None", "Low", "High"]
    availability_impact: Literal["None", "Low", "High"]
    user_interaction: Literal["None", "Required"]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class VAPTRequest(BaseModel):
    """Single VAPT finding submitted for analysis."""

    title: str = Field(..., min_length=3, max_length=200, description="Short title of the finding")
    url: str | None = Field(None, max_length=2048, description="Affected URL or endpoint")
    parameter: str | None = Field(
        None, max_length=500, description="Affected parameter or input field"
    )
    evidence: str | None = Field(
        None, max_length=8000, description="Raw evidence captured during testing"
    )
    description: str | None = Field(
        None, max_length=4000, description="Tester description of the finding"
    )
    severity_factors: SeverityFactors | None = Field(
        None,
        description=(
            "CVSS-inspired severity factors. "
            "All 6 must be provided for deterministic calculation; "
            "otherwise an AI-assisted conservative assessment is used."
        ),
    )


class BatchAnalyzeRequest(BaseModel):
    findings: list[VAPTRequest] = Field(..., min_length=1, max_length=20)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class RemediationPlan(BaseModel):
    """Structured, developer-focused remediation action plan."""
    immediate_mitigation: str = Field(..., description="Quick infra/ops change to stop the bleeding today (e.g. WAF rules, config changes).")
    root_cause_fix: str = Field(..., description="Contextualized architectural instructions for the software engineer to fix the core flaw.")
    official_references: list[str] = Field(..., description="1-3 URLs to official documentation like OWASP or CWE.")

class VAPTResult(BaseModel):
    """Structured output produced by the VAPT analysis agent."""

    vulnerability_name: str = Field(..., description="Canonical name of the vulnerability")
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    owasp: str = Field(..., description="OWASP Top 10 (2021) mapping")
    cwe: str | None = Field(None, description="CWE identifier, or null if no confident mapping")
    url: str | None = Field(None, description="Preserved from the original request")
    parameter: str | None = Field(None, description="Preserved from the original request")
    description: str = Field(..., description="Professional vulnerability description")
    impact: str = Field(..., description="Business and technical impact analysis")
    remediation: RemediationPlan = Field(..., description="Structured, contextualized developer remediation plan")
    poc: str = Field(..., description="Proof of concept or reproduction steps")
    confidence: Literal["High", "Medium", "Low"]
    reasoning_summary: str = Field(
        ...,
        description="Concise evidence-based explanation (no chain-of-thought)",
    )


# ---------------------------------------------------------------------------
# API response wrappers
# ---------------------------------------------------------------------------


class AnalyzeResponse(BaseModel):
    success: bool
    result: VAPTResult | None = None
    report: str | None = None
    error: str | None = None


class BatchAnalyzeResponse(BaseModel):
    success: bool
    results: list[AnalyzeResponse]
    total: int
    successful: int
    failed: int
