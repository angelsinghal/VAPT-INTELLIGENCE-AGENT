"""Tests for Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.vapt import (
    BatchAnalyzeRequest,
    SeverityFactors,
    VAPTRequest,
    VAPTResult,
)


class TestVAPTRequest:
    def test_minimal_valid(self) -> None:
        req = VAPTRequest(title="XSS in search", evidence="<script>alert(1)</script> reflected")
        assert req.title == "XSS in search"
        assert req.severity_factors is None

    def test_with_all_fields(self) -> None:
        req = VAPTRequest(
            title="SQL Injection",
            url="/api/users",
            parameter="id",
            evidence="1 AND 1=1--",
            description="SQL injection in user lookup endpoint",
            severity_factors=SeverityFactors(
                exploitability="High",
                authentication_required="None",
                confidentiality_impact="High",
                integrity_impact="High",
                availability_impact="Low",
                user_interaction="None",
            ),
        )
        assert req.url == "/api/users"
        assert req.severity_factors is not None
        assert req.severity_factors.exploitability == "High"

    def test_missing_title_raises(self) -> None:
        with pytest.raises(ValidationError):
            VAPTRequest()  # type: ignore[call-arg]

    def test_empty_title_raises(self) -> None:
        with pytest.raises(ValidationError):
            VAPTRequest(title="")

    def test_severity_factors_invalid_value_raises(self) -> None:
        with pytest.raises(ValidationError):
            SeverityFactors(
                exploitability="Very High",  # invalid
                authentication_required="None",
                confidentiality_impact="High",
                integrity_impact="High",
                availability_impact="Low",
                user_interaction="None",
            )


class TestVAPTResult:
    def _make_result(self, **overrides: object) -> dict:
        base = {
            "vulnerability_name": "Reflected XSS",
            "severity": "High",
            "owasp": "A03:2021 - Injection",
            "cwe": "CWE-79",
            "url": "/search",
            "parameter": "q",
            "description": "User input reflected without encoding.",
            "impact": "Session hijacking possible.",
            "remediation": {
                "immediate_mitigation": "Enable WAF",
                "root_cause_fix": "Apply output encoding.",
                "official_references": ["https://owasp.org"]
            },
            "poc": "Search for <script>alert(1)</script>.",
            "confidence": "High",
            "reasoning_summary": "Input reflected verbatim in response body.",
        }
        base.update(overrides)
        return base

    def test_valid_result(self) -> None:
        result = VAPTResult(**self._make_result())
        assert result.vulnerability_name == "Reflected XSS"
        assert result.severity == "High"

    def test_cwe_can_be_none(self) -> None:
        result = VAPTResult(**self._make_result(cwe=None))
        assert result.cwe is None

    def test_url_can_be_none(self) -> None:
        result = VAPTResult(**self._make_result(url=None))
        assert result.url is None

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValidationError):
            VAPTResult(**self._make_result(severity="SuperHigh"))

    def test_invalid_confidence_raises(self) -> None:
        with pytest.raises(ValidationError):
            VAPTResult(**self._make_result(confidence="Certain"))

    def test_reasoning_summary_required(self) -> None:
        data = self._make_result()
        del data["reasoning_summary"]
        with pytest.raises(ValidationError):
            VAPTResult(**data)


class TestBatchRequest:
    def test_empty_list_raises(self) -> None:
        with pytest.raises(ValidationError):
            BatchAnalyzeRequest(findings=[])

    def test_single_item(self) -> None:
        batch = BatchAnalyzeRequest(
            findings=[VAPTRequest(title="Test finding", evidence="some evidence")]
        )
        assert len(batch.findings) == 1
