"""API integration tests using a mocked LangGraph pipeline."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.models.vapt import VAPTResult

# ── Fixtures ────────────────────────────────────────────────────────────────

MOCK_RESULT = VAPTResult(
    vulnerability_name="Reflected XSS",
    severity="High",
    owasp="A03:2021 - Injection",
    cwe="CWE-79",
    url="/search",
    parameter="q",
    description="User-controlled input reflected without output encoding.",
    impact="An attacker can steal session cookies or perform phishing.",
    remediation={
        "immediate_mitigation": "Apply WAF rules to block script tags.",
        "root_cause_fix": "Apply HTML output encoding. Implement Content Security Policy headers.",
        "official_references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]
    },
    poc="Search for <script>alert(1)</script>. Observe script tag reflected in response.",
    confidence="High",
    reasoning_summary="Evidence shows user input reflected verbatim in HTML response.",
)

MOCK_STATE: dict[str, Any] = {
    "result": MOCK_RESULT,
    "report": "# VAPT Finding Report\n\nMock report.",
    "errors": [],
}


@pytest.fixture()
def mock_rag_ready() -> Any:
    """Patch is_ready as imported in routes so the server accepts analysis requests."""
    with patch("app.api.routes.is_ready", return_value=True):
        yield


@pytest.fixture()
def mock_run_analysis(mock_rag_ready: Any) -> Any:
    """Patch run_analysis to return MOCK_STATE without making LLM or DB calls."""
    with patch("app.api.routes.run_analysis", new_callable=AsyncMock) as m:
        m.return_value = MOCK_STATE
        yield m


@pytest.fixture()
def client() -> TestClient:
    from app.main import create_app

    application = create_app()
    return TestClient(application)



# ── Health endpoint ──────────────────────────────────────────────────────────


class TestHealth:
    def test_health_always_200(self, client: TestClient) -> None:
        with patch("app.api.routes.is_ready", return_value=False):
            resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_rag_not_ready(self, client: TestClient) -> None:
        with patch("app.api.routes.is_ready", return_value=False):
            resp = client.get("/health")
        data = resp.json()
        assert data["rag_ready"] is False
        assert "message" in data

    def test_health_rag_ready(self, client: TestClient, mock_rag_ready: Any) -> None:
        with patch("app.api.routes.is_ready", return_value=True):
            resp = client.get("/health")
        data = resp.json()
        assert data["rag_ready"] is True
        assert data["status"] == "ok"


# ── Single analysis endpoint ─────────────────────────────────────────────────


class TestAnalyze:
    PAYLOAD = {
        "title": "Reflected XSS in search",
        "url": "/search",
        "parameter": "q",
        "evidence": "<script>alert(1)</script> reflected in response",
        "description": "User input reflected without encoding",
    }

    def test_analyze_success(self, client: TestClient, mock_run_analysis: AsyncMock) -> None:
        resp = client.post("/api/v1/analyze", json=self.PAYLOAD)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["result"]["vulnerability_name"] == "Reflected XSS"
        assert data["result"]["severity"] == "High"

    def test_analyze_preserves_url(self, client: TestClient, mock_run_analysis: AsyncMock) -> None:
        resp = client.post("/api/v1/analyze", json=self.PAYLOAD)
        assert resp.json()["result"]["url"] == "/search"

    def test_analyze_missing_title_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/analyze", json={"evidence": "some evidence"})
        assert resp.status_code == 422

    def test_analyze_rag_not_ready_returns_503(self, client: TestClient) -> None:
        with patch("app.api.routes.is_ready", return_value=False):
            resp = client.post("/api/v1/analyze", json=self.PAYLOAD)
        assert resp.status_code == 503

    def test_analyze_with_all_severity_factors(
        self, client: TestClient, mock_run_analysis: AsyncMock
    ) -> None:
        payload = {
            **self.PAYLOAD,
            "severity_factors": {
                "exploitability": "High",
                "authentication_required": "None",
                "confidentiality_impact": "High",
                "integrity_impact": "High",
                "availability_impact": "Low",
                "user_interaction": "None",
            },
        }
        resp = client.post("/api/v1/analyze", json=payload)
        assert resp.status_code == 200

    def test_analyze_pipeline_error_returns_failure(
        self, client: TestClient, mock_rag_ready: Any
    ) -> None:
        error_state = {"result": None, "errors": ["LLM synthesis error: timeout"], "report": None}
        with patch("app.api.routes.run_analysis", new_callable=AsyncMock) as m:
            m.return_value = error_state
            resp = client.post("/api/v1/analyze", json=self.PAYLOAD)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "error" in data


# ── Batch analysis endpoint ───────────────────────────────────────────────────


class TestBatchAnalyze:
    def test_batch_success(self, client: TestClient, mock_run_analysis: AsyncMock) -> None:
        payload = {
            "findings": [
                {"title": "XSS", "evidence": "reflected input"},
                {"title": "SQLI", "evidence": "1 AND 1=1"},
            ]
        }
        resp = client.post("/api/v1/analyze/batch", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["successful"] == 2

    def test_batch_empty_list_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/analyze/batch", json={"findings": []})
        assert resp.status_code == 422

    def test_batch_rag_not_ready_returns_503(self, client: TestClient) -> None:
        with patch("app.api.routes.is_ready", return_value=False):
            resp = client.post(
                "/api/v1/analyze/batch",
                json={"findings": [{"title": "XSS", "evidence": "test"}]},
            )
        assert resp.status_code == 503


# ── Report endpoint ──────────────────────────────────────────────────────────


class TestReportEndpoint:
    RESULT_PAYLOAD = {
        "vulnerability_name": "SQL Injection",
        "severity": "Critical",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-89",
        "url": "/api/users",
        "parameter": "id",
        "description": "SQL injection vulnerability detected.",
        "impact": "Full database compromise.",
        "remediation": {
            "immediate_mitigation": "Disable the affected endpoint temporarily.",
            "root_cause_fix": "Use parameterised queries.",
            "official_references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
        },
        "poc": "id=1 AND 1=1--",
        "confidence": "High",
        "reasoning_summary": "Classic SQL injection pattern in id parameter.",
    }

    def test_report_returns_markdown(self, client: TestClient) -> None:
        resp = client.post("/api/v1/report", json=self.RESULT_PAYLOAD)
        assert resp.status_code == 200
        assert "SQL Injection" in resp.text
        assert "# VAPT Finding Report" in resp.text

    def test_report_invalid_payload_returns_422(self, client: TestClient) -> None:
        resp = client.post("/api/v1/report", json={"foo": "bar"})
        assert resp.status_code == 422
