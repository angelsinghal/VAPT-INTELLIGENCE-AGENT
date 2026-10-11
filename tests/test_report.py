"""Tests for the deterministic Markdown report generator."""

from __future__ import annotations

from app.models.vapt import VAPTResult
from app.services.report import generate_consolidated_report, generate_markdown


def _make_result(**overrides: object) -> VAPTResult:
    base = dict(
        vulnerability_name="Reflected XSS",
        severity="High",
        owasp="A03:2021 - Injection",
        cwe="CWE-79",
        url="/search",
        parameter="q",
        description="User-controlled input is reflected without encoding.",
        impact="Attackers can steal session cookies or redirect users.",
        remediation={
            "immediate_mitigation": "Block with WAF.",
            "root_cause_fix": "Apply HTML output encoding. Implement CSP headers.",
            "official_references": ["https://owasp.org"]
        },
        poc="Search for <script>alert(1)</script>. Observe reflected script tag.",
        confidence="High",
        reasoning_summary="Input reflected verbatim; consistent with Reflected XSS.",
    )
    base.update(overrides)
    return VAPTResult(**base)


class TestGenerateMarkdown:
    def test_contains_vulnerability_name(self) -> None:
        report = generate_markdown(_make_result())
        assert "Reflected XSS" in report

    def test_contains_severity(self) -> None:
        report = generate_markdown(_make_result())
        assert "High" in report

    def test_contains_owasp(self) -> None:
        report = generate_markdown(_make_result())
        assert "A03:2021" in report

    def test_contains_cwe_link(self) -> None:
        report = generate_markdown(_make_result())
        assert "CWE-79" in report
        assert "cwe.mitre.org" in report

    def test_contains_url(self) -> None:
        report = generate_markdown(_make_result())
        assert "/search" in report

    def test_contains_parameter(self) -> None:
        report = generate_markdown(_make_result())
        assert "`q`" in report

    def test_contains_description(self) -> None:
        report = generate_markdown(_make_result())
        assert "reflected without encoding" in report

    def test_contains_remediation(self) -> None:
        report = generate_markdown(_make_result())
        assert "encoding" in report.lower()

    def test_contains_poc(self) -> None:
        report = generate_markdown(_make_result())
        assert "alert(1)" in report

    def test_contains_reasoning_summary(self) -> None:
        report = generate_markdown(_make_result())
        assert "Reflected XSS" in report

    def test_contains_non_cvss_disclaimer(self) -> None:
        report = generate_markdown(_make_result())
        assert "NOT a replacement" in report

    def test_none_url_handled(self) -> None:
        report = generate_markdown(_make_result(url=None))
        assert "Not specified" in report

    def test_none_cwe_handled(self) -> None:
        report = generate_markdown(_make_result(cwe=None))
        assert "Not determined" in report

    def test_returns_string(self) -> None:
        assert isinstance(generate_markdown(_make_result()), str)


class TestGenerateConsolidatedReport:
    def test_empty_list(self) -> None:
        report = generate_consolidated_report([])
        assert "No findings" in report

    def test_single_finding(self) -> None:
        report = generate_consolidated_report([_make_result()])
        assert "Reflected XSS" in report
        assert "Total Findings**: 1" in report

    def test_multiple_findings_sorted_by_severity(self) -> None:
        critical = _make_result(vulnerability_name="Critical Bug", severity="Critical")
        low = _make_result(vulnerability_name="Low Issue", severity="Low")
        report = generate_consolidated_report([low, critical])
        # Critical should appear before Low in the report
        assert report.index("Critical Bug") < report.index("Low Issue")

    def test_summary_table_present(self) -> None:
        report = generate_consolidated_report([_make_result()])
        assert "Executive Summary" in report

    def test_disclaimer_present(self) -> None:
        report = generate_consolidated_report([_make_result()])
        assert "NOT replacements for formal CVSS" in report
