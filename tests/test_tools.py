"""Tests for deterministic tool modules."""

from __future__ import annotations

import pytest

from app.tools.cwe import lookup_cwe
from app.tools.owasp import lookup_owasp
from app.tools.severity import REQUIRED_FACTORS, assess_severity

# ---------------------------------------------------------------------------
# OWASP tool
# ---------------------------------------------------------------------------


class TestLookupOwasp:
    def test_exact_match_xss(self) -> None:
        assert lookup_owasp(["xss"]) == "A03:2021 - Injection"

    def test_exact_match_sqli(self) -> None:
        assert lookup_owasp(["sql injection"]) == "A03:2021 - Injection"

    def test_exact_match_ssrf(self) -> None:
        assert lookup_owasp(["ssrf"]) == "A10:2021 - Server-Side Request Forgery"

    def test_exact_match_broken_access_control(self) -> None:
        assert lookup_owasp(["broken access control"]) == "A01:2021 - Broken Access Control"

    def test_exact_match_idor(self) -> None:
        assert lookup_owasp(["idor"]) == "A01:2021 - Broken Access Control"

    def test_exact_match_csrf(self) -> None:
        assert lookup_owasp(["csrf"]) == "A01:2021 - Broken Access Control"

    def test_case_insensitive(self) -> None:
        assert lookup_owasp(["XSS"]) == "A03:2021 - Injection"

    def test_first_match_wins(self) -> None:
        # Both xss and ssrf are in the list; xss comes first
        result = lookup_owasp(["xss", "ssrf"])
        assert result == "A03:2021 - Injection"

    def test_unknown_returns_none(self) -> None:
        assert lookup_owasp(["unknown vulnerability xyz"]) is None

    def test_empty_list_returns_none(self) -> None:
        assert lookup_owasp([]) is None

    def test_default_credentials(self) -> None:
        assert lookup_owasp(["default credentials"]) == "A05:2021 - Security Misconfiguration"

    def test_deserialization(self) -> None:
        assert "A08" in (lookup_owasp(["deserialization"]) or "")


# ---------------------------------------------------------------------------
# CWE tool
# ---------------------------------------------------------------------------


class TestLookupCwe:
    def test_xss(self) -> None:
        assert lookup_cwe(["xss"]) == "CWE-79"

    def test_sqli(self) -> None:
        assert lookup_cwe(["sql injection"]) == "CWE-89"

    def test_csrf(self) -> None:
        assert lookup_cwe(["csrf"]) == "CWE-352"

    def test_ssrf(self) -> None:
        assert lookup_cwe(["ssrf"]) == "CWE-918"

    def test_path_traversal(self) -> None:
        assert lookup_cwe(["path traversal"]) == "CWE-22"

    def test_command_injection(self) -> None:
        assert lookup_cwe(["command injection"]) == "CWE-78"

    def test_case_insensitive(self) -> None:
        assert lookup_cwe(["CSRF"]) == "CWE-352"

    def test_unknown_returns_none(self) -> None:
        assert lookup_cwe(["something completely unknown"]) is None

    def test_empty_returns_none(self) -> None:
        assert lookup_cwe([]) is None

    def test_open_redirect(self) -> None:
        assert lookup_cwe(["open redirect"]) == "CWE-601"

    def test_cors(self) -> None:
        assert lookup_cwe(["cors"]) == "CWE-942"


# ---------------------------------------------------------------------------
# Severity tool
# ---------------------------------------------------------------------------

ALL_HIGH: dict[str, str] = {
    "exploitability": "High",
    "authentication_required": "None",
    "confidentiality_impact": "High",
    "integrity_impact": "High",
    "availability_impact": "High",
    "user_interaction": "None",
}

ALL_LOW: dict[str, str] = {
    "exploitability": "Low",
    "authentication_required": "High",
    "confidentiality_impact": "None",
    "integrity_impact": "None",
    "availability_impact": "None",
    "user_interaction": "Required",
}


class TestAssessSeverity:
    def test_all_high_factors_returns_critical_or_high(self) -> None:
        result = assess_severity(ALL_HIGH)
        assert result["severity"] in ("Critical", "High")
        assert result["reason"]

    def test_all_low_factors_returns_low_or_informational(self) -> None:
        result = assess_severity(ALL_LOW)
        assert result["severity"] in ("Low", "Informational")

    def test_result_has_required_keys(self) -> None:
        result = assess_severity(ALL_HIGH)
        assert "severity" in result
        assert "reason" in result

    def test_reason_contains_not_cvss_disclaimer(self) -> None:
        result = assess_severity(ALL_HIGH)
        assert "NOT a formal CVSS" in result["reason"]

    def test_missing_factor_raises_value_error(self) -> None:
        incomplete = {k: v for k, v in ALL_HIGH.items() if k != "exploitability"}
        with pytest.raises(ValueError, match="exploitability"):
            assess_severity(incomplete)

    def test_required_factors_set(self) -> None:
        assert len(REQUIRED_FACTORS) == 6

    def test_medium_factors(self) -> None:
        factors = {
            "exploitability": "Medium",
            "authentication_required": "Low",
            "confidentiality_impact": "Low",
            "integrity_impact": "Low",
            "availability_impact": "None",
            "user_interaction": "Required",
        }
        result = assess_severity(factors)
        assert result["severity"] in ("Low", "Medium", "High")
