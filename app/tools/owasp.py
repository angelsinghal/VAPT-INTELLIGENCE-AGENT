"""Deterministic OWASP Top 10 (2021) mapping tool.

The mapping is keyword-based and intentionally conservative: if the finding
does not match any known keyword, ``None`` is returned rather than guessing.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Mapping: lowercase keyword -> OWASP Top 10 2021 category
# ---------------------------------------------------------------------------
OWASP_MAPPING: dict[str, str] = {
    # A01: Broken Access Control
    "broken access control": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "insecure direct object reference": "A01:2021 - Broken Access Control",
    "privilege escalation": "A01:2021 - Broken Access Control",
    "forced browsing": "A01:2021 - Broken Access Control",
    "path traversal": "A01:2021 - Broken Access Control",
    "directory traversal": "A01:2021 - Broken Access Control",
    "unauthorized access": "A01:2021 - Broken Access Control",
    "missing function level access control": "A01:2021 - Broken Access Control",
    "csrf": "A01:2021 - Broken Access Control",
    "cross-site request forgery": "A01:2021 - Broken Access Control",
    "cross site request forgery": "A01:2021 - Broken Access Control",
    # A02: Cryptographic Failures
    "cryptographic failure": "A02:2021 - Cryptographic Failures",
    "sensitive data exposure": "A02:2021 - Cryptographic Failures",
    "weak encryption": "A02:2021 - Cryptographic Failures",
    "insecure transmission": "A02:2021 - Cryptographic Failures",
    "cleartext": "A02:2021 - Cryptographic Failures",
    "plaintext password": "A02:2021 - Cryptographic Failures",
    "weak cipher": "A02:2021 - Cryptographic Failures",
    "md5": "A02:2021 - Cryptographic Failures",
    "sha1": "A02:2021 - Cryptographic Failures",
    "hardcoded secret": "A02:2021 - Cryptographic Failures",
    # A03: Injection
    "injection": "A03:2021 - Injection",
    "sql injection": "A03:2021 - Injection",
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "cross-site scripting": "A03:2021 - Injection",
    "cross site scripting": "A03:2021 - Injection",
    "reflected xss": "A03:2021 - Injection",
    "stored xss": "A03:2021 - Injection",
    "dom xss": "A03:2021 - Injection",
    "command injection": "A03:2021 - Injection",
    "os injection": "A03:2021 - Injection",
    "ldap injection": "A03:2021 - Injection",
    "xpath injection": "A03:2021 - Injection",
    "html injection": "A03:2021 - Injection",
    "template injection": "A03:2021 - Injection",
    "ssti": "A03:2021 - Injection",
    "server-side template injection": "A03:2021 - Injection",
    "code injection": "A03:2021 - Injection",
    "xml injection": "A03:2021 - Injection",
    "crlf injection": "A03:2021 - Injection",
    # A04: Insecure Design
    "insecure design": "A04:2021 - Insecure Design",
    "business logic": "A04:2021 - Insecure Design",
    "logic flaw": "A04:2021 - Insecure Design",
    "race condition": "A04:2021 - Insecure Design",
    # A05: Security Misconfiguration
    "security misconfiguration": "A05:2021 - Security Misconfiguration",
    "misconfiguration": "A05:2021 - Security Misconfiguration",
    "default credentials": "A05:2021 - Security Misconfiguration",
    "default password": "A05:2021 - Security Misconfiguration",
    "verbose error": "A05:2021 - Security Misconfiguration",
    "debug enabled": "A05:2021 - Security Misconfiguration",
    "directory listing": "A05:2021 - Security Misconfiguration",
    "cors misconfiguration": "A05:2021 - Security Misconfiguration",
    "cors": "A05:2021 - Security Misconfiguration",
    "open redirect": "A05:2021 - Security Misconfiguration",
    "xxe": "A05:2021 - Security Misconfiguration",
    "xml external entity": "A05:2021 - Security Misconfiguration",
    # A06: Vulnerable and Outdated Components
    "vulnerable component": "A06:2021 - Vulnerable and Outdated Components",
    "outdated component": "A06:2021 - Vulnerable and Outdated Components",
    "known vulnerability": "A06:2021 - Vulnerable and Outdated Components",
    "cve": "A06:2021 - Vulnerable and Outdated Components",
    "outdated library": "A06:2021 - Vulnerable and Outdated Components",
    "third party library": "A06:2021 - Vulnerable and Outdated Components",
    # A07: Identification and Authentication Failures
    "authentication failure": "A07:2021 - Identification and Authentication Failures",
    "broken authentication": "A07:2021 - Identification and Authentication Failures",
    "weak password": "A07:2021 - Identification and Authentication Failures",
    "credential stuffing": "A07:2021 - Identification and Authentication Failures",
    "session fixation": "A07:2021 - Identification and Authentication Failures",
    "session hijacking": "A07:2021 - Identification and Authentication Failures",
    "insecure cookie": "A07:2021 - Identification and Authentication Failures",
    "missing secure flag": "A07:2021 - Identification and Authentication Failures",
    "brute force": "A07:2021 - Identification and Authentication Failures",
    "account lockout": "A07:2021 - Identification and Authentication Failures",
    "password policy": "A07:2021 - Identification and Authentication Failures",
    "missing httponly": "A07:2021 - Identification and Authentication Failures",
    # A08: Software and Data Integrity Failures
    "software integrity": "A08:2021 - Software and Data Integrity Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "insecure deserialization": "A08:2021 - Software and Data Integrity Failures",
    "supply chain": "A08:2021 - Software and Data Integrity Failures",
    # A09: Security Logging and Monitoring Failures
    "logging failure": "A09:2021 - Security Logging and Monitoring Failures",
    "insufficient logging": "A09:2021 - Security Logging and Monitoring Failures",
    "missing logging": "A09:2021 - Security Logging and Monitoring Failures",
    "monitoring failure": "A09:2021 - Security Logging and Monitoring Failures",
    # A10: Server-Side Request Forgery
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "server-side request forgery": "A10:2021 - Server-Side Request Forgery",
    "server side request forgery": "A10:2021 - Server-Side Request Forgery",
}


def lookup_owasp(keywords: list[str]) -> str | None:
    """Return the first OWASP Top 10 (2021) mapping for any of the keywords.

    Comparison is case-insensitive.  Returns ``None`` if no confident match
    is found — the caller should treat ``None`` as "unknown" rather than
    fabricating a category.
    """
    for kw in keywords:
        match = OWASP_MAPPING.get(kw.lower().strip())
        if match:
            return match
    return None
