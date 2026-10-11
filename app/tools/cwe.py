"""Deterministic CWE mapping tool.

Provides keyword -> CWE ID mappings based on common security weakness names.
Returns ``None`` when no confident mapping can be made.
"""

from __future__ import annotations

CWE_MAPPING: dict[str, str] = {
    # Injection
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "cross site scripting": "CWE-79",
    "reflected xss": "CWE-79",
    "stored xss": "CWE-79",
    "dom xss": "CWE-79",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "code injection": "CWE-94",
    "template injection": "CWE-94",
    "ssti": "CWE-94",
    "server-side template injection": "CWE-94",
    "ldap injection": "CWE-90",
    "xml injection": "CWE-91",
    "xpath injection": "CWE-643",
    "html injection": "CWE-80",
    "crlf injection": "CWE-93",
    "http response splitting": "CWE-113",
    # Access Control
    "idor": "CWE-639",
    "insecure direct object reference": "CWE-639",
    "broken access control": "CWE-284",
    "missing function level access control": "CWE-285",
    "privilege escalation": "CWE-269",
    "unauthorized access": "CWE-284",
    "forced browsing": "CWE-425",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    # CSRF
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "cross site request forgery": "CWE-352",
    # SSRF
    "ssrf": "CWE-918",
    "server-side request forgery": "CWE-918",
    "server side request forgery": "CWE-918",
    # Authentication
    "broken authentication": "CWE-287",
    "authentication failure": "CWE-287",
    "weak password": "CWE-521",
    "credential stuffing": "CWE-307",
    "brute force": "CWE-307",
    "account lockout": "CWE-307",
    "session fixation": "CWE-384",
    "session hijacking": "CWE-613",
    "insecure cookie": "CWE-614",
    "missing secure flag": "CWE-614",
    "missing httponly": "CWE-1004",
    "missing httponly flag": "CWE-1004",
    # Cryptography
    "weak encryption": "CWE-326",
    "weak cipher": "CWE-327",
    "cleartext": "CWE-319",
    "plaintext password": "CWE-312",
    "insecure transmission": "CWE-319",
    "md5": "CWE-327",
    "sha1": "CWE-327",
    "cryptographic failure": "CWE-310",
    "hardcoded secret": "CWE-798",
    # XXE
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    # Deserialization
    "deserialization": "CWE-502",
    "insecure deserialization": "CWE-502",
    # File Inclusion
    "lfi": "CWE-73",
    "local file inclusion": "CWE-73",
    "rfi": "CWE-98",
    "remote file inclusion": "CWE-98",
    # Configuration / Information Disclosure
    "security misconfiguration": "CWE-16",
    "default credentials": "CWE-1392",
    "default password": "CWE-1392",
    "directory listing": "CWE-548",
    "verbose error": "CWE-209",
    "information disclosure": "CWE-200",
    "sensitive data exposure": "CWE-200",
    "cors misconfiguration": "CWE-942",
    "cors": "CWE-942",
    "open redirect": "CWE-601",
    # Business Logic
    "business logic": "CWE-840",
    "race condition": "CWE-362",
    "logic flaw": "CWE-840",
    # Logging
    "insufficient logging": "CWE-778",
    "missing logging": "CWE-778",
    # Supply chain
    "supply chain": "CWE-1035",
}


def lookup_cwe(keywords: list[str]) -> str | None:
    """Return the first CWE ID that matches any of the supplied keywords.

    Comparison is case-insensitive.  Returns ``None`` if no confident mapping
    is found — the caller should surface this as ``null`` rather than
    fabricating a CWE ID.
    """
    for kw in keywords:
        match = CWE_MAPPING.get(kw.lower().strip())
        if match:
            return match
    return None
