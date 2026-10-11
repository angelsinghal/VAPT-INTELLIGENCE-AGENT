# Common CWE Reference – VAPT Knowledge Base

This document provides concise definitions and remediation guidance for the
most commonly encountered CWEs in web and API penetration testing.

---

## CWE-79 – Cross-Site Scripting (XSS)

**Description**: The application does not neutralise user-controllable input before including it in output sent to a web browser, enabling script injection.

**Variants**: Reflected (non-persistent), Stored (persistent), DOM-based.

**Impact**: Session hijacking, credential theft, defacement, redirection to malicious sites.

**Remediation**:
- Output encode all user data (HTML entity encoding, JavaScript encoding, URL encoding based on context)
- Apply Content Security Policy (CSP) headers
- Use framework auto-escaping features
- Never insert raw user input into innerHTML, document.write(), or eval()

---

## CWE-89 – SQL Injection

**Description**: User-controlled input is incorporated into SQL queries without sanitisation, allowing modification of query logic.

**Impact**: Authentication bypass, data exfiltration, data modification, possible remote code execution via stored procedures.

**Remediation**:
- Use parameterised queries (prepared statements) exclusively
- Apply stored procedures with parameterised input
- Implement ORM with safe query building
- Apply least privilege to database accounts

---

## CWE-78 – OS Command Injection

**Description**: User input is passed to an operating system shell without proper sanitisation.

**Impact**: Remote code execution, full system compromise.

**Remediation**:
- Avoid shell calls entirely; use language-native libraries
- If shell is unavoidable, use strict allowlisting of input values
- Apply sandboxing

---

## CWE-94 – Code Injection / Template Injection (SSTI)

**Description**: User input is evaluated as code by an interpreter or template engine.

**Impact**: Remote code execution, information disclosure.

**Remediation**:
- Never pass user input to eval(), exec(), or template engine render functions
- Use logic-less templates or sandbox template engines
- Validate and whitelist all user-supplied template variables

---

## CWE-352 – Cross-Site Request Forgery (CSRF)

**Description**: The application does not verify that a state-changing request was intentionally sent by the authenticated user.

**Impact**: Unwanted actions (fund transfers, password changes, account deletion) executed on behalf of victims.

**Remediation**:
- Implement synchroniser token pattern (CSRF tokens) on all state-changing requests
- Use SameSite=Strict or SameSite=Lax cookie attribute
- Verify Origin/Referer headers on sensitive operations

---

## CWE-918 – Server-Side Request Forgery (SSRF)

**Description**: The server fetches remote content based on attacker-controlled URLs.

**Impact**: Internal network scanning, cloud metadata access (AWS IMDSv1), potential RCE.

**Remediation**:
- Whitelist allowed domains/IP ranges
- Block private and loopback IP ranges
- Disable URL redirects for server-side fetches

---

## CWE-284 / CWE-639 – Broken Access Control / IDOR

**CWE-284**: Improper access control – actions or data available without authorisation.
**CWE-639**: Authorisation bypass through user-controlled keys (IDOR).

**Impact**: Horizontal privilege escalation, data exposure.

**Remediation**:
- Implement server-side authorisation checks on every resource request
- Use indirect object references (map user-visible IDs to internal IDs server-side)
- Log and alert on authorisation failures

---

## CWE-287 – Improper Authentication

**Description**: The system does not properly verify that a user is who they claim to be.

**Impact**: Unauthorised access to accounts or systems.

**Remediation**:
- Use established authentication frameworks
- Enforce MFA
- Invalidate sessions properly on logout

---

## CWE-307 – Improper Restriction of Excessive Authentication Attempts

**Description**: No rate limiting or lockout on login/authentication endpoints.

**Impact**: Brute force, credential stuffing.

**Remediation**:
- Implement account lockout after N failed attempts
- Apply CAPTCHA or MFA
- Throttle login endpoints

---

## CWE-22 – Path Traversal

**Description**: The application allows user input to navigate outside intended directories using sequences like `../`.

**Impact**: Arbitrary file read, potentially write or code execution.

**Remediation**:
- Resolve canonical paths and verify they reside within the allowed base directory
- Reject input containing `..` sequences
- Use OS-level sandboxing (chroot, containers)

---

## CWE-611 – XML External Entity (XXE) Injection

**Description**: XML parsers process external entity references in XML input supplied by attackers.

**Impact**: Arbitrary file read, SSRF, denial of service.

**Remediation**:
- Disable external entity processing in XML parsers
- Use JSON where XML is not required
- Validate and restrict XML input schema

---

## CWE-502 – Deserialization of Untrusted Data

**Description**: The application deserialises data from untrusted sources without validation.

**Impact**: Remote code execution, denial of service.

**Remediation**:
- Never deserialise untrusted data
- Use safe serialisation formats (JSON with schema validation)
- Implement integrity checks (signatures) on serialised data

---

## CWE-319 – Cleartext Transmission of Sensitive Information

**Description**: Sensitive data is transmitted without encryption.

**Impact**: Credential and session token interception.

**Remediation**:
- Enforce HTTPS/TLS for all communications
- Implement HSTS

---

## CWE-200 – Exposure of Sensitive Information

**Description**: The application exposes sensitive information to unauthorised actors.

**Impact**: Credential leakage, PII exposure, system information disclosure.

**Remediation**:
- Suppress verbose error messages in production
- Restrict access to debug endpoints and logs
- Apply least privilege to data returned by APIs

---

## CWE-601 – Open Redirect

**Description**: The application redirects to a URL supplied in user-controlled input without validation.

**Impact**: Phishing, credential harvesting via redirect to attacker site.

**Remediation**:
- Validate redirect targets against an allowlist of trusted domains
- Avoid using user-supplied input directly in redirect URLs
- Warn users when redirecting outside the application domain

---

## CWE-614 / CWE-1004 – Insecure Cookie Attributes

**CWE-614**: Cookie without Secure flag – transmitted over non-HTTPS.
**CWE-1004**: Cookie without HttpOnly flag – accessible to JavaScript.

**Remediation**:
- Set Secure flag on all session cookies
- Set HttpOnly flag to prevent JavaScript access
- Apply SameSite attribute

---

## CWE-942 – Overly Permissive CORS Policy

**Description**: CORS headers allow arbitrary origins to make credentialed cross-origin requests.

**Impact**: Cross-origin data theft, CSRF via CORS.

**Remediation**:
- Never reflect the Origin request header as the Access-Control-Allow-Origin value
- Restrict Access-Control-Allow-Origin to a known allowlist
- Do not combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true
