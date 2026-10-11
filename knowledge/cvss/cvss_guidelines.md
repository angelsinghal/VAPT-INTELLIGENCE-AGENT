# Severity Assessment Guidelines – VAPT Knowledge Base

> **Important**: The VAPT Intelligence Agent uses a simplified evidence-based
> severity assessment inspired by CVSS factors.  It does NOT calculate a formal
> CVSS score or vector.  Always perform a formal CVSS assessment for
> compliance-grade reporting.

---

## Severity Levels

| Level | Description | Typical Score Range (CVSS v3) |
|-------|-------------|-------------------------------|
| **Critical** | Easily exploitable remotely with no authentication; catastrophic confidentiality, integrity, and availability impact | 9.0 – 10.0 |
| **High** | Exploitable with limited preconditions; significant impact on data or system functionality | 7.0 – 8.9 |
| **Medium** | Moderately complex exploitation; partial impact or requires user interaction | 4.0 – 6.9 |
| **Low** | Difficult to exploit; minimal impact; requires significant preconditions | 0.1 – 3.9 |
| **Informational** | No direct security impact; observations, misconfigurations, or best-practice deviations | N/A |

---

## Severity Assessment Factors

### Exploitability

How easily can the vulnerability be exploited?

- **High**: No special skills, tools, or conditions required. Exploitable remotely and reliably.
- **Medium**: Some prerequisites (account, specific network position, specialised tool).
- **Low**: Significant conditions required; unreliable exploitation.

### Authentication Required

What level of authentication is needed to exploit the vulnerability?

- **None**: Exploitable without any authentication (unauthenticated attack).
- **Low**: Requires a valid (low-privilege) account.
- **High**: Requires a privileged (administrator) account.

### Confidentiality Impact

What is the impact on confidentiality of data?

- **High**: Complete or extensive data disclosure.
- **Low**: Partial data disclosure; attacker does not control what data is exposed.
- **None**: No impact on confidentiality.

### Integrity Impact

What is the impact on data integrity?

- **High**: Complete or extensive modification of data.
- **Low**: Limited data modification; attacker does not control the extent.
- **None**: No impact on integrity.

### Availability Impact

What is the impact on system availability?

- **High**: Complete or extensive denial of service; full availability loss.
- **Low**: Reduced performance or intermittent availability.
- **None**: No impact on availability.

### User Interaction

Is user interaction required to exploit the vulnerability?

- **None**: No user interaction needed (e.g., server-side attack, unauthenticated).
- **Required**: Requires a victim to perform an action (e.g., click a link, visit a page).

---

## Common Vulnerability Severity Patterns

| Vulnerability | Typical Severity | Notes |
|---------------|-----------------|-------|
| Reflected XSS | Medium–High | Depends on context; higher if no user interaction required |
| Stored XSS | High | Affects all visitors; broad impact |
| SQL Injection (auth bypass) | Critical | Direct authentication bypass |
| SQL Injection (data exfiltration) | High–Critical | Depends on data sensitivity |
| SSRF (internal access) | High | Cloud metadata access can be critical |
| SSRF (blind) | Medium | Impact depends on reachable endpoints |
| CSRF (state-changing) | Medium–High | Depends on action (password change = High) |
| IDOR (PII access) | High | Data sensitivity elevates severity |
| Path Traversal (read) | High | Arbitrary file read of sensitive data |
| Open Redirect | Low–Medium | Higher with OAUTH token phishing |
| XXE (file read) | High | Arbitrary file read |
| Insecure Deserialisation (RCE) | Critical | Remote code execution |
| Missing Security Headers | Informational–Low | Context-dependent |
| Verbose Error Messages | Low–Medium | May reveal stack traces, file paths |
| Default Credentials | Critical | Trivial authentication bypass |
| Broken Access Control (horizontal) | Medium–High | Access to peer data |
| Broken Access Control (vertical) | High–Critical | Access to admin functions |

---

## Conservative Assessment Guidelines

When evidence is limited or severity factors are incomplete:

1. **Do not assume High or Critical without clear evidence of exploitability and impact.**
2. **Default to the lower of two plausible severity levels.**
3. **Set confidence = "Low" and explain the limitation in reasoning_summary.**
4. **Never fabricate evidence of successful exploitation.**
5. **State explicitly that a formal CVSS assessment should be performed.**

---

## Confidence Levels

| Confidence | Meaning |
|------------|---------|
| **High** | All key factors observed; exploitation confirmed or clearly demonstrated |
| **Medium** | Reasonable evidence; some factors inferred from context or partial testing |
| **Low** | Limited evidence; significant uncertainty; key factors missing; cannot confirm impact |
