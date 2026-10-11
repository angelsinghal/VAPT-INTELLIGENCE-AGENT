# OWASP Top 10 (2021) – Security Knowledge Base

## A01:2021 – Broken Access Control

**Definition**: Restrictions on what authenticated users can do are not properly enforced. Attackers can exploit these flaws to access unauthorised functionality or data.

**Common weaknesses**:
- IDOR (Insecure Direct Object Reference) – accessing resources by modifying identifiers
- Missing function-level access control
- CSRF (Cross-Site Request Forgery) – forging requests on behalf of authenticated users
- Forced browsing to unauthenticated pages
- Privilege escalation (horizontal and vertical)
- Directory traversal / path traversal attacks

**Impact**: Unauthorised data access, data modification, account takeover, admin actions by unprivileged users.

**Remediation**:
- Implement server-side access control on every request
- Deny by default; allow only what is explicitly permitted
- Log and alert on access control failures
- Validate object ownership before returning data
- Use anti-CSRF tokens for state-changing requests

---

## A02:2021 – Cryptographic Failures

**Definition**: Failures related to cryptography that expose sensitive data.

**Common weaknesses**:
- Transmitting data in cleartext (HTTP, FTP, SMTP)
- Using deprecated or weak cryptographic algorithms (MD5, SHA-1, DES, RC4)
- Hardcoded or weak encryption keys
- Insufficient randomness used in key generation
- Storing passwords without hashing, or using weak hashing (MD5, unsalted SHA-1)
- Missing HTTPS or certificate validation

**Impact**: Exposure of passwords, credit cards, PII, medical records. Session hijacking over insecure channels.

**Remediation**:
- Enforce HTTPS for all data in transit (HSTS headers)
- Use modern algorithms: AES-256, RSA-2048+, SHA-256+, bcrypt/scrypt/Argon2 for passwords
- Never hard-code secrets; use key management solutions
- Disable TLS 1.0/1.1; enforce TLS 1.2+

---

## A03:2021 – Injection

**Definition**: Untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute unintended commands.

**Common injection types**:
- **SQL Injection (SQLi)** – CWE-89: user input concatenated into SQL queries
- **Cross-Site Scripting (XSS)** – CWE-79: user input reflected in HTML without encoding
  - Reflected XSS: input immediately reflected in response
  - Stored XSS: input persisted and reflected to other users
  - DOM XSS: JavaScript reads from an attacker-controllable source
- **Command Injection** – CWE-78: user input passed to OS shell commands
- **Server-Side Template Injection (SSTI)** – CWE-94: template engines process user input
- **LDAP Injection** – CWE-90
- **XML Injection / XPath Injection** – CWE-91, CWE-643
- **CRLF Injection** – CWE-93: inserting carriage return/linefeed into headers

**Impact**: Data exfiltration, authentication bypass, remote code execution, full system compromise.

**Remediation**:
- Use parameterised queries / prepared statements for all database queries
- Apply strict output encoding for HTML, JavaScript, CSS contexts (XSS)
- Validate and whitelist input; reject unexpected characters
- Use sandboxed template engines; avoid user-controlled template strings
- Apply Content Security Policy (CSP) headers

---

## A04:2021 – Insecure Design

**Definition**: Missing or ineffective control design. Security is not considered during the design phase.

**Common weaknesses**:
- Missing threat modelling
- Business logic flaws (e.g., bypassing payment, abusing discount codes)
- Race conditions exploitable to bypass limits
- Missing rate limiting on sensitive operations

**Remediation**:
- Integrate threat modelling in design phase
- Apply defence in depth
- Implement business rule validation on the server side

---

## A05:2021 – Security Misconfiguration

**Definition**: Insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, verbose error messages.

**Common weaknesses**:
- Default credentials not changed
- Verbose error messages exposing stack traces or internal paths
- Directory listing enabled
- XML External Entity (XXE) processing enabled
- CORS misconfigured to allow arbitrary origins
- Open redirect vulnerabilities
- Unnecessary features/services enabled (debug mode, admin consoles)
- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)

**Impact**: Unauthorised access, sensitive information disclosure, code execution (via XXE).

**Remediation**:
- Disable unnecessary features and services
- Change all default credentials immediately
- Implement secure defaults and hardening guides
- Regularly audit configurations
- Use restrictive CORS policies

---

## A06:2021 – Vulnerable and Outdated Components

**Definition**: Using components (libraries, frameworks, OS) with known vulnerabilities.

**Impact**: Full range of vulnerabilities depending on the component.

**Remediation**:
- Maintain a software bill of materials (SBOM)
- Monitor CVE databases and update promptly
- Remove unused dependencies

---

## A07:2021 – Identification and Authentication Failures

**Definition**: Weaknesses in authentication and session management.

**Common weaknesses**:
- Missing or weak multi-factor authentication
- Weak or default passwords permitted
- No protection against brute force or credential stuffing
- Session tokens exposed in URLs
- Session fixation
- Missing Secure/HttpOnly flags on session cookies
- Sessions not invalidated on logout

**Remediation**:
- Enforce MFA
- Implement account lockout or CAPTCHA after failed attempts
- Use secure, randomly generated session tokens
- Set Secure and HttpOnly flags on all session cookies
- Invalidate sessions on logout and password change

---

## A08:2021 – Software and Data Integrity Failures

**Definition**: Code and infrastructure that does not protect against integrity violations, insecure deserialisation.

**Common weaknesses**:
- Insecure deserialisation of untrusted data (CWE-502)
- Auto-update without signature verification
- Untrusted CDN or plugins

**Remediation**:
- Never deserialise data from untrusted sources without validation
- Use digital signatures for software packages and updates
- Use integrity checks (SRI) for CDN resources

---

## A09:2021 – Security Logging and Monitoring Failures

**Definition**: Insufficient logging, monitoring, and incident response.

**Remediation**:
- Log all authentication events, access control failures, and input validation failures
- Ensure logs cannot be cleared by attackers
- Implement alerting on suspicious patterns
- Retain logs for sufficient time

---

## A10:2021 – Server-Side Request Forgery (SSRF)

**Definition**: The application fetches a remote resource based on user-supplied input without validating the URL, allowing attackers to make the server request internal resources.

**Impact**: Access to internal services, cloud metadata endpoints (e.g., AWS IMDSv1), port scanning internal networks, potential RCE.

**Remediation**:
- Validate and whitelist allowed URL schemes and destinations
- Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)
- Do not forward raw error responses from fetched URLs to clients
- Use network-level controls to limit server egress
