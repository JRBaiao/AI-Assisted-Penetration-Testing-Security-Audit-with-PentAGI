# AI-Assisted-Penetration-Testing-Security-Audit-with-PentAGI

> **Hands-on offensive security case study** | Kali Linux · PentAGI · Docker · OWASP Juice Shop · GitHub Pages
>
> **Assessment date:** 3 November 2026  
> **Scope:** Locally hosted OWASP Juice Shop (active testing) and my own portfolio website/repository (non-invasive security review)  
> **Status:** Documented AI-assisted findings; screenshots and the AI agent's outputs are evidence of the recorded tests, not a substitute for independently reproducing and validating every claim.

## Overview

This project explores the practical use of **PentAGI**, an autonomous, AI-assisted penetration-testing platform, to support vulnerability investigation and security assessment. I ran PentAGI in my **Kali Linux** lab environment and used two deliberately different testing approaches:

1. **Active penetration testing** against a locally hosted **OWASP Juice Shop**, an intentionally vulnerable training application.
2. **Non-invasive security audit** of my personal GitHub-hosted portfolio, with emphasis on secure configuration and observability.

The goal was to understand how AI agents can help organize security workflows, execute or suggest tests, collect evidence, describe risk, and propose remediation—while retaining human responsibility for scope, accuracy, and interpretation.

**Portfolio assessed:** [jrbaiao.github.io/Portfolio](https://jrbaiao.github.io/Portfolio/)  
**Platform:** [PentAGI](https://github.com/vxcontrol/pentagi)  
**Training target:** [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

## Table of contents

- [Environment and architecture](#environment-and-architecture)
- [Assessment scope and methodology](#assessment-scope-and-methodology)
- [Findings summary](#findings-summary)
- [Finding 2 — UNION-based SQL injection](#finding-2--union-based-sql-injection)
- [Finding 3 — Client-supplied role / privilege escalation](#finding-3--client-supplied-role--privilege-escalation)
- [Finding 4 — Insecure direct object reference](#finding-4--insecure-direct-object-reference)
- [Portfolio audit — CSP reporting gap (L3)](#portfolio-audit--csp-reporting-gap-l3)
- [Limitations and validation](#limitations-and-validation)
- [Recommendations](#recommendations)
- [Lessons learned](#lessons-learned)
- [Ethics and disclosure](#ethics-and-disclosure)
- [Evidence gallery](#evidence-gallery)

## Environment and architecture

| Component | Purpose | Evidence / notes |
|---|---|---|
| macOS host with Apple Silicon | Host computer | Kali Linux executed as a virtual machine using UTM |
| Kali Linux | Security testing workstation | PentAGI deployed from Kali |
| PentAGI v2.2.0-ce | AI-assisted assessment and orchestration | Version visible in the project screenshots |
| Docker and Docker Compose | Container-based deployment | PentAGI services and local Juice Shop deployment |
| Anthropic model provider | AI integration | Provider selected in the PentAGI interface; model/API secrets are not included |
| OWASP Juice Shop | Intentionally vulnerable test target | Local service at `127.0.0.1:3000` in the screenshots |
| GitHub Pages portfolio | Non-invasive configuration review | Static HTML/CSP inspection |

The screenshots show PentAGI accessible locally at `127.0.0.1:8443`. Localhost ports shown here are lab-specific, not public endpoints.

### PentAGI setup evidence

![PentAGI installation and environment checks](<img width="1271" height="800" alt="PentAGI" src="https://github.com/user-attachments/assets/5d4da703-5ef5-470a-bf38-8424e4df19b1" />
)

*Figure 1 — PentAGI setup checks for Docker, Compose, network connectivity, and required environment configuration.*

> **Reproducibility note:** This is a results-focused case study, not a turnkey deployment guide. Installation settings, sensitive environment variables, secrets, and complete agent prompts are intentionally not published. Refer to the upstream project documentation for installation instructions.

## Assessment scope and methodology

### Scope and guardrails

**In scope — active testing:** a local instance of OWASP Juice Shop under my control, for educational purposes. Activities shown include endpoint requests, controlled SQL-injection testing, registration/role validation, and authorization checks against basket IDs.

**In scope — passive review:** my own personal portfolio/repository. The recorded finding concerns Content Security Policy (CSP) metadata and lack of CSP violation-reporting directives. No exploit attempt against the published portfolio is claimed.

**Out of scope:** third-party systems, other people's applications, real users' accounts, production exploitation, and disclosure of genuine credentials or tokens.

### Workflow

1. Prepare the Kali Linux environment, Docker services, PentAGI, and a locally accessible Juice Shop instance.
2. Define a testing goal and limits for the agent workflow.
3. Review PentAGI's reported findings and the associated terminal output.
4. Associate each finding with its affected component, relevant OWASP category, risk, evidence, and a recommended fix.
5. Run a separate non-invasive review of the portfolio's CSP configuration.
6. Document important evidence and explicitly state which conclusions need manual validation.

The screenshots represent selected observations, not a complete audit trail or proof of comprehensive coverage.

## Findings summary

| ID | Target | PentAGI finding | Reported severity / score | Evidence |
|---|---|---|---|---|
| 2 | Juice Shop | UNION-based SQL injection and database-record exposure | Labeled **Critical** by the agent; **CVSS 3.1: 8.6** | [Screenshot](<img width="1271" height="800" alt="Finding 2" src="https://github.com/user-attachments/assets/468e9540-4742-4f7f-a1d0-39a1b6d90d2f" />
) |
| 3 | Juice Shop | Client-supplied role accepted during registration / potential privilege escalation | **Critical**, **CVSS 3.1: 9.8** | [Screenshot](<img width="1271" height="800" alt="Finding 3" src="https://github.com/user-attachments/assets/3a325344-027c-47e7-92f7-a5b082c640f9" />
) |
| 4 | Juice Shop | IDOR / broken object-level authorization for shopping baskets | **High**, **CVSS 3.1: 7.5** | [Screenshot](<img width="1271" height="800" alt="Finding 4" src="https://github.com/user-attachments/assets/d5a28103-b0cf-4cb9-9f73-668045d91c9e" />
) |
| L3 | Portfolio | CSP reporting and monitoring directives missing | **Low** impact, per agent | [Screenshot](<img width="1271" height="800" alt="Security Audit" src="https://github.com/user-attachments/assets/f6178c32-1d57-4b26-bb88-93ab26009163" />
) |

**Severity interpretation:** All labels and scores above are transcribed from the PentAGI output; they were not independently scored in this case study. Under conventional CVSS v3.1 bands, **8.6 is High**, rather than Critical (9.0–10.0). Severity should be reviewed against the actual environment and impact.

## Finding 2 — UNION-based SQL injection

**Category:** OWASP Top 10 2021 A03 — Injection  
**Affected endpoint (per agent):** `GET /rest/products/search?q=`  
**PentAGI rating:** “Critical” / CVSS v3.1 **8.6** (numeric CVSS band: High)  
**Evidence level:** The screenshot shows the reported finding and terminal output of a UNION-based query returning data associated with application users.

### Description

PentAGI reported a **UNION-based SQL injection** in the product-search parameter. The displayed test constructs a query intended to incorporate values from the application's `Users` table into the search results. The visible report states that database records, including account details and MD5-format password hashes, were exposed.

### Why it matters

An improperly parameterized search endpoint can allow database information to be read outside the intended application workflow. In a real system, credential-related data exposure could significantly expand an attacker's opportunities. The exact impact depends on database permissions, accessible columns, and what information was actually returned.

### Evidence

![PentAGI Finding 2 — SQL Injection](<img width="1271" height="800" alt="Finding 2" src="https://github.com/user-attachments/assets/db00ba8b-bc4b-418d-ad59-5c7ddd424141" />
)

*Figure 2 — PentAGI Finding 2, including the product-search endpoint, UNION-based SQL-injection test, and returned output.*

### Recommended remediation

- Use **parameterized SQL queries** / prepared statements instead of constructing SQL from untrusted input.
- Restrict application database privileges to required operations only.
- Avoid placing sensitive account information in tables or queries accessible to unrelated application functions.
- Use a modern, purpose-built password hashing algorithm such as Argon2id, scrypt, or bcrypt, with suitable configuration; do not use unsalted MD5 for password storage.
- Add regression tests that confirm malicious query strings cannot change the query's structure.

### Validation notes

The screenshot supports that the tool made a test request and recorded user-related output. A complete manual reproduction, independent row-by-row data verification, and an end-to-end remediation retest are **not included** in the provided evidence.

## Finding 3 — Client-supplied role / privilege escalation

**Category:** OWASP Top 10 2021 A01 — Broken Access Control (and relevant insecure-design considerations)  
**Affected endpoint (per agent):** `POST /api/Users`  
**PentAGI rating:** **Critical** / CVSS v3.1 **9.8**  
**Evidence level:** The screenshot records a registration workflow, output concerning the account role, and the agent's assessment of privilege escalation.

### Description

PentAGI tested whether a registration request could include a privileged `role` value provided by the client. Its report states that a role supplied during account creation was retained and that a subsequent authentication response included an administrative role claim.

### Why it matters

If a server trusts a registration request's client-controlled role field, a new user may be able to assign themselves privileges they should not have. This is a failure of **server-side authorization and trusted role assignment**.

### Evidence

![PentAGI Finding 3 — Privilege Escalation](<img width="1271" height="800" alt="Finding 3" src="https://github.com/user-attachments/assets/cf96afa2-7739-4728-be58-1cb810583e24" />
)

*Figure 3 — PentAGI Finding 3 showing account-registration testing, role-related terminal output, and the agent's severity assessment.*

### Recommended remediation

- Ignore or reject client-supplied administrative role attributes on public sign-up endpoints.
- Set default roles **server-side** from a fixed allowlist.
- Require independent authorization checks before any administrative action.
- Prevent mass assignment of privileged user fields.
- Add tests for registration, login, JWT claim issuance, and access to protected administrative endpoints.

### Validation notes

The agent reported administrative-role issuance, but the displayed terminal includes additional outputs whose authorization implications are not fully established by this single screenshot. **Confirming actual access to an administrator-only operation would be necessary** to independently substantiate full privilege escalation. The case study therefore presents it as a PentAGI-reported finding rather than a separately demonstrated administrator takeover.

## Finding 4 — Insecure direct object reference

**Category:** OWASP Top 10 2021 A01 — Broken Access Control  
**Affected endpoint (per agent):** `GET /rest/basket/<id>`  
**PentAGI rating:** **High** / CVSS v3.1 **7.5**  
**Evidence level:** The screenshot shows multiple HTTP 200 responses for basket IDs tested with a low-privilege account token.

### Description

PentAGI assessed whether a logged-in user could retrieve basket data by substituting other basket IDs in the request URL. The reported results show HTTP 200 responses and basket objects for IDs associated with other users.

### Why it matters

An **IDOR / broken object-level authorization (BOLA)** issue occurs when an application accepts an object identifier without verifying that the requester is allowed to access that specific object. Even when a user is authenticated, access should still be limited to their own records unless explicitly authorized otherwise.

### Evidence

![PentAGI Finding 4 — IDOR](<img width="1271" height="800" alt="Finding 4" src="https://github.com/user-attachments/assets/bf700c3d-941a-4c9c-9ff2-03e86767f95f" />
)

*Figure 4 — PentAGI Finding 4 showing shopping-basket requests against other IDs and returned HTTP 200 responses.*

### Recommended remediation

- Verify basket ownership **on every server-side request**.
- Scope database queries to the authenticated principal where practical.
- Return an appropriate denial response for unauthorized objects, without revealing their contents.
- Do not treat hard-to-guess IDs as an authorization mechanism.
- Add automated cross-account access tests using at least two distinct non-administrator accounts.

### Validation notes

The visible screenshot includes the agent's account-ownership interpretation and successful responses. Confirming the expected ownership of each tested basket independently would strengthen the evidence.

## Portfolio audit — CSP reporting gap (L3)

**Target:** Personal GitHub Pages portfolio  
**Review type:** Non-invasive configuration and code inspection  
**Finding:** CSP has no `report-uri` or `report-to` reporting directive  
**PentAGI impact assessment:** **Low**; detection/observability gap, not an established exploitation path.

### Description

PentAGI inspected HTML files and identified `Content-Security-Policy` declarations in HTML `<meta>` tags, without a violation-reporting destination. Its finding was labeled **L3: CSP has no reporting / monitoring**.

CSP helps restrict which content a browser is permitted to load. CSP violation reporting can provide operational visibility when a browser encounters blocked or reportable behavior; however, reporting support depends on browser behavior and how the policy is delivered. In particular, **`report-uri` and `report-to` are not supported as reporting mechanisms when the CSP is delivered via an HTML `meta` element**. Adding those directives to an existing meta tag is therefore not a functional fix.

### Evidence

![PentAGI portfolio security audit — CSP L3](<img width="1271" height="800" alt="Security Audit" src="https://github.com/user-attachments/assets/5337bef5-d4b2-41e8-af5b-c2c0e8f1dd15" />
)

*Figure 5 — PentAGI portfolio audit and inspection of CSP meta declarations in repository HTML files.*

### Recommended remediation

- Decide whether CSP violation reporting is operationally useful for the portfolio before adding additional infrastructure.
- If reporting is required, configure CSP through an **HTTP response header**, together with a reporting endpoint and supported directives, rather than relying on a meta-tag CSP for reporting.
- On GitHub Pages, check hosting limitations for custom response headers; using an intermediary/CDN or alternate hosting setup may be necessary.
- Test browser behavior and reporting delivery in supported browsers, and avoid collecting unnecessary personal data in reports.
- Continue assessing CSP restrictions separately from reporting: **missing reporting does not imply that CSP enforcement is absent**.

### Validation notes

The screenshot documents a repository-side inspection of HTML meta tags, not a verified measurement of live HTTP response headers across every page. The actual deployed headers and reporting behavior should be checked before asserting complete coverage of the live site's CSP configuration.

## Limitations and validation

This repository documents a **selected subset of PentAGI's findings**. It does not represent a comprehensive security audit, a verified professional penetration-testing engagement, or a certification of the portfolio's security.

Key limitations:

- The publicly included evidence consists primarily of **screenshots of the agent's finding descriptions and terminal logs**.
- Full agent prompts, raw request/response transcripts, timestamps for each step, and independent retest logs are not included.
- PentAGI's confidence labels and CVSS ratings are **tool-generated assessments**, not automatically equivalent to independent verification.
- Findings 2, 3, and 4 pertain to an **intentionally vulnerable lab application**, not a real production target.
- The portfolio security check is a **limited non-invasive review**; it does not establish the existence or absence of other vulnerabilities.
- No patch application or successful remediation retest is claimed.

### Suggested future validation work

For a future update, I would include sanitized HTTP request/response pairs, explicit authentication-context details, independently reproduced outcomes, remediation changes, and post-fix test results. This would make the assessment more reproducible and demonstrate both offensive and defensive learning.

## Recommendations

| Priority | Area | Recommended action |
|---|---|---|
| High | SQL injection | Replace dynamic SQL construction with parameterized statements and retest |
| High | Account registration | Enforce role assignment and privilege checks on the server |
| High | Basket access | Implement object-ownership checks and cross-user authorization tests |
| Low | Portfolio CSP monitoring | Evaluate header-based CSP reporting if useful and supported by hosting |
| Ongoing | AI-assisted workflows | Independently confirm notable claims and preserve reproducible, sanitized evidence |

These priorities reflect what should be addressed **in a real application with comparable weaknesses**; OWASP Juice Shop is intentionally vulnerable for education, so fixing its built-in challenges is not the point of the lab.

## Lessons learned

1. **AI is an accelerator, not an authority.** PentAGI can help orchestrate tests and structure outputs, but a security analyst must still check assumptions and evidence.
2. **Broken authorization can be more consequential than unexpected input alone.** Role assignment and object ownership require explicit server-side enforcement.
3. **Evidence quality matters.** A screenshot is a useful starting point; a reproducible test with a clear expected-versus-actual result is stronger.
4. **Risk classification requires interpretation.** Reported labels and CVSS scores can disagree; context and independent scoring matter.
5. **Detection and prevention are different.** CSP reporting affects visibility; it is not by itself proof of an exploitable weakness.
6. **Different targets require different engagement rules.** Active exploitation is appropriate only in explicitly authorized lab or assessment scopes; passive review should remain within its stated limits.

## Ethics and disclosure

All active security testing covered here targeted my **locally hosted, intentionally vulnerable OWASP Juice Shop lab**. The separate review of my own portfolio was intended to be **non-invasive**. This project is presented for education, portfolio development, and responsible security research.

Do not reuse these techniques against systems without explicit authorization. No real credentials, API keys, or production secrets should be stored in this repository. Screenshots should be checked and redacted before public publication to remove sensitive values, access tokens, or personal information as appropriate.

## Evidence gallery

| Screenshot | What it demonstrates |
|---|---|
| [PentAGI setup](<img width="1271" height="800" alt="PentAGI" src="https://github.com/user-attachments/assets/0cee7d2d-04b9-4afc-af95-cc48e7c9c971" />
) | Environment preparation and platform checks |
| [Finding 2](<img width="1271" height="800" alt="PentAGI" src="https://github.com/user-attachments/assets/98236b75-23a8-472f-b501-b5e33a24ed46" />
) | SQL-injection report and related test output |
| [Finding 3](<img width="1271" height="800" alt="Finding 3" src="https://github.com/user-attachments/assets/660146ca-1981-4001-8da0-89a85e6afef5" />
) | Registration-role / privilege-escalation report |
| [Finding 4](<img width="1271" height="800" alt="Finding 4" src="https://github.com/user-attachments/assets/7c76e569-acf4-4ab8-9f53-89c6f61dbd0b" />
) | Cross-basket request / IDOR report |
| [Portfolio audit](<img width="1271" height="800" alt="Security Audit" src="https://github.com/user-attachments/assets/40dee012-f308-46cd-bc12-53435024b7e4" />
) | L3 missing CSP reporting assessment |
