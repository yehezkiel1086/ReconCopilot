# Security Policy

The ReconCopilot project team takes security vulnerabilities seriously. We appreciate the efforts of security researchers and practitioners in responsibly identifying and reporting potential security flaws in ReconCopilot itself.

---

## Supported Versions

Security updates and patches are provided for the following versions:

| Version | Supported          |
| :---    | :---               |
| `0.1.x` | :white_check_mark: |
| `< 0.1` | :x:                |

We strongly recommend always running the latest released version of ReconCopilot.

---

## Reporting a Vulnerability

If you discover a security vulnerability in ReconCopilot, please report it via private disclosure. **Do not create public GitHub issues or discuss potential vulnerabilities publicly until they have been addressed.**

### How to Report

1. **GitHub Security Advisory (Preferred)**:
   - Navigate to the [Security Advisories](https://github.com/your-org/ReconCopilot/security/advisories) tab of the repository.
   - Click **"Report a vulnerability"** to submit a private draft advisory.

2. **Email Disclosure**:
   - If GitHub Security Advisories are unavailable, email: `security@reconcopilot.local` (or the project maintainer's listed security contact).
   - Please use PGP encryption if transmitting sensitive proof-of-concept material.

### What to Include in Your Report

To help us triage and investigate efficiently, please provide:
- A descriptive summary of the issue.
- The version of ReconCopilot tested (e.g. output of `reconcopilot --version`).
- Operating system and Python environment details.
- Clear step-by-step reproduction instructions or a minimal reproducible script.
- Potential impact or security implications (e.g. scope evasion, local privilege escalation, arbitrary command execution, sensitive data leakage).

---

## Vulnerability Handling Process

1. **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
2. **Assessment**: The maintainers will investigate, reproduce the issue, and confirm whether it is a valid vulnerability within **5 business days**.
3. **Remediation**: We will develop and verify a security patch in a private repository branch.
4. **Coordinated Disclosure**: Once a patch is tested and released, we will publish a security advisory giving appropriate credit to the reporter (unless you prefer anonymity).

---

## Scope & Out-of-Scope Items

### In Scope
- Vulnerabilities within ReconCopilot Python source code (`reconcopilot/*`).
- Scope bypasses or allowlist evasion vulnerabilities in `ScopeChecker`.
- Insecure local file permissions or credential disclosure vulnerabilities.
- Injection flaws in report generation, CLI parsing, or database interactions.

### Out of Scope
- Vulnerabilities in third-party external CLI tools wrapped by ReconCopilot (e.g., `subfinder`, `httpx`, `nuclei`, `nmap`). Please report those directly to upstream project maintainers.
- Social engineering, phishing, or physical attacks against maintainers.
- Denial-of-service issues caused by scanning untrusted networks without rate limiting.

---

## Safe Harbor

We consider security research conducted in good faith under this policy to be authorized. We will not pursue legal action against researchers who:
- Give us reasonable time to remediate before disclosing details publicly.
- Do not exploit vulnerabilities to access or modify data beyond what is necessary for a demonstration.
- Respect user privacy and do not disrupt system operations.
