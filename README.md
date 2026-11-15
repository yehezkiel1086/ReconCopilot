# ReconCopilot

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/Tests-Pytest%20Passing-success.svg)](tests/)

**ReconCopilot** is an AI-assisted reconnaissance and security workflow assistant designed for penetration testers, security engineers, and authorized bug bounty researchers. It streamlines the entire assessment lifecycle — from target scope definition and asset discovery to risk triage, manual finding tracking, and executive report drafting — while strictly enforcing authorization boundaries at every step.

---

> [!WARNING]
> ## Authorized Use Only
>
> **ReconCopilot is strictly designed and intended for authorized security assessments, penetration testing engagements, and bug bounty programs where you have explicit, prior written permission from the asset owner.**
>
> Testing, scanning, or probing targets without proper authorization is illegal in many jurisdictions under laws such as the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent international cybersecurity statutes.
>
> **Scope enforcement is a safety guardrail, not a legal shield**: ReconCopilot includes built-in domain wildcard and CIDR scope validation to help operators avoid accidental out-of-scope queries. However, automated scope enforcement is **not a substitute for your own legal, ethical, and contractual diligence**. You are solely responsible for ensuring that all targets, scan modes, and activities comply with your engagement terms and applicable laws.

---

## Key Features

- 🎯 **Strict Scope Allowlist Enforcement**: Program-level YAML boundary definitions supporting wildcard domains (`*.example.com`), CIDR blocks (`203.0.113.0/24`), and explicit exclusion rules (`mail.example.com`). Every single recon probe and finding must validate in-scope before execution.
- 🔍 **Standardized Recon Tool Wrapping**: Wraps leading passive and active recon tools (`subfinder`, `httpx`, `nuclei`, `nmap`) with safe scan defaults, output normalization, and clear install guidance.
- 🧠 **Dual-Engine Finding Triage**: Prioritizes attack surface risks using intelligent rules-based scoring (status codes, high-risk ports, technology fingerprinting, CVE severities) or AI-augmented reasoning with Anthropic Claude (`claude-sonnet-4-6`).
- 🛡️ **Engagement Compliance Guardrails**: Prominently warns operators before any target metadata or finding context is transmitted to third-party AI APIs. Safety guardrails strictly prohibit the AI from generating exploit code.
- 📋 **Verified Finding Management**: Dedicated manual finding tracker for validated vulnerabilities with CVSS v3.1 scoring, remediation instructions, reproduction steps, and full lifecycle tracking (`open`, `fixed`, `accepted-risk`, `duplicate`).
- 📊 **Multi-Format Report Generation**: Generates publication-ready executive and technical reports in **Markdown**, standalone styled **HTML**, structured **JSON**, or **YAML**, with AI prose polishing and template fallback.
- 📜 **Local Audit Trails**: Maintains immutable local audit logging across SQLite and plain text log files for transparency and post-engagement review.

---

## Installation

### Prerequisites

- **Python**: Version `3.10` or higher
- **Git**
- Optional recon CLI tools (installed via your system package manager or Go):
  - `subfinder` (subdomain enumeration)
  - `httpx` (HTTP service probing)
  - `nuclei` (template-based vulnerability scanning)
  - `nmap` (network port scanning)

### Install ReconCopilot

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/ReconCopilot.git
   cd ReconCopilot
   ```

2. Create and activate a virtual environment:
   ```bash
   # On macOS/Linux:
   python3 -m venv .venv
   source .venv/bin/activate

   # On Windows (PowerShell):
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. Install in editable mode:
   ```bash
   # Production runtime install:
   pip install -e .

   # Or development install (with pytest and ruff):
   pip install -e ".[dev]"
   ```

4. Verify installation:
   ```bash
   reconcopilot --version
   reconcopilot --help
   ```

---

## Quickstart Walkthrough

Follow this step-by-step walkthrough to go from a clean repository to a generated assessment report.

### 1. Initialize Configuration & Database

ReconCopilot stores its configuration and SQLite database under `~/.config/reconcopilot/`.

```bash
# Initialize local database schema
reconcopilot init
```

To configure custom settings (e.g. Anthropic API key, log levels), copy the example configuration:

```bash
# macOS/Linux:
mkdir -p ~/.config/reconcopilot
cp config.example.yaml ~/.config/reconcopilot/config.yaml

# Windows PowerShell:
New-Item -ItemType Directory -Force -Path "$HOME\.config\reconcopilot"
Copy-Item config.example.yaml "$HOME\.config\reconcopilot\config.yaml"
```

*(Optional)* Set your Anthropic API key if using Claude AI triage and report polish:

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

---

### 2. Define an Engagement Scope

Create an authorized scope YAML defining allowed domains, IP ranges, and explicit exclusions:

```bash
reconcopilot scope create acme-corp \
  --domains "*.acme.com, acme-staging.io" \
  --ips "203.0.113.0/24" \
  --exclusions "mail.acme.com" \
  --url "https://hackerone.com/acme" \
  --notes "Authorized annual web penetration test" \
  --non-interactive
```

Verify your scope boundaries:

```bash
# In scope: matches wildcard *.acme.com
reconcopilot scope check acme-corp api.acme.com

# Out of scope: explicitly excluded
reconcopilot scope check acme-corp mail.acme.com
```

List and inspect defined scopes:

```bash
reconcopilot scope list
reconcopilot scope show acme-corp
```

---

### 3. Run Reconnaissance Discovery

Run standardized discovery tools against your scope. All output is normalized and recorded in SQLite:

```bash
# 1. Enumerate subdomains via subfinder
reconcopilot recon subdomains --scope acme-corp

# 2. Probe discovered assets for live HTTP web services via httpx
reconcopilot recon probe --scope acme-corp

# 3. Run template vulnerability scans on active hosts via nuclei
reconcopilot recon scan --scope acme-corp

# 4. Port scan a specific authorized host using safe nmap flags
reconcopilot recon ports --scope acme-corp --target 203.0.113.10

# 5. Check cumulative discovery status for the scope
reconcopilot recon status --scope acme-corp
```

> **Note**: If any external tool is not installed, ReconCopilot will provide install hints. You can also manually register targets directly with:
> ```bash
> reconcopilot add api.acme.com --scope acme-corp --notes "Primary REST API"
> ```

---

### 4. Triage Findings & Attack Surface

Run the triage engine to identify the highest-priority exposure points:

```bash
# Run triage (uses Claude if ANTHROPIC_API_KEY is configured, else rules engine)
reconcopilot triage run --scope acme-corp --top 5

# Focus on specific areas (e.g. administrative portals or databases)
reconcopilot triage run --scope acme-corp --top 5 --focus "admin portals"

# Review triage audit history
reconcopilot triage history --scope acme-corp
```

---

### 5. Track Verified Manual Findings

As you confirm vulnerabilities through manual testing, record them in the verified findings database:

```bash
# Add a critical confirmed vulnerability
reconcopilot finding add --scope acme-corp \
  --title "SQL Injection in /api/v1/search" \
  --severity critical \
  --status open \
  --asset api.acme.com \
  --cvss 9.8 \
  --description "Unsanitized user input in query parameter q allows blind boolean SQL injection." \
  --impact "Full database extraction including customer PII and credentials." \
  --repro "1. Send GET /api/v1/search?q=' OR 1=1-- and observe timing differential." \
  --remediation "Implement parameterized queries using prepared statements."

# Add a medium finding
reconcopilot finding add --scope acme-corp \
  --title "Missing Content-Security-Policy Header" \
  --severity medium \
  --status open \
  --asset acme-staging.io \
  --cvss 5.4 \
  --description "Application lacks Content-Security-Policy header, elevating XSS risk." \
  --impact "Enables execution of malicious scripts if XSS vectors exist." \
  --repro "1. Inspect HTTP response headers of https://acme-staging.io." \
  --remediation "Deploy a strict Content-Security-Policy response header."
```

Review and manage findings:

```bash
# List open findings
reconcopilot finding list --scope acme-corp --status open

# Update finding status after verification of remediation
reconcopilot finding update 2 --status fixed

# Export findings to JSON
reconcopilot finding export --scope acme-corp
```

---

### 6. Generate the Assessment Report

Compile your verified findings, scope details, and recon statistics into an engagement report:

```bash
# Generate Markdown report (saved to ./output/reports/report_acme-corp_<date>.md)
reconcopilot report generate --scope acme-corp --format markdown

# Generate styled HTML report for stakeholders
reconcopilot report generate --scope acme-corp --format html -o ./reports/final_report.html

# Deterministic report without AI polish
reconcopilot report generate --scope acme-corp --format markdown --no-ai

# Export structured JSON or YAML report
reconcopilot report generate --scope acme-corp --format json
reconcopilot report generate --scope acme-corp --format yaml
```

---

## Configuration Reference

ReconCopilot configuration can be customized via `~/.config/reconcopilot/config.yaml` or through environment variables. Environment variables take precedence over configuration file values.

| Setting | YAML Key | Environment Variable | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| **App Name** | `app.name` | `RECONCOPILOT__APP__NAME` | `ReconCopilot` | Name of the application instance. |
| **Environment** | `app.environment` | `RECONCOPILOT__APP__ENVIRONMENT` | `development` | Deployment environment mode (`development`, `staging`, `production`). |
| **Log Level** | `app.log_level` | `RECONCOPILOT_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| **AI Provider** | `ai.provider` | `RECONCOPILOT__AI__PROVIDER` | `anthropic` | LLM backend provider. |
| **API Key** | `ai.api_key` | `ANTHROPIC_API_KEY` | `""` | Anthropic Claude API key for triage and report prose. |
| **AI Model** | `ai.model` | `RECONCOPILOT__AI__MODEL` | `claude-sonnet-4-6` | Claude model identifier. |
| **Max Tokens** | `ai.max_tokens` | `RECONCOPILOT__AI__MAX_TOKENS` | `4096` | Max completion tokens for AI completions. |
| **Database Path** | `database.path` | `DATABASE_PATH` or `RECONCOPILOT_DB_PATH` | `~/.config/reconcopilot/reconcopilot.db` | Local SQLite database file location. |
| **DB Timeout** | `database.timeout` | `RECONCOPILOT__DATABASE__TIMEOUT` | `30.0` | SQLite connection timeout in seconds. |
| **Audit Log File**| `audit.log_file` | `RECONCOPILOT__AUDIT__LOG_FILE` | `~/.config/reconcopilot/audit.log` | Path for structured file audit logging. |
| **Audit Enabled** | `audit.enabled` | `RECONCOPILOT__AUDIT__ENABLED` | `true` | Enable or disable audit logging. |
| **Strict Scope**  | `scope.strict_mode` | `RECONCOPILOT__SCOPE__STRICT_MODE` | `true` | Disallow actions on targets not matching scope rules. |
| **Private IPs**   | `scope.allow_private_ips` | `RECONCOPILOT__SCOPE__ALLOW_PRIVATE_IPS` | `false` | Permit RFC 1918 private IP ranges in scopes. |
| **Passive Only**  | `recon.passive_only` | `RECONCOPILOT__RECON__PASSIVE_ONLY` | `true` | Restrict scanning tools to non-intrusive queries. |
| **Recon Threads** | `recon.threads` | `RECONCOPILOT__RECON__THREADS` | `10` | Worker concurrency for network commands. |
| **Report Output** | `report.output_dir` | `RECONCOPILOT__REPORT__OUTPUT_DIR` | `./output/reports` | Default destination directory for generated reports. |
| **Report Format** | `report.default_format` | `RECONCOPILOT__REPORT__DEFAULT_FORMAT` | `markdown` | Default report output format (`markdown`, `html`, `json`, `yaml`). |

---

## Development & Testing

We welcome community contributions! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for full development standards.

### Running Linting & Formatting

We use [Ruff](https://docs.astral.sh/ruff/) to maintain code quality:

```bash
# Check code style
ruff check .

# Format code
ruff format .
```

### Running Test Suite

ReconCopilot includes comprehensive unit and integration tests covering scope boundaries, tool parsing, finding CRUD, AI triage guardrails, and report generation:

```bash
pytest -v
```

---

## Security Policy

For information regarding reporting security vulnerabilities within ReconCopilot itself, please refer to our [Security Policy](SECURITY.md).

---

## License

This project is licensed under the [MIT License](LICENSE).
