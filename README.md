# ReconCopilot

ReconCopilot is an intelligent, AI-assisted reconnaissance and security workflow assistant designed to help security engineers, penetration testers, and bug bounty researchers safely discover, track, triage, and report assets within strictly authorized scopes. By pairing systematic reconnaissance with local audit trails and LLM-assisted reasoning, ReconCopilot accelerates attack surface mapping while enforcing strict scope boundaries and operational compliance.

> **Status: early development** — Core foundational architecture (CLI, configuration system, SQLite state database, scope allowlist enforcement, audit logging) is implemented. Advanced scanning, AI triage, delta tracking, and reporting modules are currently under active development.

---

## Features

- **Scope Allowlist Enforcement**: Strict domain wildcard, CIDR, and IP validation prevents unauthorized scanning or requests outside of defined rules.
- **Hierarchical Configuration**: Configuration loads from `~/.config/reconcopilot/config.yaml` with built-in bundled defaults and flexible environment variable overrides (e.g., `ANTHROPIC_API_KEY`).
- **Local SQLite State Storage**: Tracks targets and maintains an immutable audit log of all automated and manual actions.
- **Audit Logging**: Structured local file and database audit logs to ensure full accountability and compliance.
- **Modular Architecture**: Clean phased pipeline ready for Phase 2 (Recon), Phase 3 (Triage), Phase 4 (Tracking), and Phase 5 (Reporting).

---

## Installation

Clone the repository and install ReconCopilot in editable mode:

```bash
git clone https://github.com/your-org/ReconCopilot.git
cd ReconCopilot

# Install with development dependencies
pip install -e ".[dev]"
```

Or for runtime dependencies only:

```bash
pip install -e .
```

Verify that the CLI is accessible:

```bash
reconcopilot --help
```

---

## Quick Start

### 1. Initialize Configuration and Database

Copy the example configuration to your local config folder:

```bash
mkdir -p ~/.config/reconcopilot
cp config.example.yaml ~/.config/reconcopilot/config.yaml
```

Initialize the database:

```bash
reconcopilot init
```

### 2. Configure Scope

Create a scope allowlist file (e.g. `scope.txt`):

```text
# Authorized engagement targets
*.example.com
192.168.1.0/24
10.0.0.1
```

Validate a target against your scope:

```bash
reconcopilot check-scope api.example.com --file scope.txt
```

### 3. Add Targets

```bash
reconcopilot add api.example.com --scope production --notes "Primary customer API"
reconcopilot targets
```

### 4. View Audit Logs

```bash
reconcopilot audit --limit 10
```

### 5. Generate Engagement Reports (Phase 5)

Generate comprehensive technical and executive reports in Markdown, HTML, JSON, or YAML:

```bash
# Generate Markdown report (with AI polish if ANTHROPIC_API_KEY is configured)
reconcopilot report generate --scope acme-corp-2026 --format markdown

# Generate standalone styled HTML report
reconcopilot report generate --scope acme-corp-2026 --format html -o ./reports/final.html

# Deterministic report without AI polish
reconcopilot report generate --scope acme-corp-2026 --format markdown --no-ai

# Export structured findings data for external pipelines
reconcopilot report generate --scope acme-corp-2026 --format json
```

---

## Development & Testing

Run linting and formatting checks with [Ruff](https://docs.astral.sh/ruff/):

```bash
ruff check .
ruff format --check .
```

Run test suite with [pytest](https://docs.pytest.org/):

```bash
pytest
```

---

## License

This project is licensed under the [MIT License](LICENSE).
