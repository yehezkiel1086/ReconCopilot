# Contributing to ReconCopilot

Thank you for your interest in contributing to **ReconCopilot**! ReconCopilot is an AI-assisted reconnaissance and security workflow assistant designed for authorized penetration testers, bug bounty hunters, and security teams.

We welcome issues, feature requests, documentation improvements, and code contributions.

---

## Code of Conduct & Ethical Guidelines

ReconCopilot is designed exclusively for **authorized security testing**. All contributors must abide by these principles:
- **No Weaponization**: Do not contribute exploit generation, automated payload delivery, denial-of-service, or weaponized attack modules.
- **Scope Enforcement**: Every command or utility accepting a target must validate that target against an active authorized scope.
- **Transparency & Auditability**: Actions must log structured records to local audit logs to maintain accountability.

---

## Getting Started

### Prerequisites

- **Python**: Version 3.10, 3.11, or 3.12
- **Git**: Installed and configured
- Optional recon tools (for running live recon modules):
  - `subfinder`
  - `httpx`
  - `nuclei`
  - `nmap`

### Development Environment Setup

1. Clone your fork of the repository:
   ```bash
   git clone https://github.com/your-username/ReconCopilot.git
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

3. Install ReconCopilot in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Verify installation:
   ```bash
   reconcopilot --version
   reconcopilot --help
   ```

---

## Code Style & Standards

We enforce code formatting and linting rules using **[Ruff](https://docs.astral.sh/ruff/)**.

### Linting & Formatting Commands

- **Check for lint errors**:
  ```bash
  ruff check .
  ```

- **Automatically fix lint errors**:
  ```bash
  ruff check --fix .
  ```

- **Check code formatting**:
  ```bash
  ruff format --check .
  ```

- **Auto-format code**:
  ```bash
  ruff format .
  ```

All Python code should follow:
- PEP 8 conventions.
- Explicit type annotations where appropriate (`from __future__ import annotations`).
- Line length limit of 88 characters (managed by Ruff).

---

## Running Tests

We use **[pytest](https://docs.pytest.org/)** for test coverage across all modules and CLI commands.

### Running Test Suites

- **Run all tests**:
  ```bash
  pytest
  ```

- **Run tests with verbose output**:
  ```bash
  pytest -v
  ```

- **Run a specific test module**:
  ```bash
  pytest tests/test_scope.py
  pytest tests/test_recon.py
  pytest tests/test_triage.py
  pytest tests/test_tracking.py
  pytest tests/test_report.py
  ```

Before submitting a Pull Request, ensure that all tests pass cleanly without errors or warnings.

---

## Conventional Commits

We follow the **[Conventional Commits](https://www.conventionalcommits.org/)** standard for all commit messages. This helps generate clean changelogs and maintain structured project history.

Format:
```
<type>(<scope>): <short description>
```

Common types:
- `feat`: A new feature (e.g. `feat(report): add HTML styling template`)
- `fix`: A bug fix (e.g. `fix(scope): handle IPv6 CIDR edge cases`)
- `docs`: Documentation updates (e.g. `docs: update installation instructions`)
- `refactor`: Code restructuring without changing behavior (e.g. `refactor(cli): simplify command options`)
- `test`: Adding or updating test suites (e.g. `test(recon): add httpx parsing tests`)
- `chore`: Tooling, build config, or dependency updates (e.g. `chore: update .gitignore rules`)

---

## Pull Request Guidelines

1. **Create a topic branch**:
   ```bash
   git checkout -b feature/my-feature-name
   ```
2. **Implement changes**: Follow code style guidelines, add test coverage, and verify tests pass.
3. **Commit with Conventional Commits**: Make logical, atomic commits.
4. **Push and open a PR**:
   - Provide a clear title and description of the changes.
   - Reference any related issues (e.g., `Closes #12`).
   - Confirm CI workflows pass on your branch.
