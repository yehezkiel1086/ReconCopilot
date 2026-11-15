"""Command-line interface entry point for ReconCopilot."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

import reconcopilot
from reconcopilot.audit import log_audit, read_file_audit_logs
from reconcopilot.config import load_config
from reconcopilot.db import add_target, init_db, list_targets
from reconcopilot.modules import recon, report, tracking, triage
from reconcopilot.scope import ScopeAllowlist, ScopeViolationError, enforce_scope

app = typer.Typer(
    name="reconcopilot",
    help="ReconCopilot: AI-assisted reconnaissance and security workflow assistant.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(
            f"[bold cyan]ReconCopilot[/bold cyan] version [green]{reconcopilot.__version__}[/green]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """ReconCopilot CLI root command."""


@app.command()
def init(
    db_path: Optional[str] = typer.Option(
        None, "--db-path", help="Custom SQLite database file path."
    ),
) -> None:
    """Initialize ReconCopilot SQLite database and verify environment."""
    cfg = load_config()
    resolved_db = init_db(db_path=db_path)
    console.print(
        f"[bold green]✔[/bold green] Initialized database at: [cyan]{resolved_db}[/cyan]"
    )
    console.print(
        f"[bold green]✔[/bold green] Environment mode: [yellow]{cfg.app.environment}[/yellow]"
    )
    log_audit("cli.init", details={"db_path": str(resolved_db)})


@app.command()
def add(
    target: str = typer.Argument(..., help="Target host, IP, or domain."),
    scope_name: str = typer.Option(
        "default", "--scope", "-s", help="Scope group name."
    ),
    notes: str = typer.Option("", "--notes", "-n", help="Optional notes for target."),
    strict: bool = typer.Option(
        True, "--strict/--no-strict", help="Enforce scope allowlist."
    ),
) -> None:
    """Add a target to the tracking database."""
    init_db()
    if strict:
        try:
            enforce_scope(target)
        except ScopeViolationError as exc:
            console.print(f"[bold red]Scope Error:[/bold red] {exc}")
            raise typer.Exit(code=1)

    target_id = add_target(scope_name=scope_name, target=target, notes=notes)
    console.print(
        f"[bold green]✔[/bold green] Added target [cyan]{target}[/cyan] (id: {target_id}) under scope [yellow]{scope_name}[/yellow]"
    )
    log_audit(
        "target.add", target=target, details={"scope": scope_name, "id": target_id}
    )


@app.command()
def targets(
    scope_name: Optional[str] = typer.Option(
        None, "--scope", "-s", help="Filter by scope name."
    ),
) -> None:
    """List registered reconnaissance targets."""
    init_db()
    rows = list_targets(scope_name=scope_name)
    if not rows:
        console.print("[yellow]No targets found.[/yellow]")
        return

    table = Table(title="Recon Targets")
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Scope", style="magenta")
    table.add_column("Target", style="green")
    table.add_column("Added At", style="blue")
    table.add_column("Notes", style="white")

    for r in rows:
        table.add_row(
            str(r["id"]),
            r["scope_name"],
            r["target"],
            r["added_at"],
            r.get("notes", ""),
        )
    console.print(table)


@app.command()
def check_scope(
    target: str = typer.Argument(..., help="Target host, IP, or domain to verify."),
    scope_file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Path to scope rules file."
    ),
) -> None:
    """Verify if a target is authorized within the configured scope."""
    if scope_file:
        scope = ScopeAllowlist.from_file(scope_file)
    else:
        cfg = load_config()
        if cfg.scope.allowlist_file and Path(cfg.scope.allowlist_file).is_file():
            scope = ScopeAllowlist.from_file(cfg.scope.allowlist_file)
        else:
            scope = ScopeAllowlist()

    allowed = scope.is_in_scope(target)
    if allowed:
        console.print(
            f"[bold green]✔ IN SCOPE:[/bold green] [cyan]{target}[/cyan] is authorized."
        )
    else:
        console.print(
            f"[bold red]✘ OUT OF SCOPE:[/bold red] [cyan]{target}[/cyan] is NOT authorized."
        )
        raise typer.Exit(code=1)


@app.command()
def audit(
    limit: int = typer.Option(
        20, "--limit", "-l", help="Number of audit log entries to show."
    ),
) -> None:
    """View recent audit logs."""
    logs = read_file_audit_logs(limit=limit)
    if not logs:
        console.print("[yellow]No audit logs found.[/yellow]")
        return

    table = Table(title="Audit Log")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Action", style="magenta")
    table.add_column("Target", style="green")
    table.add_column("Details", style="white")

    for entry in logs:
        table.add_row(
            entry.get("timestamp", ""),
            entry.get("action", ""),
            entry.get("target", ""),
            str(entry.get("details", "")),
        )
    console.print(table)


# Phase stubs
@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host or IP."),
    passive: bool = typer.Option(
        True, "--passive/--active", help="Passive reconnaissance mode."
    ),
) -> None:
    """Run reconnaissance against target (Phase 2)."""
    result = recon.run_recon(target=target, passive_only=passive)
    console.print(f"[bold blue]Recon (Phase 2):[/bold blue] {result}")


@app.command()
def triage_cmd(
    target: str = typer.Argument(..., help="Target host or IP."),
    finding: str = typer.Option("open_port", "--finding", "-f", help="Finding type."),
) -> None:
    """Triage findings with AI reasoning (Phase 3)."""
    result = triage.triage_finding(
        target=target, finding_type=finding, raw_evidence="stub"
    )
    console.print(f"[bold blue]Triage (Phase 3):[/bold blue] {result}")


@app.command()
def track(
    target: str = typer.Argument(..., help="Target host or IP."),
) -> None:
    """Track asset deltas and changes (Phase 4)."""
    result = tracking.track_asset_changes(target=target)
    console.print(f"[bold blue]Tracking (Phase 4):[/bold blue] {result}")


@app.command()
def report_cmd(
    scope_name: str = typer.Argument("default", help="Scope group name."),
    format: str = typer.Option(
        "markdown", "--format", help="Output format (markdown/json/html)."
    ),
) -> None:
    """Generate engagement report (Phase 5)."""
    result = report.generate_report(scope_name=scope_name, output_format=format)
    console.print(f"[bold blue]Report (Phase 5):[/bold blue] {result}")


if __name__ == "__main__":
    app()
