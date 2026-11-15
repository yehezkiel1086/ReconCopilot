"""Command-line interface entry point for ReconCopilot."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import reconcopilot
from reconcopilot.audit import log_audit, read_file_audit_logs
from reconcopilot.config import load_config
from reconcopilot.db import add_target, init_db, list_targets
from reconcopilot.modules import recon, report, tracking, triage
from reconcopilot.scope import (
    ScopeChecker,
    ScopeViolationError,
    list_scopes,
    require_in_scope,
)

app = typer.Typer(
    name="reconcopilot",
    help="ReconCopilot: AI-assisted reconnaissance and security workflow assistant.",
    add_completion=False,
)
scope_app = typer.Typer(
    name="scope",
    help="Manage and verify engagement scopes.",
    no_args_is_help=True,
)
app.add_typer(scope_app, name="scope")

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


# ==============================================================================
# Scope Management Command Group
# ==============================================================================


@scope_app.command("create")
def scope_create(
    name: str = typer.Argument(..., help="Unique scope or engagement name."),
    domains: Optional[str] = typer.Option(
        None, "--domains", "-d", help="Comma-separated in-scope domains."
    ),
    ip_ranges: Optional[str] = typer.Option(
        None,
        "--ip-ranges",
        "--ips",
        "-i",
        help="Comma-separated in-scope IP ranges (CIDRs).",
    ),
    exclusions: Optional[str] = typer.Option(
        None, "--exclusions", "-e", help="Comma-separated explicit exclusions."
    ),
    program_url: Optional[str] = typer.Option(
        None, "--url", help="Bug bounty or engagement URL."
    ),
    contact_email: Optional[str] = typer.Option(
        None, "--email", help="Security contact email."
    ),
    start_date: Optional[str] = typer.Option(
        None, "--start-date", help="Engagement start date (YYYY-MM-DD)."
    ),
    end_date: Optional[str] = typer.Option(
        None, "--end-date", help="Engagement end date (YYYY-MM-DD)."
    ),
    notes: Optional[str] = typer.Option(
        None, "--notes", help="Rules of engagement or notes."
    ),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", help="Do not prompt for missing fields."
    ),
) -> None:
    """Create a new scope YAML file interactively or with options."""
    clean_name = name.strip()
    if not clean_name:
        console.print("[bold red]Error:[/bold red] Scope name cannot be empty.")
        raise typer.Exit(code=1)

    # If in interactive mode and fields are missing, prompt the user
    if not non_interactive:
        if domains is None:
            domains = typer.prompt(
                "In-scope domains (comma-separated, e.g. '*.acme.com, acme-staging.io')",
                default="",
            )
        if ip_ranges is None:
            ip_ranges = typer.prompt(
                "In-scope IP ranges (comma-separated CIDRs, e.g. '203.0.113.0/24')",
                default="",
            )
        if exclusions is None:
            exclusions = typer.prompt(
                "Explicit exclusions (comma-separated, e.g. 'mail.acme.com, 198.51.100.0/28')",
                default="",
            )
        if program_url is None:
            program_url = typer.prompt(
                "Program URL (optional)",
                default="",
            )
        if contact_email is None:
            contact_email = typer.prompt(
                "Contact email (optional)",
                default="",
            )
        if notes is None:
            notes = typer.prompt(
                "Rules of engagement / notes (optional)",
                default="",
            )

    domain_list = [d.strip() for d in (domains or "").split(",") if d.strip()]
    ip_list = [i.strip() for i in (ip_ranges or "").split(",") if i.strip()]
    exclusion_list = [e.strip() for e in (exclusions or "").split(",") if e.strip()]

    metadata: dict[str, str] = {}
    if program_url and program_url.strip():
        metadata["program_url"] = program_url.strip()
    if contact_email and contact_email.strip():
        metadata["contact_email"] = contact_email.strip()
    if start_date and start_date.strip():
        metadata["start_date"] = start_date.strip()
    if end_date and end_date.strip():
        metadata["end_date"] = end_date.strip()
    if notes and notes.strip():
        metadata["notes"] = notes.strip()

    scope_data = {
        "name": clean_name,
        "targets": {
            "domains": domain_list,
            "ip_ranges": ip_list,
            "exclusions": exclusion_list,
        },
        "metadata": metadata,
    }

    checker = ScopeChecker(data=scope_data)
    saved_path = checker.save()

    console.print(
        f"[bold green]✔[/bold green] Created scope [cyan]{clean_name}[/cyan] at [yellow]{saved_path}[/yellow]"
    )
    log_audit("scope.create", target=clean_name, details={"file": str(saved_path)})


@scope_app.command("list")
def scope_list() -> None:
    """List all defined scopes."""
    scopes = list_scopes()
    if not scopes:
        console.print(
            "[yellow]No scopes defined yet.[/yellow] Run 'reconcopilot scope create <name>' to define one."
        )
        return

    table = Table(title="Defined Scopes")
    table.add_column("Scope Name", style="cyan", no_wrap=True)
    table.add_column("Domains", style="green")
    table.add_column("IP Ranges", style="blue")
    table.add_column("Exclusions", style="red")
    table.add_column("Program URL", style="magenta", overflow="fold")

    for s in scopes:
        d_summary = f"{len(s.domains)} domain(s)" if s.domains else "None"
        if s.domains:
            d_summary += (
                f" ({', '.join(s.domains[:2])}{'...' if len(s.domains) > 2 else ''})"
            )

        i_summary = f"{len(s.ip_ranges)} range(s)" if s.ip_ranges else "None"
        if s.ip_ranges:
            i_summary += f" ({', '.join(s.ip_ranges[:2])}{'...' if len(s.ip_ranges) > 2 else ''})"

        e_summary = f"{len(s.exclusions)} exclusion(s)" if s.exclusions else "None"
        if s.exclusions:
            e_summary += f" ({', '.join(s.exclusions[:2])}{'...' if len(s.exclusions) > 2 else ''})"

        url = s.metadata.get("program_url", "")
        table.add_row(s.name, d_summary, i_summary, e_summary, url)

    console.print(table)


@scope_app.command("show")
def scope_show(
    name: str = typer.Argument(..., help="Scope name to inspect."),
) -> None:
    """Print a scope's targets, exclusions, and metadata."""
    try:
        scope = ScopeChecker.from_name(name)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    lines: list[str] = [
        f"[bold cyan]Scope Name:[/bold cyan] {scope.name}",
        f"[bold dim]File Path:[/bold dim] {scope.file_path}",
        "",
        "[bold green]In-Scope Domains:[/bold green]",
    ]
    if scope.domains:
        for d in scope.domains:
            lines.append(f"  • {d}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("[bold blue]In-Scope IP Ranges:[/bold blue]")
    if scope.ip_ranges:
        for r in scope.ip_ranges:
            lines.append(f"  • {r}")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("[bold red]Explicit Exclusions:[/bold red]")
    if scope.exclusions:
        for e in scope.exclusions:
            lines.append(f"  • {e}")
    else:
        lines.append("  (none)")

    if scope.metadata:
        lines.append("")
        lines.append("[bold magenta]Metadata:[/bold magenta]")
        for k, v in scope.metadata.items():
            lines.append(f"  • {k}: {v}")

    console.print(Panel("\n".join(lines), title=f"Scope Details: {scope.name}"))


@scope_app.command("check")
def scope_check(
    name: str = typer.Argument(..., help="Scope name to test against."),
    target: str = typer.Argument(..., help="Target host, IP, or domain to verify."),
) -> None:
    """Test whether a given target is in scope, with clear reasoning."""
    try:
        scope = ScopeChecker.from_name(name)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    result = scope.check(target)
    if result.in_scope:
        console.print(f"[bold green]{result.reason}[/bold green]")
    else:
        console.print(f"[bold red]{result.reason}[/bold red]")
        raise typer.Exit(code=1)


# Top-level check-scope command (retained for backward compatibility)
@app.command("check-scope")
def check_scope_cmd(
    target: str = typer.Argument(..., help="Target host, IP, or domain to verify."),
    scope_name: Optional[str] = typer.Option(
        None, "--scope", "-s", help="Scope name to check against."
    ),
    scope_file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Path to scope rules YAML file."
    ),
) -> None:
    """Verify if a target is authorized within the configured scope."""
    try:
        if scope_file:
            scope = ScopeChecker.from_file(scope_file)
        elif scope_name:
            scope = ScopeChecker.from_name(scope_name)
        else:
            active = require_in_scope
            norm = active(target)
            console.print(
                f"[bold green]✔ IN SCOPE:[/bold green] [cyan]{norm}[/cyan] is authorized."
            )
            return

        result = scope.check(target)
        if result.in_scope:
            console.print(f"[bold green]{result.reason}[/bold green]")
        else:
            console.print(f"[bold red]{result.reason}[/bold red]")
            raise typer.Exit(code=1)
    except ScopeViolationError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=1)


# ==============================================================================
# Target & Engagement Commands
# ==============================================================================


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
        "default", "--scope", "-s", help="Scope group or engagement name."
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
            target = require_in_scope(target, scope=scope_name)
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


# ==============================================================================
# Phase Module Stubs
# ==============================================================================


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target host or IP."),
    passive: bool = typer.Option(
        True, "--passive/--active", help="Passive reconnaissance mode."
    ),
    scope: Optional[str] = typer.Option(
        None, "--scope", "-s", help="Scope name to check against."
    ),
) -> None:
    """Run reconnaissance against target (Phase 2)."""
    try:
        result = recon.run_recon(target=target, passive_only=passive, scope=scope)
        console.print(f"[bold blue]Recon (Phase 2):[/bold blue] {result}")
    except ScopeViolationError as exc:
        console.print(f"[bold red]Scope Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def triage_cmd(
    target: str = typer.Argument(..., help="Target host or IP."),
    finding: str = typer.Option("open_port", "--finding", "-f", help="Finding type."),
    scope: Optional[str] = typer.Option(
        None, "--scope", "-s", help="Scope name to check against."
    ),
) -> None:
    """Triage findings with AI reasoning (Phase 3)."""
    try:
        result = triage.triage_finding(
            target=target, finding_type=finding, raw_evidence="stub", scope=scope
        )
        console.print(f"[bold blue]Triage (Phase 3):[/bold blue] {result}")
    except ScopeViolationError as exc:
        console.print(f"[bold red]Scope Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


@app.command()
def track(
    target: str = typer.Argument(..., help="Target host or IP."),
    scope: Optional[str] = typer.Option(
        None, "--scope", "-s", help="Scope name to check against."
    ),
) -> None:
    """Track asset deltas and changes (Phase 4)."""
    try:
        result = tracking.track_asset_changes(target=target, scope=scope)
        console.print(f"[bold blue]Tracking (Phase 4):[/bold blue] {result}")
    except ScopeViolationError as exc:
        console.print(f"[bold red]Scope Error:[/bold red] {exc}")
        raise typer.Exit(code=1)


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
