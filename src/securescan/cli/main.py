"""CLI entry point for SecureScan AI."""

import click
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..core.scanner import Scanner
from ..utils.logger import get_logger, setup_logging
from ..utils.config import Config, init_config
from ..utils.exceptions import SecureScanError, ConfigError, ScanError
from ..version import VERSION

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

console = Console()
logger = get_logger(__name__)


@click.group()
@click.version_option(version=VERSION, prog_name="SecureScan AI")
@click.option("--config", type=click.Path(exists=True), help="Configuration file path")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--log-file", type=click.Path(), help="Write logs to file")
@click.pass_context
def cli(ctx, config, verbose, log_file):
    """
    SecureScan AI - Open Source Security Code Review Platform
    
    Combines SAST scanning, AI validation, and CVE intelligence.
    
    \b
    Examples:
        # Basic scan
        secscan scan .
        
        # With AI validation
        secscan scan . --llm openai
        
        # Complete pipeline
        secscan scan . --llm openai --enrich-cve
        
        # Setup API keys
        secscan setup
        
        # Show configuration
        secscan config show
    """
    log_level = "DEBUG" if verbose else "INFO"
    
    try:
        setup_logging(level=log_level, log_file=Path(log_file) if log_file else None, verbose=verbose)
    except Exception as e:
        console.print(f"[red]❌ Logging setup failed:[/red] {e}")
        sys.exit(1)
    
    try:
        if config:
            logger.info(f"Loading config from: {config}")
            cfg = init_config(Path(config))
        else:
            cfg = Config()
        
        ctx.ensure_object(dict)
        ctx.obj["config"] = cfg
        ctx.obj["verbose"] = verbose
        logger.debug("Configuration loaded successfully")
    
    except ConfigError as e:
        console.print(f"[red]❌ Configuration Error:[/red]\n{e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Unexpected Error:[/red] {e}")
        logger.error(f"Initialization failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument("target", type=click.Path(exists=True), required=True)
@click.option("--severity", "-s", multiple=True, type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False), help="Filter by severity")
@click.option("--output", "-o", type=click.Choice(["console", "json", "sarif"], case_sensitive=False), default="console", help="Output format")
@click.option("--output-file", "-f", type=click.Path(), help="Write output to file")
@click.option("--max-findings", "-m", type=int, default=50, help="Max findings to display")
@click.option("--llm", type=click.Choice(["openai", "ollama"], case_sensitive=False), help="Enable LLM validation")
@click.option("--llm-model", default="gpt-4o", help="LLM model to use")
@click.option("--llm-confidence", type=float, default=0.7, help="LLM confidence threshold")
@click.option("--enrich-cve", is_flag=True, help="Enable CVE enrichment")
@click.option("--cve-max", default=10, type=int, help="Max CVEs per finding")
@click.option("--no-secrets", is_flag=True, help="Disable secrets detection")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"], case_sensitive=False), default="HIGH", help="Fail on severity")
@click.pass_context
def scan(ctx, target, severity, output, output_file, max_findings, llm, llm_model, llm_confidence, enrich_cve, cve_max, no_secrets, fail_on):
    """
    Scan target directory or file for security vulnerabilities.
    
    \b
    Examples:
        # Basic scan (free)
        secscan scan .
        
        # With AI validation
        secscan scan ./src --llm openai
        
        # Complete pipeline
        secscan scan ./src --llm openai --enrich-cve
        
        # Severity filter
        secscan scan ./src --severity HIGH --severity CRITICAL
        
        # JSON output
        secscan scan ./src --output json --output-file results.json
    
    \b
    Exit Codes:
        0 - No issues or below threshold
        1 - HIGH severity found
        2 - CRITICAL severity found
        3 - Scan error
    """
    cfg = ctx.obj.get("config", Config())
    verbose = ctx.obj.get("verbose", False)
    target_path = Path(target).resolve()
    
    if not target_path.exists():
        console.print(f"[red]❌ Target not found:[/red] {target_path}")
        sys.exit(1)
    
    console.print()
    console.print(Panel.fit(f"[bold cyan]SecureScan AI v{VERSION}[/bold cyan]\nTarget: [yellow]{target_path}[/yellow]", border_style="cyan"))
    console.print()
    
    severity_filter = [s.upper() for s in severity] if severity else None
    
    if severity_filter:
        console.print(f"🔍 Severity filter: [yellow]{', '.join(severity_filter)}[/yellow]")
    if llm:
        console.print(f"🤖 LLM validation: [green]{llm}/{llm_model}[/green] (confidence: {llm_confidence:.0%})")
        console.print(f"[dim]   Using {llm.upper()} API - costs may apply[/dim]")
    if enrich_cve:
        console.print(f"📋 CVE enrichment: [green]Enabled[/green]")
    
    console.print(f"⚠️  Fail on: [yellow]{fail_on.upper()}[/yellow] severity or higher")
    console.print()
    
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("🔍 Scanning...", total=None)
            scanner = Scanner(config=cfg)
            result = scanner.scan(
                target=target_path,
                severity_filter=severity_filter,
                enable_secrets=not no_secrets,
                enable_llm=bool(llm),
                llm_provider=llm or "openai",
                llm_model=llm_model,
                llm_confidence_threshold=llm_confidence,
                enable_cve_enrichment=enrich_cve,
                cve_max_per_finding=cve_max,
            )
            progress.update(task, description="✅ Scan complete")
        
        console.print()
        
        if output == "json":
            _output_json(result, output_file)
        elif output == "sarif":
            _output_sarif(result, output_file)
        else:
            _output_console(result, max_findings)
        
        exit_code = _determine_exit_code(result, fail_on)
        if exit_code != 0:
            logger.warning(f"Scan failed with exit code {exit_code}")
        sys.exit(exit_code)
    
    except (ScanError, ConfigError, SecureScanError) as e:
        console.print(f"\n[bold red]❌ Error:[/bold red]\n{e}")
        logger.error(f"Scan failed: {e}", exc_info=verbose)
        sys.exit(3)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Unexpected Error:[/bold red] {e}")
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(3)


def _determine_exit_code(result, fail_on: str) -> int:
    """Determine exit code based on findings."""
    if not result.success:
        return 3
    if fail_on.upper() == "NONE":
        return 0
    
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    fail_threshold = severity_order.get(fail_on.upper(), 3)
    
    for severity, count in result.findings_by_severity.items():
        if count > 0 and severity_order.get(severity, 0) >= fail_threshold:
            if severity == "CRITICAL":
                return 2
            elif severity == "HIGH":
                return 1
    return 0


def _output_console(result, max_findings: int):
    """Display results in console."""
    try:
        from .output import format_scan_results
        console.print(format_scan_results(result, max_findings))
        return
    except ImportError:
        pass
    
    console.print()
    console.print("[bold]" + "="*70 + "[/bold]")
    console.print("[bold cyan]SCAN SUMMARY[/bold cyan]")
    console.print("[bold]" + "="*70 + "[/bold]")
    console.print()
    console.print(f"[bold]Scan ID:[/bold] {result.scan_id}")
    console.print(f"[bold]Duration:[/bold] {result.duration_seconds:.2f}s")
    console.print(f"[bold]Files:[/bold] {result.files_scanned}")
    console.print(f"[bold]Findings:[/bold] {result.total_findings}")
    
    if result.findings_by_severity:
        console.print()
        table = Table(title="Findings by Severity")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        for severity, count in result.findings_by_severity.items():
            if count > 0:
                color = colors.get(severity, "white")
                table.add_row(f"[{color}]{severity}[/{color}]", f"[{color}]{count}[/{color}]")
        console.print(table)
    
    if result.findings:
        console.print()
        console.print(f"[bold cyan]TOP {min(len(result.findings), max_findings)} FINDINGS[/bold cyan]")
        console.print()
        
        colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        for i, f in enumerate(result.findings[:max_findings], 1):
            sev = f.get("severity", "MEDIUM")
            color = colors.get(sev, "white")
            console.print(f"[bold]{i}. [{color}]{sev}[/{color}][/bold] {f.get('title', 'No title')}")
            console.print(f"   [dim]File:[/dim] {Path(f.get('file', '')).name}:{f.get('line', 0)}")
            console.print(f"   [dim]Rule:[/dim] {f.get('rule_id', 'unknown')}")
            if f.get("code_snippet"):
                snippet = f["code_snippet"].strip()[:80]
                console.print(f"   [dim]Code:[/dim] [yellow]{snippet}[/yellow]")
            console.print()
    
    console.print("[bold]" + "="*70 + "[/bold]")
    if result.total_findings == 0:
        console.print("[bold green]✅ No vulnerabilities found![/bold green]")
    else:
        console.print(f"[bold yellow]⚠️  Found {result.total_findings} vulnerabilities[/bold yellow]")
    console.print()


def _output_json(result, output_file: str = None):
    """Output as JSON."""
    data = {
        "scan_id": result.scan_id,
        "target": result.target,
        "started_at": result.started_at.isoformat(),
        "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        "duration_seconds": result.duration_seconds,
        "files_scanned": result.files_scanned,
        "total_findings": result.total_findings,
        "findings_by_severity": result.findings_by_severity,
        "success": result.success,
        "errors": result.errors,
        "config": result.config,
        "findings": result.findings,
    }
    json_str = json.dumps(data, indent=2)
    if output_file:
        Path(output_file).write_text(json_str)
        console.print(f"[green]✅ Results written to {output_file}[/green]")
    else:
        console.print(json_str)


def _output_sarif(result, output_file: str = None):
    """Output as SARIF."""
    try:
        from ..github.sarif_generator import generate_sarif
        sarif_data = generate_sarif(result)
        sarif_str = json.dumps(sarif_data, indent=2)
        if output_file:
            Path(output_file).write_text(sarif_str)
            console.print(f"[green]✅ SARIF written to {output_file}[/green]")
        else:
            console.print(sarif_str)
    except ImportError:
        console.print("[red]❌ SARIF generation not available[/red]")
        sys.exit(1)


@cli.group()
def config():
    """Manage SecureScan configuration."""
    pass


@config.command()
@click.pass_context
def show(ctx):
    """Show current configuration."""
    cfg = ctx.obj.get("config", Config())
    console.print("\n[bold cyan]📋 Current Configuration[/bold cyan]\n")
    console.print(f"[cyan]Scan timeout:[/cyan] {cfg.scan.timeout}s")
    console.print(f"[cyan]LLM provider:[/cyan] {cfg.llm.provider}")
    console.print(f"[cyan]CVE enabled:[/cyan] {cfg.cve.enabled}\n")


@config.command()
@click.option("--overwrite", is_flag=True, help="Overwrite existing")
def init(overwrite):
    """Initialize config file."""
    try:
        config_file = Config.create_user_config(overwrite=overwrite)
        console.print(f"\n[green]✅ Created: {config_file}[/green]\n")
    except ConfigError as e:
        console.print(f"\n[red]❌ Error: {e}[/red]\n")
        sys.exit(1)


@cli.command()
def version():
    """Show version information."""
    console.print(f"\n[bold cyan]SecureScan AI[/bold cyan] v[yellow]{VERSION}[/yellow]\n")
    console.print("[dim]https://github.com/saimani21/securescan-ai[/dim]\n")


# IMPORTANT: Register setup command AFTER cli is defined
try:
    from .setup import setup
    cli.add_command(setup)
except ImportError:
    pass


if __name__ == "__main__":
    cli(obj={})
