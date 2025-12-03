import typer
import asyncio
import os
from typing import Optional
from pathlib import Path
from .scanner.engine import ScanEngine
from .scanner.models import ScanLogEntry
from .models import ScanResult
from .pdf import generate_pdf, generate_json, generate_markdown, generate_ai_pdf
from .config import settings
from .routes import AI_REPORT_SYSTEM_PROMPT
from .ai.schema import build_ai_scan_view
from .ai.utils import parse_ai_json
from .ai.analyzer import analyzer
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from rich.layout import Layout
from rich.align import Align

app = typer.Typer(help="Relic - AI-Assisted Web Security Auditor CLI")
console = Console()

def print_banner():
    banner_text = """
    ____      _ _      
   |  _ \ ___| (_) ___ 
   | |_) / _ \ | |/ __|
   |  _ <  __/ | | (__ 
   |_| \_\___|_|_|\___|
                       
    """
    console.print(Panel(Align.center(banner_text + "\n[bold blue]Relic - AI-Assisted Web Security Auditor[/bold blue]"), border_style="blue"))

async def run_scan_async(target: str, json_out: Optional[Path], pdf_out: Optional[Path], markdown_out: Optional[Path]):
    print_banner()
    
    engine = ScanEngine()
    
    console.print(f"[bold]Target:[/bold] [cyan]{target}[/cyan]")
    console.print("[dim]Initializing scan engine...[/dim]\n")
    
    async def log_callback(entry: ScanLogEntry):
        # We can keep it quiet or show verbose logs if a flag is passed.
        # For a clean UI, let's only show INFO/WARNING/ERROR with rich markup
        if entry.level == "ERROR":
            console.print(f"[red][ERROR][/red] {entry.message}")
        elif entry.level == "WARNING":
            console.print(f"[yellow][WARN][/yellow]  {entry.message}")
        # Skip INFO for cleaner output unless verbose (not implemented yet)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            task = progress.add_task(description="Scanning target...", total=None)
            result_dataclass = await engine.run_scan(target, log_callback)
            progress.update(task, completed=True)

        # Convert to Pydantic model for reporting
        findings_dicts = [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence": f.evidence
            } for f in result_dataclass.findings
        ]
        
        logs_dicts = [
            {
                "timestamp": l.timestamp,
                "level": l.level,
                "message": l.message
            } for l in result_dataclass.logs
        ]
        
        result = ScanResult(
            scan_id="cli-scan", # Placeholder
            target=result_dataclass.target,
            status="done",
            score=result_dataclass.score,
            grade=result_dataclass.grade,
            findings=findings_dicts,
            logs=logs_dicts,
            timestamp=result_dataclass.scanned_at,
            response_time_ms=result_dataclass.response_time_ms,
            debug_info=result_dataclass.debug_info,
            scan_status=result_dataclass.scan_status,
            blocking_mechanism=result_dataclass.blocking_mechanism,
            visibility_level=result_dataclass.visibility_level
        )
        
        # Display Summary Table
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Grade", f"[bold {get_grade_color(result.grade)}]{result.grade}[/]")
        table.add_row("Score", f"{result.score}/100")
        table.add_row("Findings", str(len(result.findings)))
        table.add_row("Duration", f"{result.response_time_ms/1000:.2f}s")
        
        console.print(table)
        console.print("\n")

        # AI Analysis
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            ai_task = progress.add_task(description="[cyan]Running AI Analysis...[/cyan]", total=None)
            try:
                # Prepare data
                ai_input = result.debug_info.copy() if result.debug_info else {}
                ai_input.update({
                    "target": result.target,
                    "grade": result.grade,
                    "score": result.score,
                    "scan_status": result.scan_status,
                    "blocking_mechanism": result.blocking_mechanism,
                    "visibility_level": result.visibility_level,
                    "findings": [f.model_dump() for f in result.findings]
                })
                
                ai_view = build_ai_scan_view(ai_input)
                
                system_prompt = AI_REPORT_SYSTEM_PROMPT
                user_prompt = f"Here is the scan result for {ai_input.get('target')}:\n{json.dumps(ai_view, indent=2)}\n\nAnalyze this data and provide the security report in the requested JSON format.\nIMPORTANT: Ensure all backslashes in strings are double-escaped (e.g. use '\\\\' for a literal backslash). Do not output invalid JSON escape sequences."
                
                response_generator = await analyzer.analyze(system_prompt, user_prompt)
                
                full_response = ""
                async for chunk in response_generator:
                    full_response += chunk
                    
                ai_summary = parse_ai_json(full_response)
                result.ai_analysis = ai_summary
                progress.update(ai_task, completed=True)
                console.print("[bold green]✓ AI Analysis Complete[/bold green]")
                
            except Exception as e:
                progress.update(ai_task, completed=True)
                console.print(f"[bold red]✗ AI Analysis Failed:[/bold red] {e}")
        
        # Exports
        console.print(Panel("Generating Reports...", style="dim"))
        if json_out:
            with open(json_out, "w") as f:
                f.write(generate_json(result))
            console.print(f"[green]✓[/green] JSON report saved to [bold]{json_out}[/bold]")
            
        if pdf_out:
            if result.ai_analysis:
                pdf_bytes = generate_ai_pdf(result, result.ai_analysis)
            else:
                pdf_bytes = generate_pdf(result)
            with open(pdf_out, "wb") as f:
                f.write(pdf_bytes)
            console.print(f"[green]✓[/green] PDF report saved to [bold]{pdf_out}[/bold]")
            console.print(f"\n[dim]Tip: If running in Docker, retrieve the file with:[/dim]")
            console.print(f"[dim]docker compose cp scanner:/app/{pdf_out} ~/Downloads/{pdf_out}[/dim]")
            
        if markdown_out:
            with open(markdown_out, "w") as f:
                f.write(generate_markdown(result))
            console.print(f"[green]✓[/green] Markdown report saved to [bold]{markdown_out}[/bold]")
            
    except Exception as e:
        console.print(f"[bold red]Scan failed:[/bold red] {e}")
        raise typer.Exit(code=1)

def get_grade_color(grade):
    if grade in ["A", "B"]: return "green"
    if grade in ["C", "D"]: return "yellow"
    return "red"

@app.command()
def scan(
    target: Optional[str] = typer.Argument(None, help="Target URL or IP to scan"),
    json_out: Optional[Path] = typer.Option(None, "--json-out", help="Path to save JSON report"),
    pdf_out: Optional[Path] = typer.Option(None, "--pdf-out", help="Path to save PDF report"),
    markdown_out: Optional[Path] = typer.Option(None, "--markdown-out", help="Path to save Markdown report"),
):
    """
    Run a security scan against a target.
    """
    # Workaround for typer sometimes capturing the command name as argument
    if target == "scan":
        target = None

    if not target:
        print_banner()
        target = typer.prompt("Enter target URL or IP")
        
    asyncio.run(run_scan_async(target, json_out, pdf_out, markdown_out))

if __name__ == "__main__":
    app()
