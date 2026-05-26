import typer
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from pathlib import Path
from typing import List

from .scanner import Scanner
from .detector import Detector, Finding

app = typer.Typer(help="helpfulGremlin: Sanity check your repo for secrets before you push.")

console = Console()

def scan_file_worker(file_path: Path) -> List[Finding]:
    """Worker function to scan a single file."""
    detector = Detector() # Lightweight enough to init per process
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return detector.scan_file(file_path, f.read())
    except Exception:
        pass # Worker shouldn't crash main process
    return []

@app.command()
def scan(
    path: Path = typer.Argument(
        ".", 
        help="Path to the directory to scan. Defaults to current directory."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show all files scanned."
    ),
    workers: int = typer.Option(
        None, "--workers", "-w", help="Number of worker processes."
    ),
):
    """
    Scans the directory for secrets and sensitive artifacts.
    """
    
    console.print(Panel.fit("👾 helpfulGremlin v0.1.4 is checking your vibes... ", style="bold purple"))
    
    scanner = Scanner(path)
    issues: List[Finding] = []
    scanned_count = 0
    base_path = path if path.is_dir() else path.parent

    with Progress(
        SpinnerColumn(),
        # TextColumn("[progress.description]{task.description}"), # Simplify for speed
        TextColumn("[green]Files scanned: {task.completed}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        task_id = progress.add_task("[green]Scanning...", total=None)
        
        # Use ProcessPoolExecutor for CPU-bound regex scanning
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
            # We keep 'futures' map or just submit and yield
            # Since we don't know total file count upfront easily, we stream submission
            
            # Note: submitting 100k tasks might choke memory.
            # Ideally we'd batch or semaphore, but let's stick to simple submission for now.
            # Python's executor handles queueing.
            
            future_to_file = {}
            for file_path in scanner.walk():
                future = executor.submit(scan_file_worker, file_path)
                future_to_file[future] = file_path
                
                # To keep UI responsive, we could check for completed futures here,
                # but as_completed is easier if we submit all. 
                # For very large repos, chunking submission is better.
                # Let's optimize: Submit all (assuming < 1M files it's fine for RAM)
            
            for future in concurrent.futures.as_completed(future_to_file):
                scanned_count += 1
                progress.update(task_id, advance=1)
                
                file_path = future_to_file[future]
                if verbose:
                     console.log(f"Scanned {file_path}")

                try:
                    file_issues = future.result()
                    issues.extend(file_issues)
                except Exception as e:
                    console.log(f"[red]Error scanning {file_path}: {e}")

    if not issues:
        console.print(Panel(f"✅ Scan complete. {scanned_count} files checked. No issues found. Your vibes are immaculate.", style="green"))
        return

    # Report Issues using Table (same as before)
    table = Table(title=f"🚨 Found {len(issues)} Potential Issues", show_lines=True)
    table.add_column("Location", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("Category", style="magenta")
    table.add_column("Issue Type", style="bold red")
    table.add_column("Snippet", style="yellow")
    table.add_column("Suggestion", style="green")

    for finding in issues:
        try:
            rel_path = finding.file_path.relative_to(base_path)
        except ValueError:
            rel_path = finding.file_path
        location = f"{rel_path}:{finding.line_no}" if finding.line_no else str(rel_path)
        table.add_row(
            location,
            finding.severity,
            finding.category,
            finding.name,
            finding.snippet,
            finding.remediation,
        )

    console.print(table)
    console.print("\n[bold]Finding details[/bold]")
    for finding in issues:
        console.print(f"- {finding.severity} {finding.category}: {finding.name}")
    console.print("\n[bold red]⚠️  Please review the above issues before pushing![/bold red]")
    raise typer.Exit(code=1)

def main():
    app()

if __name__ == "__main__":
    main()
