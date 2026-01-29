import typer
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from pathlib import Path
from typing import List, Tuple

from .scanner import Scanner
from .detector import Detector, SecretPattern

app = typer.Typer(help="helpfulGremlin: Sanity check your repo for secrets before you push.")
def get_remediation(pattern: SecretPattern, file_path: Path) -> str:
    """Generate smart remediation advice based on context."""
    fname = file_path.name.lower()
    
    if ".env" in fname:
        return "CRITICAL: Stop tracking this file. Run `git rm --cached .env` and add to .gitignore."
    
    if "key" in pattern.name.lower() or "token" in pattern.name.lower():
        return "Revoke key immediately. Load via `os.environ`."
        
    if "private key" in pattern.name.lower():
        return "Rotate key. Never commit PEM files."
        
    if "entropy" in pattern.name.lower():
        return "Verify if secret. If yes, move to env vars."
        
    return "Check and remove."

console = Console()

# ... existing imports ...

def scan_file_worker(file_path: Path) -> List[Tuple[Path, int, SecretPattern, str]]:
    """Worker function to scan a single file."""
    issues = []
    detector = Detector() # Lightweight enough to init per process
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                match = detector.check_line(line)
                if match:
                    content_snippet = line.strip()
                    if len(content_snippet) > 50:
                        content_snippet = content_snippet[:50] + "..."
                    issues.append((file_path, i, match, content_snippet))
    except Exception:
        pass # Worker shouldn't crash main process
    return issues

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
    
    console.print(Panel.fit("👾 helpfulGremlin v0.1.2 is checking your vibes... ", style="bold purple"))
    
    scanner = Scanner(path)
    issues: List[Tuple[Path, int, SecretPattern, str]] = []
    scanned_count = 0

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
    table.add_column("Issue Type", style="bold red")
    table.add_column("Snippet", style="yellow")
    table.add_column("Suggestion", style="green")

    for file_path, line_no, pattern, snippet in issues:
        rel_path = file_path.relative_to(path)
        table.add_row(
            f"{rel_path}:{line_no}",
            pattern.name,
            snippet,
            get_remediation(pattern, file_path)
        )

    console.print(table)
    console.print("\n[bold red]⚠️  Please review the above issues before pushing![/bold red]")
    raise typer.Exit(code=1)

def main():
    app()

if __name__ == "__main__":
    main()
