"""Output formatting utilities"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from typing import Dict, List, Any

class OutputFormatter:
    """Formats output for terminal display"""

    def __init__(self):
        self.console = Console()

    def print_panel(self, content: str, title: str = "", border_style: str = "cyan"):
        """Print content in a bordered panel"""
        self.console.print(Panel(content, title=title, border_style=border_style))

    def print_markdown(self, content: str):
        """Print markdown formatted content"""
        md = Markdown(content)
        self.console.print(md)

    def print_table(self, headers: List[str], rows: List[List[str]], title: str = ""):
        """Print a formatted table"""
        table = Table(title=title, show_header=True, header_style="bold cyan")

        for header in headers:
            table.add_column(header)

        for row in rows:
            table.add_row(*[str(cell) for cell in row])

        self.console.print(table)

    def print_success(self, message: str):
        """Print success message"""
        self.console.print(f"[bold green]✓[/bold green] {message}")

    def print_error(self, message: str):
        """Print error message"""
        self.console.print(f"[bold red]✗[/bold red] {message}")

    def print_warning(self, message: str):
        """Print warning message"""
        self.console.print(f"[bold yellow]⚠[/bold yellow] {message}")

    def print_info(self, message: str):
        """Print info message"""
        self.console.print(f"[bold blue]ℹ[/bold blue] {message}")

    def format_command_output(self, command: str, output: str, success: bool) -> str:
        """Format command execution output"""
        status = "[bold green]SUCCESS[/bold green]" if success else "[bold red]FAILED[/bold red]"
        return f"""
Command: [cyan]{command}[/cyan]
Status: {status}

Output:
{output}
"""

    def format_target_info(self, target: Dict[str, Any]) -> str:
        """Format target information"""
        lines = []
        lines.append(f"[bold]Target ID:[/bold] {target.get('id', 'N/A')}")
        lines.append(f"[bold]Host:[/bold] {target.get('host', 'N/A')}")
        lines.append(f"[bold]Ports:[/bold] {target.get('ports', 'N/A')}")
        lines.append(f"[bold]Description:[/bold] {target.get('description', 'N/A')}")
        lines.append(f"[bold]Status:[/bold] {target.get('status', 'N/A')}")
        return "\n".join(lines)
