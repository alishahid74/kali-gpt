"""Menu Display Module"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from typing import List, Dict

class MenuDisplay:
    """Handles menu display and user interaction"""

    def __init__(self):
        self.console = Console()

    def display_main_menu(self, current_mode: str = "general"):
        """Display the main menu"""
        menu = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
        menu.add_column("Option", style="cyan", width=4)
        menu.add_column("Description", style="white")

        menu.add_row("1", "AI-Assisted Question/Task")
        menu.add_row("2", "Quick Command Generation")
        menu.add_row("3", "Execute Command with AI Analysis")
        menu.add_row("4", "Tool Workflow Builder")
        menu.add_row("5", "Change Security Profile")
        menu.add_row("6", "Advanced Payload Generator")
        menu.add_row("7", "Analyze Output")
        menu.add_row("8", "Show Conversation History")
        menu.add_row("9", "Settings & Configuration")
        menu.add_row("", "")
        menu.add_row("10", "🎯 Target Management")
        menu.add_row("11", "🔍 Vulnerability Scanner")
        menu.add_row("12", "📊 Generate Report")
        menu.add_row("13", "🛡️ Metasploit Integration")
        menu.add_row("14", "🌐 Vulnerability Database Lookup")
        menu.add_row("15", "🔌 Plugin Management")
        menu.add_row("16", "👥 Team Collaboration")
        menu.add_row("", "")
        menu.add_row("0", "[bold red]Exit[/bold red]")

        title = f"🎯 KALI GPT ADVANCED - Mode: [bold yellow]{current_mode.upper()}[/bold yellow]"
        self.console.print(Panel(menu, title=title, border_style="cyan"))

    def display_profile_menu(self, profiles: Dict):
        """Display security profile selection menu"""
        menu = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
        menu.add_column("ID", style="cyan", width=4)
        menu.add_column("Profile", style="white")
        menu.add_column("Description", style="dim")

        for i, (profile_id, profile) in enumerate(profiles.items(), 1):
            menu.add_row(
                str(i),
                profile.get("name", profile_id),
                profile.get("description", "")
            )

        self.console.print(Panel(menu, title="🔧 Security Profiles", border_style="cyan"))

    def display_target_list(self, targets: List[Dict]):
        """Display list of targets"""
        if not targets:
            self.console.print("[yellow]No targets configured[/yellow]")
            return

        table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
        table.add_column("ID", style="cyan", width=10)
        table.add_column("Host", style="white")
        table.add_column("Ports", style="yellow")
        table.add_column("Status", style="green")
        table.add_column("Findings", style="red")

        for target in targets:
            table.add_row(
                target.get("id", ""),
                target.get("host", ""),
                target.get("ports", ""),
                target.get("status", ""),
                str(len(target.get("findings", [])))
            )

        self.console.print(Panel(table, title="🎯 Targets", border_style="cyan"))

    def display_scan_results(self, results: Dict):
        """Display scan results"""
        if not results.get("success"):
            self.console.print(f"[red]Scan failed: {results.get('error', 'Unknown error')}[/red]")
            return

        hosts = results.get("hosts", [])

        for host in hosts:
            host_panel = Table(show_header=True, box=box.SIMPLE)
            host_panel.add_column("Port", style="cyan", width=8)
            host_panel.add_column("State", style="green", width=10)
            host_panel.add_column("Service", style="yellow")
            host_panel.add_column("Version", style="white")

            for port in host.get("ports", []):
                host_panel.add_row(
                    f"{port.get('port')}/{port.get('protocol')}",
                    port.get("state", ""),
                    port.get("service", ""),
                    port.get("version", "")
                )

            title = f"Host: {host.get('ip')} ({host.get('hostname', 'N/A')}) - OS: {host.get('os', 'Unknown')}"
            self.console.print(Panel(host_panel, title=title, border_style="green"))

    def display_vulnerability_info(self, cve_data: Dict):
        """Display CVE/vulnerability information"""
        if not cve_data:
            self.console.print("[yellow]No vulnerability data found[/yellow]")
            return

        info_text = f"""[bold]CVE ID:[/bold] {cve_data.get('id', 'N/A')}

[bold]Description:[/bold]
{cve_data.get('description', 'No description available')}

[bold]Published:[/bold] {cve_data.get('published', 'N/A')}
[bold]Modified:[/bold] {cve_data.get('modified', 'N/A')}

[bold]CVSS v3 Score:[/bold] {cve_data.get('cvss_v3', {}).get('score', 'N/A')} ({cve_data.get('cvss_v3', {}).get('severity', 'N/A')})
[bold]CVSS v2 Score:[/bold] {cve_data.get('cvss_v2', {}).get('score', 'N/A')}

[bold]CWE:[/bold] {', '.join(cve_data.get('cwe', [])) or 'N/A'}
"""

        self.console.print(Panel(info_text, title="🔍 Vulnerability Details", border_style="red"))

        # Display references
        refs = cve_data.get('references', [])
        if refs:
            self.console.print("\n[bold]References:[/bold]")
            for ref in refs[:5]:  # Show first 5
                self.console.print(f"  • {ref.get('url', '')}")

    def display_plugin_list(self, plugins: List[Dict]):
        """Display list of plugins"""
        if not plugins:
            self.console.print("[yellow]No plugins loaded[/yellow]")
            return

        table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
        table.add_column("ID", style="cyan", width=15)
        table.add_column("Name", style="white")
        table.add_column("Version", style="yellow", width=10)
        table.add_column("Status", style="green", width=10)

        for plugin in plugins:
            status = "✓ Enabled" if plugin.get("enabled") else "✗ Disabled"
            status_color = "green" if plugin.get("enabled") else "red"

            table.add_row(
                plugin.get("id", ""),
                plugin.get("name", ""),
                plugin.get("version", ""),
                f"[{status_color}]{status}[/{status_color}]"
            )

        self.console.print(Panel(table, title="🔌 Plugins", border_style="cyan"))

    def display_settings(self, config: Dict):
        """Display current settings"""
        settings_text = f"""[bold]AI Model:[/bold] {config.get('model', 'N/A')}
[bold]Temperature:[/bold] {config.get('temperature', 'N/A')}
[bold]Max Tokens:[/bold] {config.get('max_tokens', 'N/A')}
[bold]Require Confirmation:[/bold] {config.get('require_confirmation', 'N/A')}
[bold]Auto Copy:[/bold] {config.get('auto_copy', 'N/A')}
[bold]Save History:[/bold] {config.get('save_history', 'N/A')}
[bold]Max History:[/bold] {config.get('max_history', 'N/A')}

[bold cyan]Metasploit:[/bold cyan]
  Enabled: {config.get('metasploit', {}).get('enabled', False)}

[bold cyan]Vulnerability DB:[/bold cyan]
  Enabled: {config.get('vulnerability_db', {}).get('enabled', False)}
  Auto Update: {config.get('vulnerability_db', {}).get('auto_update', False)}

[bold cyan]Scanner:[/bold cyan]
  Enabled: {config.get('scanner', {}).get('enabled', False)}
  Default Scanner: {config.get('scanner', {}).get('default_scanner', 'N/A')}

[bold cyan]Collaboration:[/bold cyan]
  Enabled: {config.get('collaboration', {}).get('enabled', False)}

[bold cyan]Plugins:[/bold cyan]
  Enabled: {config.get('plugins', {}).get('enabled', False)}
  Auto Load: {config.get('plugins', {}).get('auto_load', False)}
"""

        self.console.print(Panel(settings_text, title="⚙️ Settings", border_style="cyan"))

    def prompt_choice(self, prompt_text: str, default: str = "") -> str:
        """Prompt user for input"""
        if default:
            return self.console.input(f"\n[cyan]{prompt_text}[/cyan] [dim](default: {default})[/dim]: ") or default
        return self.console.input(f"\n[cyan]{prompt_text}[/cyan]: ")

    def confirm(self, message: str) -> bool:
        """Ask for yes/no confirmation"""
        response = self.console.input(f"\n[yellow]{message}[/yellow] (yes/no): ").lower()
        return response in ["yes", "y"]

    def show_error(self, message: str):
        """Display error message"""
        self.console.print(f"\n[bold red]Error:[/bold red] {message}\n")

    def show_success(self, message: str):
        """Display success message"""
        self.console.print(f"\n[bold green]Success:[/bold green] {message}\n")

    def show_warning(self, message: str):
        """Display warning message"""
        self.console.print(f"\n[bold yellow]Warning:[/bold yellow] {message}\n")

    def show_info(self, message: str):
        """Display info message"""
        self.console.print(f"\n[bold blue]Info:[/bold blue] {message}\n")
