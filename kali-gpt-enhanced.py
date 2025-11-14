#!/usr/bin/env python3
"""
Kali GPT Advanced - Enhanced Version 2.0
Professional Red Team AI Assistant with Advanced Features

Features:
- Modular architecture
- Metasploit Framework integration
- Custom tool profiles
- Report generation (HTML, Markdown, JSON)
- Multi-target management
- Plugin system
- Team collaboration
- Automated vulnerability scanning
- Vulnerability database integration (NVD, CVE, ExploitDB)
"""

import os
import sys
from pathlib import Path

# Add the kali_gpt module to the path
sys.path.insert(0, str(Path(__file__).parent))

from kali_gpt.core.config import ConfigManager
from kali_gpt.modules.ai_service import AIService
from kali_gpt.modules.command_executor import CommandExecutor
from kali_gpt.modules.profile_manager import ProfileManager
from kali_gpt.modules.history_manager import HistoryManager
from kali_gpt.modules.report_generator import ReportGenerator
from kali_gpt.modules.target_manager import TargetManager
from kali_gpt.integrations.metasploit import MetasploitIntegration
from kali_gpt.integrations.vulnerability_db import VulnerabilityDatabase
from kali_gpt.integrations.scanner import ScannerManager
from kali_gpt.integrations.collaboration import CollaborationManager
from kali_gpt.plugins.plugin_manager import PluginManager
from kali_gpt.ui.menu import MenuDisplay
from kali_gpt.ui.colors import ColorScheme
from kali_gpt.utils.formatters import OutputFormatter

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
import pyperclip
from dotenv import load_dotenv

class KaliGPTEnhanced:
    """Enhanced Kali GPT with modular architecture and advanced features"""

    def __init__(self):
        """Initialize the enhanced application"""
        # Load environment variables
        load_dotenv()

        # Check for API key
        if not os.getenv("OPENAI_API_KEY"):
            print("ERROR: OPENAI_API_KEY not found in environment")
            print("Please set your API key in .env file or environment")
            sys.exit(1)

        # Initialize console and UI
        self.console = Console()
        self.menu = MenuDisplay()
        self.formatter = OutputFormatter()

        # Initialize configuration
        self.config = ConfigManager()

        # Initialize core modules
        self.ai = AIService(self.config)
        self.executor = CommandExecutor(self.config)
        self.profiles = ProfileManager(self.config)
        self.history = HistoryManager(self.config)
        self.targets = TargetManager(self.config)

        # Initialize report generator
        self.reports = ReportGenerator(self.config, self.history)

        # Initialize integrations
        self.metasploit = MetasploitIntegration(self.config)
        self.vuln_db = VulnerabilityDatabase(self.config)
        self.scanner = ScannerManager(self.config, self.executor)
        self.collaboration = CollaborationManager(self.config, self.history)

        # Initialize plugin system
        self.plugins = PluginManager(self.config)
        self.plugins.initialize_plugins(self)

        # Current profile
        self.current_profile = "general"

        # Display banner
        self.display_banner()

    def display_banner(self):
        """Display application banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██╗  ██╗ █████╗ ██╗     ██╗     ██████╗ ██████╗ ████████╗      ║
║   ██║ ██╔╝██╔══██╗██║     ██║    ██╔════╝ ██╔══██╗╚══██╔══╝      ║
║   █████╔╝ ███████║██║     ██║    ██║  ███╗██████╔╝   ██║         ║
║   ██╔═██╗ ██╔══██║██║     ██║    ██║   ██║██╔═══╝    ██║         ║
║   ██║  ██╗██║  ██║███████╗██║    ╚██████╔╝██║        ██║         ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═════╝ ╚═╝        ╚═╝         ║
║                                                                   ║
║           Professional Red Team AI Assistant - Enhanced          ║
║                          Version 2.0                              ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

[bold cyan]New Features:[/bold cyan]
✓ Metasploit Framework Integration    ✓ Custom Tool Profiles
✓ Advanced Report Generation           ✓ Multi-Target Management
✓ Plugin System                        ✓ Team Collaboration
✓ Automated Vulnerability Scanning     ✓ Vulnerability Database Integration

[dim]Type 'help' for instructions or select an option from the menu[/dim]
"""
        self.console.print(banner)

    def run(self):
        """Main application loop"""
        while True:
            try:
                self.menu.display_main_menu(self.current_profile)
                choice = input("\n[?] Select option: ").strip()

                if choice == "0":
                    self.shutdown()
                    break
                elif choice == "1":
                    self.ai_assisted_task()
                elif choice == "2":
                    self.quick_command_generation()
                elif choice == "3":
                    self.execute_with_analysis()
                elif choice == "4":
                    self.tool_workflow_builder()
                elif choice == "5":
                    self.change_profile()
                elif choice == "6":
                    self.payload_generator()
                elif choice == "7":
                    self.analyze_output()
                elif choice == "8":
                    self.show_history()
                elif choice == "9":
                    self.settings_menu()
                elif choice == "10":
                    self.target_management()
                elif choice == "11":
                    self.vulnerability_scanner()
                elif choice == "12":
                    self.generate_report()
                elif choice == "13":
                    self.metasploit_menu()
                elif choice == "14":
                    self.vulnerability_lookup()
                elif choice == "15":
                    self.plugin_management()
                elif choice == "16":
                    self.collaboration_menu()
                else:
                    self.console.print("[red]Invalid option[/red]")

            except KeyboardInterrupt:
                print("\n")
                if self.menu.confirm("Do you want to exit?"):
                    self.shutdown()
                    break
            except Exception as e:
                self.menu.show_error(f"An error occurred: {str(e)}")

    def ai_assisted_task(self):
        """AI-assisted question or task"""
        user_input = self.menu.prompt_choice("Enter your question or task")

        if not user_input:
            return

        # Get current profile prompt
        profile_prompt = self.profiles.get_profile_prompt(self.current_profile)

        # Ask AI
        response = self.ai.ask(user_input, system_prompt=profile_prompt)

        # Display response
        self.console.print(Panel(Markdown(response), title="AI Response", border_style="green"))

        # Auto-copy if enabled
        if self.config.get("auto_copy", True):
            try:
                pyperclip.copy(response)
                self.console.print("[dim]Response copied to clipboard[/dim]")
            except:
                pass

        # Log interaction
        self.history.log_interaction(user_input, response, mode=self.current_profile)

    def quick_command_generation(self):
        """Quick command generation"""
        task = self.menu.prompt_choice("Describe what you want to accomplish")

        if not task:
            return

        target = self.menu.prompt_choice("Target (optional)", "")

        # Generate command
        result = self.ai.generate_command(task, target)

        # Display result
        self.console.print(Panel(Markdown(result['full_response']), title="Generated Command", border_style="cyan"))

        # Ask if user wants to execute
        if result['command'] and self.menu.confirm("Execute this command?"):
            exec_result = self.executor.execute(result['command'])
            self.console.print(Panel(exec_result['output'], title="Output", border_style="green" if exec_result['success'] else "red"))

            # AI analysis of output
            if exec_result['success']:
                analysis = self.ai.analyze_output(result['command'], exec_result['output'])
                self.console.print(Panel(Markdown(analysis), title="AI Analysis", border_style="yellow"))

    def execute_with_analysis(self):
        """Execute command with AI analysis"""
        command = self.menu.prompt_choice("Enter command to execute")

        if not command:
            return

        # Execute command
        result = self.executor.execute(command)

        # Display output
        self.console.print(Panel(result['output'] if result['success'] else result['error'],
                                title="Command Output",
                                border_style="green" if result['success'] else "red"))

        # AI analysis
        if result['success'] and result['output']:
            analysis = self.ai.analyze_output(command, result['output'])
            self.console.print(Panel(Markdown(analysis), title="AI Analysis", border_style="yellow"))

            # Log
            self.history.log_interaction(
                f"Execute: {command}",
                analysis,
                command=command,
                command_output=result['output'],
                mode=self.current_profile
            )

    def tool_workflow_builder(self):
        """Tool workflow builder"""
        self.console.print("[cyan]Tool Workflow Builder[/cyan]")
        objective = self.menu.prompt_choice("What is your objective?")

        if not objective:
            return

        workflow_prompt = f"""Create a detailed penetration testing workflow for the following objective:

Objective: {objective}

Provide:
1. Sequential steps with specific Kali Linux commands
2. Expected outputs at each step
3. Decision points based on results
4. Alternative paths if initial attempts fail
5. Commands formatted ready to execute

Format each command on its own line starting with '$'
"""

        response = self.ai.ask(workflow_prompt, include_history=False)
        self.console.print(Panel(Markdown(response), title="Workflow", border_style="cyan"))

        self.history.log_interaction(objective, response, mode=self.current_profile)

    def change_profile(self):
        """Change security profile"""
        profiles = self.profiles.list_profiles()
        self.menu.display_profile_menu(profiles)

        profile_list = list(profiles.keys())
        choice = self.menu.prompt_choice(f"Select profile (1-{len(profile_list)})")

        try:
            index = int(choice) - 1
            if 0 <= index < len(profile_list):
                self.current_profile = profile_list[index]
                profile_name = profiles[self.current_profile]["name"]
                self.menu.show_success(f"Switched to profile: {profile_name}")
            else:
                self.menu.show_error("Invalid selection")
        except ValueError:
            self.menu.show_error("Invalid input")

    def payload_generator(self):
        """Advanced payload generator"""
        if not self.metasploit.is_available():
            self.menu.show_warning("Metasploit not available. Using AI-based payload generation.")

        lhost = self.menu.prompt_choice("Enter LHOST (your IP)")
        lport = self.menu.prompt_choice("Enter LPORT", "4444")
        payload_type = self.menu.prompt_choice("Payload type", "windows/meterpreter/reverse_tcp")

        if self.metasploit.is_available():
            # Generate with msfvenom
            result = self.metasploit.generate_payload(payload_type, lhost, lport, format="raw")

            if result['success']:
                self.menu.show_success("Payload generated successfully")
                self.console.print(Panel(result['command'], title="Command Used", border_style="cyan"))

                # Show handler command
                handler = self.metasploit.start_handler(payload_type, lhost, lport)
                self.console.print(Panel(handler, title="Listener Command", border_style="green"))
            else:
                self.menu.show_error(f"Payload generation failed: {result['error']}")
        else:
            # AI-based payload generation
            prompt = f"""Generate payload code for:
Type: {payload_type}
LHOST: {lhost}
LPORT: {lport}

Provide:
1. Payload code in multiple formats (bash, python, php)
2. Listener setup command
3. Evasion techniques
4. Troubleshooting tips
"""
            response = self.ai.ask(prompt, include_history=False)
            self.console.print(Panel(Markdown(response), title="AI-Generated Payload", border_style="magenta"))

    def analyze_output(self):
        """Analyze command output"""
        self.console.print("[cyan]Paste command output (press Ctrl+D when done):[/cyan]")

        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass

        output = "\n".join(lines)

        if not output.strip():
            return

        command = self.menu.prompt_choice("What command generated this output? (optional)", "")

        analysis = self.ai.analyze_output(command or "Unknown", output)
        self.console.print(Panel(Markdown(analysis), title="Analysis", border_style="yellow"))

    def show_history(self):
        """Show conversation history"""
        recent = self.history.get_recent_conversations(5)

        if not recent:
            self.console.print("[yellow]No conversation history[/yellow]")
            return

        for i, conv in enumerate(recent, 1):
            self.console.print(f"\n[bold cyan]#{i} - {conv['timestamp']} [{conv['mode']}][/bold cyan]")
            self.console.print(f"[dim]User:[/dim] {conv['user'][:100]}...")
            self.console.print(f"[dim]AI:[/dim] {conv['assistant'][:100]}...")

    def settings_menu(self):
        """Settings and configuration menu"""
        self.menu.display_settings(self.config.config)

        self.console.print("\n[cyan]Update Settings:[/cyan]")
        self.console.print("1. AI Model Settings")
        self.console.print("2. Integration Settings")
        self.console.print("3. Reset to Defaults")
        self.console.print("0. Back")

        choice = self.menu.prompt_choice("Select option")

        if choice == "1":
            model = self.menu.prompt_choice("Model", self.config.get("model"))
            temp = self.menu.prompt_choice("Temperature (0-1)", str(self.config.get("temperature")))
            max_tokens = self.menu.prompt_choice("Max Tokens", str(self.config.get("max_tokens")))

            self.config.set("model", model)
            self.config.set("temperature", float(temp))
            self.config.set("max_tokens", int(max_tokens))
            self.menu.show_success("AI settings updated")

        elif choice == "2":
            msf = self.menu.confirm("Enable Metasploit integration?")
            scanner = self.menu.confirm("Enable vulnerability scanner?")
            vuln_db = self.menu.confirm("Enable vulnerability database?")
            collab = self.menu.confirm("Enable collaboration features?")

            self.config.set("metasploit.enabled", msf)
            self.config.set("scanner.enabled", scanner)
            self.config.set("vulnerability_db.enabled", vuln_db)
            self.config.set("collaboration.enabled", collab)
            self.menu.show_success("Integration settings updated")

        elif choice == "3":
            if self.menu.confirm("Reset all settings to defaults?"):
                self.config.reset_to_defaults()
                self.menu.show_success("Settings reset to defaults")

    def target_management(self):
        """Target management menu"""
        while True:
            self.console.print("\n[bold cyan]Target Management[/bold cyan]")
            self.console.print("1. List Targets")
            self.console.print("2. Add Target")
            self.console.print("3. Set Active Target")
            self.console.print("4. View Target Details")
            self.console.print("5. Add Finding to Target")
            self.console.print("0. Back")

            choice = self.menu.prompt_choice("Select option")

            if choice == "0":
                break
            elif choice == "1":
                targets = self.targets.list_targets()
                self.menu.display_target_list(targets)
            elif choice == "2":
                host = self.menu.prompt_choice("Target host (IP or domain)")
                ports = self.menu.prompt_choice("Ports (optional)", "")
                desc = self.menu.prompt_choice("Description (optional)", "")

                target_id = self.targets.add_target(host, ports, desc)
                self.menu.show_success(f"Target added with ID: {target_id}")
            elif choice == "3":
                target_id = self.menu.prompt_choice("Target ID")
                if self.targets.set_active_target(target_id):
                    self.menu.show_success(f"Active target set to: {target_id}")
                else:
                    self.menu.show_error("Target not found")
            elif choice == "4":
                target_id = self.menu.prompt_choice("Target ID")
                target = self.targets.get_target(target_id)
                if target:
                    info = self.formatter.format_target_info(target)
                    self.console.print(Panel(info, title=f"Target: {target_id}", border_style="cyan"))
                else:
                    self.menu.show_error("Target not found")
            elif choice == "5":
                target_id = self.menu.prompt_choice("Target ID")
                title = self.menu.prompt_choice("Finding title")
                desc = self.menu.prompt_choice("Description")
                severity = self.menu.prompt_choice("Severity (low/medium/high/critical)", "medium")

                if self.targets.add_finding(target_id, title, desc, severity):
                    self.menu.show_success("Finding added")
                else:
                    self.menu.show_error("Failed to add finding")

    def vulnerability_scanner(self):
        """Vulnerability scanner menu"""
        self.console.print("\n[bold cyan]Vulnerability Scanner[/bold cyan]")
        self.console.print(f"Available scanners: {', '.join(self.scanner.get_available_scanners())}")

        target = self.menu.prompt_choice("Target IP/hostname")
        scan_type = self.menu.prompt_choice("Scan type (quick/full/stealth/vuln)", "quick")

        self.console.print(f"\n[yellow]Starting {scan_type} scan on {target}...[/yellow]")

        results = self.scanner.nmap_scan(target, scan_type)

        if results.get("success"):
            self.menu.display_scan_results(results)

            # Ask if user wants AI analysis
            if self.menu.confirm("Get AI analysis of results?"):
                analysis = self.ai.analyze_output(f"nmap {scan_type} scan", results.get("raw_output", ""))
                self.console.print(Panel(Markdown(analysis), title="AI Analysis", border_style="yellow"))
        else:
            self.menu.show_error(f"Scan failed: {results.get('error')}")

    def generate_report(self):
        """Generate penetration testing report"""
        self.console.print("\n[bold cyan]Report Generation[/bold cyan]")
        self.console.print("1. HTML Report")
        self.console.print("2. Markdown Report")
        self.console.print("3. JSON Report")

        choice = self.menu.prompt_choice("Select format")

        title = self.menu.prompt_choice("Report title", "Penetration Testing Report")

        report_file = None

        if choice == "1":
            report_file = self.reports.generate_html_report(title=title)
        elif choice == "2":
            report_file = self.reports.generate_markdown_report(title=title)
        elif choice == "3":
            report_file = self.reports.generate_json_report()
        else:
            self.menu.show_error("Invalid choice")
            return

        if report_file:
            self.menu.show_success(f"Report generated: {report_file}")

    def metasploit_menu(self):
        """Metasploit integration menu"""
        if not self.metasploit.is_available():
            self.menu.show_error("Metasploit Framework is not available on this system")
            return

        self.console.print(f"\n[bold cyan]Metasploit Integration[/bold cyan]")
        self.console.print(f"Version: {self.metasploit.check_version()}")
        self.console.print("\n1. Search Exploits")
        self.console.print("2. Search Auxiliary Modules")
        self.console.print("3. List Payloads")
        self.console.print("4. Generate Payload")
        self.console.print("0. Back")

        choice = self.menu.prompt_choice("Select option")

        if choice == "1":
            query = self.menu.prompt_choice("Search query (CVE, platform, etc.)")
            exploits = self.metasploit.search_exploits(query)

            if exploits:
                for i, exploit in enumerate(exploits[:10], 1):
                    self.console.print(f"{i}. {exploit.get('name')} - {exploit.get('description', '')[:80]}")
            else:
                self.console.print("[yellow]No exploits found[/yellow]")

        elif choice == "2":
            query = self.menu.prompt_choice("Search query")
            modules = self.metasploit.search_auxiliary(query)

            if modules:
                for i, module in enumerate(modules[:10], 1):
                    self.console.print(f"{i}. {module.get('name')} - {module.get('description', '')[:80]}")
            else:
                self.console.print("[yellow]No modules found[/yellow]")

        elif choice == "3":
            platform = self.menu.prompt_choice("Platform filter (optional)", "")
            payloads = self.metasploit.list_payloads(platform)

            for payload in payloads[:20]:
                self.console.print(f"  • {payload}")

            self.console.print(f"\n[dim]Showing first 20 of {len(payloads)} payloads[/dim]")

        elif choice == "4":
            self.payload_generator()

    def vulnerability_lookup(self):
        """Vulnerability database lookup"""
        self.console.print("\n[bold cyan]Vulnerability Database Lookup[/bold cyan]")
        self.console.print("1. CVE Lookup")
        self.console.print("2. Search Vulnerabilities")
        self.console.print("3. Recent Vulnerabilities")
        self.console.print("4. Check Service Vulnerabilities")
        self.console.print("0. Back")

        choice = self.menu.prompt_choice("Select option")

        if choice == "1":
            cve_id = self.menu.prompt_choice("Enter CVE ID (e.g., CVE-2021-44228)")
            cve_data = self.vuln_db.lookup_cve(cve_id)

            if cve_data:
                self.menu.display_vulnerability_info(cve_data)

                # Check for exploits
                exploit_info = self.vuln_db.get_exploit_availability(cve_id)
                if exploit_info.get("exploits_available"):
                    self.console.print("\n[bold red]Public exploits available![/bold red]")
                    for exploit_url in exploit_info.get("public_exploits", []):
                        self.console.print(f"  • {exploit_url}")
            else:
                self.menu.show_error("CVE not found")

        elif choice == "2":
            keyword = self.menu.prompt_choice("Search keyword")
            results = self.vuln_db.search_vulnerabilities(keyword, limit=10)

            if results:
                for vuln in results:
                    severity_color = ColorScheme.get_severity_color(vuln.get("severity", "UNKNOWN"))
                    self.console.print(f"\n[{severity_color}]{vuln.get('id')}[/{severity_color}] - Score: {vuln.get('cvss_score', 'N/A')}")
                    self.console.print(f"  {vuln.get('description', '')}")
            else:
                self.console.print("[yellow]No vulnerabilities found[/yellow]")

        elif choice == "3":
            days = int(self.menu.prompt_choice("Days to look back", "7"))
            recent = self.vuln_db.get_recent_vulnerabilities(days=days, limit=10)

            if recent:
                for vuln in recent:
                    severity_color = ColorScheme.get_severity_color(vuln.get("severity", "UNKNOWN"))
                    self.console.print(f"\n[{severity_color}]{vuln.get('id')}[/{severity_color}] - Score: {vuln.get('cvss_score', 'N/A')}")
                    self.console.print(f"  Published: {vuln.get('published', 'N/A')}")
                    self.console.print(f"  {vuln.get('description', '')}")
            else:
                self.console.print("[yellow]No recent vulnerabilities found[/yellow]")

        elif choice == "4":
            service = self.menu.prompt_choice("Service name")
            version = self.menu.prompt_choice("Version (optional)", "")

            vulns = self.vuln_db.check_service_vulnerabilities(service, version)

            if vulns:
                self.console.print(f"\n[bold red]Found {len(vulns)} vulnerabilities for {service}[/bold red]")
                for vuln in vulns[:10]:
                    severity_color = ColorScheme.get_severity_color(vuln.get("severity", "UNKNOWN"))
                    self.console.print(f"\n[{severity_color}]{vuln.get('id')}[/{severity_color}] - Score: {vuln.get('cvss_score', 'N/A')}")
                    self.console.print(f"  {vuln.get('description', '')}")
            else:
                self.console.print(f"[green]No known vulnerabilities found for {service}[/green]")

    def plugin_management(self):
        """Plugin management menu"""
        while True:
            plugins = self.plugins.list_plugins()
            self.menu.display_plugin_list(plugins)

            self.console.print("\n1. Enable/Disable Plugin")
            self.console.print("2. Reload Plugin")
            self.console.print("3. Create Plugin Template")
            self.console.print("0. Back")

            choice = self.menu.prompt_choice("Select option")

            if choice == "0":
                break
            elif choice == "1":
                plugin_id = self.menu.prompt_choice("Plugin ID")
                action = self.menu.prompt_choice("Enable or Disable? (e/d)", "e")

                if action.lower() == "e":
                    if self.plugins.enable_plugin(plugin_id):
                        self.menu.show_success(f"Plugin {plugin_id} enabled")
                    else:
                        self.menu.show_error("Plugin not found")
                else:
                    if self.plugins.disable_plugin(plugin_id):
                        self.menu.show_success(f"Plugin {plugin_id} disabled")
                    else:
                        self.menu.show_error("Plugin not found")

            elif choice == "2":
                plugin_id = self.menu.prompt_choice("Plugin ID")
                if self.plugins.reload_plugin(plugin_id):
                    self.menu.show_success(f"Plugin {plugin_id} reloaded")
                else:
                    self.menu.show_error("Failed to reload plugin")

            elif choice == "3":
                plugin_name = self.menu.prompt_choice("Plugin name")
                template_file = self.plugins.create_plugin_template(plugin_name)
                self.menu.show_success(f"Plugin template created: {template_file}")

    def collaboration_menu(self):
        """Team collaboration menu"""
        self.console.print("\n[bold cyan]Team Collaboration[/bold cyan]")
        self.console.print("1. Create Shareable Session")
        self.console.print("2. Export Session")
        self.console.print("3. Import Session")
        self.console.print("4. List Shared Sessions")
        self.console.print("5. Team Activity Summary")
        self.console.print("0. Back")

        choice = self.menu.prompt_choice("Select option")

        if choice == "1":
            name = self.menu.prompt_choice("Session name")
            desc = self.menu.prompt_choice("Description", "")
            include_logs = self.menu.confirm("Include logs?")

            result = self.collaboration.create_session_share(name, desc, include_logs)
            self.menu.show_success(result['message'])

        elif choice == "2":
            session_id = self.menu.prompt_choice("Session ID")
            output_file = self.menu.prompt_choice("Output file name", f"session_{session_id}.json")

            exported = self.collaboration.export_session(session_id, output_file)
            if exported:
                self.menu.show_success(f"Session exported to: {exported}")
            else:
                self.menu.show_error("Failed to export session")

        elif choice == "3":
            session_file = self.menu.prompt_choice("Session file path")
            session_id = self.collaboration.import_session(session_file)

            if session_id:
                self.menu.show_success(f"Session imported with ID: {session_id}")
            else:
                self.menu.show_error("Failed to import session")

        elif choice == "4":
            sessions = self.collaboration.get_shared_sessions()
            if sessions:
                for session in sessions:
                    self.console.print(f"\n[cyan]{session['id']}[/cyan] - {session['name']}")
                    self.console.print(f"  Created: {session['created']}")
            else:
                self.console.print("[yellow]No shared sessions[/yellow]")

        elif choice == "5":
            activity = self.collaboration.get_team_activity()
            self.console.print(f"\nTotal Members: {activity['total_members']}")
            self.console.print(f"Shared Sessions: {activity['shared_sessions']}")
            self.console.print(f"Collaboration: {'Enabled' if activity['collaboration_enabled'] else 'Disabled'}")

    def shutdown(self):
        """Shutdown the application"""
        self.console.print("\n[cyan]Shutting down...[/cyan]")

        # Shutdown plugins
        self.plugins.shutdown_all()

        self.console.print("[green]Thank you for using Kali GPT Enhanced![/green]")


def main():
    """Main entry point"""
    try:
        app = KaliGPTEnhanced()
        app.run()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
