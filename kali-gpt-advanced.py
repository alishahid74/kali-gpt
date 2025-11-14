#!/usr/bin/env python3
"""
Kali GPT Advanced - Enhanced AI-Powered Penetration Testing Assistant
Supports command execution, red team operations, and intelligent workflow automation
"""

import os
import sys
import subprocess
import json
import datetime
import pyperclip
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize
console = Console()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Configuration
CONFIG_DIR = Path.home() / ".kali-gpt"
LOG_FILE = CONFIG_DIR / "interaction_logs.json"
HISTORY_FILE = CONFIG_DIR / "conversation_history.json"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Ensure config directory exists
CONFIG_DIR.mkdir(exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "model": "gpt-4o",
    "temperature": 0.7,
    "max_tokens": 2000,
    "require_confirmation": True,
    "auto_copy": True,
    "save_history": True,
    "max_history": 10
}

class KaliGPTAdvanced:
    def __init__(self):
        self.console = Console()
        self.config = self.load_config()
        self.conversation_history = []
        self.last_response = None
        self.current_mode = "general"
        self.load_history()

        # Security profiles with specialized system prompts
        self.security_profiles = {
            "general": {
                "name": "General Pentesting",
                "prompt": """You are an elite penetration testing assistant specializing in Kali Linux.
                Provide expert-level guidance for ethical hacking, security assessments, and red team operations.
                Always prioritize authorized testing and responsible disclosure.
                When suggesting commands, explain what they do and potential risks."""
            },
            "recon": {
                "name": "Reconnaissance",
                "prompt": """You are a reconnaissance specialist. Focus on information gathering, OSINT,
                network scanning, and enumeration. Suggest tools like nmap, recon-ng, theHarvester,
                amass, subfinder, and provide detailed scanning strategies. Emphasize passive vs active recon."""
            },
            "exploit": {
                "name": "Exploitation",
                "prompt": """You are an exploitation expert. Guide through vulnerability exploitation,
                payload generation, and attack vectors. Focus on Metasploit, exploit-db, searchsploit,
                custom exploits, and privilege escalation. Always verify authorization before exploitation."""
            },
            "web": {
                "name": "Web Application Testing",
                "prompt": """You are a web application security specialist. Focus on OWASP Top 10,
                SQLi, XSS, CSRF, authentication bypass, and web vulnerabilities. Suggest tools like
                burpsuite, sqlmap, nikto, wfuzz, ffuf, and manual testing techniques."""
            },
            "wireless": {
                "name": "Wireless Security",
                "prompt": """You are a wireless security expert. Focus on WiFi cracking, WPA/WPA2/WPA3
                attacks, rogue AP detection, and wireless reconnaissance. Guide on aircrack-ng suite,
                wifite, reaver, and wireless protocol analysis."""
            },
            "post_exploit": {
                "name": "Post-Exploitation",
                "prompt": """You are a post-exploitation specialist. Focus on privilege escalation,
                persistence, lateral movement, data exfiltration, and covering tracks. Guide on
                maintaining access, pivoting, and achieving objectives while remaining undetected."""
            },
            "forensics": {
                "name": "Digital Forensics",
                "prompt": """You are a digital forensics expert. Focus on evidence collection,
                malware analysis, memory forensics, and incident response. Guide on tools like
                volatility, autopsy, sleuthkit, and proper forensic procedures."""
            }
        }

    def load_config(self) -> Dict:
        """Load configuration from file or create default"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        else:
            self.save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG

    def save_config(self, config: Dict):
        """Save configuration to file"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

    def load_history(self):
        """Load conversation history"""
        if HISTORY_FILE.exists() and self.config.get("save_history", True):
            try:
                with open(HISTORY_FILE, 'r') as f:
                    data = json.load(f)
                    self.conversation_history = data.get("history", [])[-self.config.get("max_history", 10):]
            except:
                self.conversation_history = []

    def save_history(self):
        """Save conversation history"""
        if self.config.get("save_history", True):
            with open(HISTORY_FILE, 'w') as f:
                json.dump({"history": self.conversation_history}, f, indent=2)

    def log_interaction(self, user_input: str, ai_response: str, command: Optional[str] = None,
                       command_output: Optional[str] = None):
        """Log interactions to file"""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "mode": self.current_mode,
            "user_input": user_input,
            "ai_response": ai_response,
            "command": command,
            "command_output": command_output
        }

        logs = []
        if LOG_FILE.exists():
            with open(LOG_FILE, 'r') as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []

        logs.append(log_entry)

        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)

    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, any]:
        """Execute shell command with safety checks"""
        # Dangerous commands that require extra confirmation
        dangerous_keywords = ['rm -rf', 'dd if=', 'mkfs', ':(){:|:&};:', 'fork bomb', '> /dev/sda']

        if any(keyword in command.lower() for keyword in dangerous_keywords):
            self.console.print(Panel("[bold red]⚠️  DANGEROUS COMMAND DETECTED![/bold red]",
                                    title="Security Warning"))
            if not Confirm.ask("This command could be destructive. Are you ABSOLUTELY sure?"):
                return {"success": False, "error": "Command cancelled by user", "output": ""}

        if self.config.get("require_confirmation", True):
            self.console.print(Panel(f"[yellow]{command}[/yellow]", title="Execute Command?"))
            if not Confirm.ask("Run this command?"):
                return {"success": False, "error": "Command cancelled by user", "output": ""}

        try:
            self.console.print(f"[cyan]Executing:[/cyan] {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            output = result.stdout + result.stderr
            success = result.returncode == 0

            if output:
                self.console.print(Panel(output, title="Command Output",
                                        border_style="green" if success else "red"))

            return {
                "success": success,
                "output": output,
                "return_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timeout", "output": ""}
        except Exception as e:
            return {"success": False, "error": str(e), "output": ""}

    def ask_gpt(self, prompt_text: str, include_history: bool = True) -> str:
        """Send request to GPT with conversation history"""
        messages = [
            {"role": "system", "content": self.security_profiles[self.current_mode]["prompt"]}
        ]

        # Add conversation history for context
        if include_history:
            for msg in self.conversation_history[-5:]:  # Last 5 exchanges
                messages.append({"role": "user", "content": msg["user"]})
                messages.append({"role": "assistant", "content": msg["assistant"]})

        messages.append({"role": "user", "content": prompt_text})

        try:
            response = client.chat.completions.create(
                model=self.config.get("model", "gpt-4o"),
                messages=messages,
                temperature=self.config.get("temperature", 0.7),
                max_tokens=self.config.get("max_tokens", 2000)
            )

            answer = response.choices[0].message.content

            # Save to conversation history
            self.conversation_history.append({
                "user": prompt_text,
                "assistant": answer,
                "timestamp": datetime.datetime.now().isoformat()
            })
            self.save_history()

            return answer
        except Exception as e:
            return f"Error communicating with AI: {str(e)}"

    def display_main_menu(self):
        """Display main menu"""
        table = Table(title="🐉 Kali GPT Advanced - Red Team Assistant", show_lines=True,
                     title_style="bold green")
        table.add_column("Option", justify="center", style="cyan")
        table.add_column("Action", style="white")

        table.add_row("1", "💬 AI-Assisted Question/Task")
        table.add_row("2", "⚡ Quick Command Generation")
        table.add_row("3", "🎯 Execute Command with AI Analysis")
        table.add_row("4", "🔧 Tool Workflow Builder")
        table.add_row("5", "🛡️  Change Security Profile")
        table.add_row("6", "📋 Payload Generator")
        table.add_row("7", "🔍 Analyze Output")
        table.add_row("8", "📚 Show Conversation History")
        table.add_row("9", "⚙️  Settings")
        table.add_row("0", "❌ Exit")

        self.console.print(table)
        self.console.print(f"\n[bold cyan]Current Mode:[/bold cyan] {self.security_profiles[self.current_mode]['name']}")

    def change_mode(self):
        """Change security profile/mode"""
        table = Table(title="Select Security Profile", show_lines=True)
        table.add_column("#", justify="center")
        table.add_column("Profile", style="cyan")
        table.add_column("Description", style="white")

        modes = list(self.security_profiles.items())
        for idx, (key, profile) in enumerate(modes, 1):
            table.add_row(str(idx), profile["name"], profile["prompt"][:80] + "...")

        self.console.print(table)

        choice = Prompt.ask("Select profile", choices=[str(i) for i in range(1, len(modes) + 1)])
        self.current_mode = modes[int(choice) - 1][0]
        self.console.print(f"[green]✓ Switched to {self.security_profiles[self.current_mode]['name']}[/green]")

    def ai_assisted_task(self):
        """AI-assisted question or task"""
        user_input = Prompt.ask("[bold yellow]💬 Describe your task or question[/bold yellow]")

        with self.console.status("[bold green]Consulting AI...[/bold green]"):
            response = self.ask_gpt(user_input)

        md = Markdown(response)
        self.console.print(Panel(md, title="🤖 AI Response", border_style="green"))

        if self.config.get("auto_copy", True):
            pyperclip.copy(response)
            self.console.print("[dim]✓ Copied to clipboard[/dim]")

        self.last_response = response
        self.log_interaction(user_input, response)

    def quick_command_generation(self):
        """Generate commands quickly"""
        task = Prompt.ask("[bold yellow]⚡ What command do you need?[/bold yellow]")

        prompt = f"""Generate a Kali Linux command for: {task}

Provide:
1. The exact command(s) to run
2. Brief explanation of what it does
3. Important parameters/flags
4. Expected output

Format: Show commands in code blocks."""

        with self.console.status("[bold green]Generating command...[/bold green]"):
            response = self.ask_gpt(prompt)

        md = Markdown(response)
        self.console.print(Panel(md, title="⚡ Generated Command", border_style="cyan"))

        if self.config.get("auto_copy", True):
            pyperclip.copy(response)

        self.log_interaction(task, response)

        if Confirm.ask("Would you like to execute this command?"):
            command = Prompt.ask("Enter the exact command to execute")
            result = self.execute_command(command)

            if result["success"] and result["output"]:
                self.analyze_output(result["output"], command)

    def execute_with_analysis(self):
        """Execute command and get AI analysis"""
        command = Prompt.ask("[bold yellow]🎯 Enter command to execute[/bold yellow]")

        result = self.execute_command(command)

        if result["success"]:
            self.log_interaction(f"Executed: {command}", "", command, result.get("output", ""))

            if result.get("output"):
                self.analyze_output(result["output"], command)
        else:
            error_msg = result.get("error", "Unknown error")
            self.console.print(f"[red]Error: {error_msg}[/red]")

    def analyze_output(self, output: str, command: str = ""):
        """Analyze command output with AI"""
        if Confirm.ask("Get AI analysis of this output?"):
            prompt = f"""Analyze this command output from Kali Linux:

Command: {command}

Output:
```
{output[:3000]}
```

Provide:
1. Key findings and discoveries
2. Security implications
3. Next recommended steps
4. Vulnerabilities or interesting observations"""

            with self.console.status("[bold green]Analyzing output...[/bold green]"):
                response = self.ask_gpt(prompt)

            md = Markdown(response)
            self.console.print(Panel(md, title="🔍 Analysis", border_style="blue"))
            self.log_interaction(f"Analysis of: {command}", response)

    def tool_workflow_builder(self):
        """Build automated tool workflows"""
        self.console.print(Panel("[bold cyan]🔧 Tool Workflow Builder[/bold cyan]\n" +
                                "Describe a pentesting workflow and I'll create an automated sequence."))

        workflow_desc = Prompt.ask("Describe your workflow (e.g., 'Full web app scan on target.com')")

        prompt = f"""Create a step-by-step pentesting workflow for: {workflow_desc}

Provide:
1. Sequential commands to execute
2. What each command discovers
3. How to interpret results
4. Decision points based on findings
5. Next steps based on results

Focus on practical, executable commands for Kali Linux."""

        with self.console.status("[bold green]Building workflow...[/bold green]"):
            response = self.ask_gpt(prompt)

        md = Markdown(response)
        self.console.print(Panel(md, title="🔧 Workflow", border_style="cyan"))

        if Confirm.ask("Execute this workflow step-by-step?"):
            self.console.print("[yellow]Enter commands one at a time as prompted by the workflow[/yellow]")

    def payload_generator(self):
        """Advanced payload generation"""
        self.console.print(Panel("[bold cyan]📋 Payload Generator[/bold cyan]"))

        payload_type = Prompt.ask("Payload type",
                                 default="reverse shell",
                                 show_default=True)
        target_ip = Prompt.ask("Target/LHOST IP", default="10.10.10.10")
        target_port = Prompt.ask("Target/LPORT port", default="4444")

        prompt = f"""Generate detailed {payload_type} payload(s) for:
- Target IP: {target_ip}
- Target Port: {target_port}

Provide:
1. Multiple payload variations (bash, python, php, etc.)
2. Listener command
3. Usage instructions
4. Evasion techniques if applicable
5. Common issues and troubleshooting"""

        with self.console.status("[bold green]Generating payloads...[/bold green]"):
            response = self.ask_gpt(prompt)

        md = Markdown(response)
        self.console.print(Panel(md, title="📋 Payloads", border_style="green"))

        if self.config.get("auto_copy", True):
            pyperclip.copy(response)
            self.console.print("[dim]✓ Copied to clipboard[/dim]")

        self.log_interaction(f"Payload: {payload_type}", response)

    def show_history(self):
        """Display conversation history"""
        if not self.conversation_history:
            self.console.print("[yellow]No conversation history yet[/yellow]")
            return

        for idx, entry in enumerate(self.conversation_history[-5:], 1):
            self.console.print(f"\n[bold cyan]═══ Exchange {idx} ({entry.get('timestamp', 'N/A')}) ═══[/bold cyan]")
            self.console.print(f"[yellow]User:[/yellow] {entry['user'][:100]}...")
            self.console.print(f"[green]AI:[/green] {entry['assistant'][:200]}...")

    def settings_menu(self):
        """Settings configuration"""
        table = Table(title="⚙️  Settings", show_lines=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Current Value", style="yellow")

        table.add_row("Model", self.config.get("model", "gpt-4o"))
        table.add_row("Temperature", str(self.config.get("temperature", 0.7)))
        table.add_row("Max Tokens", str(self.config.get("max_tokens", 2000)))
        table.add_row("Require Confirmation", str(self.config.get("require_confirmation", True)))
        table.add_row("Auto Copy", str(self.config.get("auto_copy", True)))
        table.add_row("Save History", str(self.config.get("save_history", True)))

        self.console.print(table)

        if Confirm.ask("Modify settings?"):
            setting = Prompt.ask("Which setting?",
                               choices=["model", "temperature", "require_confirmation", "auto_copy"])

            if setting == "model":
                new_value = Prompt.ask("New model",
                                      choices=["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"])
            elif setting == "temperature":
                new_value = float(Prompt.ask("New temperature (0.0-1.0)"))
            else:
                new_value = Confirm.ask(f"Enable {setting}?")

            self.config[setting] = new_value
            self.save_config(self.config)
            self.console.print("[green]✓ Settings saved[/green]")

    def run(self):
        """Main application loop"""
        self.console.print(Panel.fit(
            "[bold green]🐉 Kali GPT Advanced[/bold green]\n" +
            "[cyan]AI-Powered Penetration Testing Assistant[/cyan]\n" +
            "[yellow]⚠️  For authorized security testing only[/yellow]",
            border_style="green"
        ))

        # Check for API key
        if not os.getenv("OPENAI_API_KEY"):
            self.console.print("[bold red]ERROR: OPENAI_API_KEY not found in .env file[/bold red]")
            sys.exit(1)

        while True:
            try:
                self.display_main_menu()
                choice = Prompt.ask("\n[bold]Select option[/bold]",
                                   choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"])

                if choice == "1":
                    self.ai_assisted_task()
                elif choice == "2":
                    self.quick_command_generation()
                elif choice == "3":
                    self.execute_with_analysis()
                elif choice == "4":
                    self.tool_workflow_builder()
                elif choice == "5":
                    self.change_mode()
                elif choice == "6":
                    self.payload_generator()
                elif choice == "7":
                    if self.last_response:
                        output = Prompt.ask("Paste output to analyze")
                        self.analyze_output(output)
                    else:
                        self.console.print("[yellow]No previous output[/yellow]")
                elif choice == "8":
                    self.show_history()
                elif choice == "9":
                    self.settings_menu()
                elif choice == "0":
                    self.console.print("[bold cyan]Stay safe and hack responsibly! 🐉[/bold cyan]")
                    break

                self.console.print("\n" + "═" * 80 + "\n")

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use option 0 to exit properly[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")

def main():
    app = KaliGPTAdvanced()
    app.run()

if __name__ == "__main__":
    main()
