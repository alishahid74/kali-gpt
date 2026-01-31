"""
Kali-GPT Multi-Agent v4.0 Integration

Provides menu and entry points for the 12-agent collaborative system.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()


async def multi_agent_v4_menu(ai_service, attack_tree=None):
    """
    Multi-Agent v4.0 Menu - 12 Specialized AI Agents
    """
    
    console.print(Panel(
        "[bold cyan]🤖 MULTI-AGENT SYSTEM v4.0[/bold cyan]\n\n"
        "[bold]12 Specialized AI Agents:[/bold]\n"
        "  🔍 Recon      - Port scanning, service detection\n"
        "  🌐 Network    - SMB, LDAP, SNMP enumeration\n"
        "  🕸️  Web        - Web app testing, fuzzing\n"
        "  💥 Exploit    - Vulnerability exploitation\n"
        "  🔓 PostExploit- Privilege escalation, persistence\n"
        "  ☁️  Cloud      - AWS/Azure/GCP security\n"
        "  📦 Container  - Docker/K8s security\n"
        "  🔬 Binary     - Reverse engineering, analysis\n"
        "  🏆 CTF        - Forensics, steganography\n"
        "  🔎 OSINT      - Open source intelligence\n"
        "  📝 Reporting  - Report generation\n"
        "  🎯 Coordinator- Orchestrates all agents\n\n"
        "[dim]Agents collaborate, share findings, and work together[/dim]",
        title="Multi-Agent Pentest",
        border_style="cyan"
    ))
    
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    table.add_column("", style="dim")
    
    table.add_row("1", "🚀 Full Pentest", "All 12 agents collaborate")
    table.add_row("2", "⚡ Quick Scan", "Recon + Web + Exploit only")
    table.add_row("3", "☁️  Cloud Audit", "Cloud + Container agents")
    table.add_row("4", "🏆 CTF Mode", "CTF + Binary + Forensics")
    table.add_row("5", "🔎 OSINT Only", "OSINT + Recon agents")
    table.add_row("6", "🎯 Custom", "Select specific agents")
    table.add_row("b", "⬅️  Back", "")
    
    console.print(table)
    
    choice = Prompt.ask("\nSelect mode", default="b")
    
    if choice == "1":
        await run_full_pentest(ai_service, attack_tree)
    elif choice == "2":
        await run_quick_scan(ai_service, attack_tree)
    elif choice == "3":
        await run_cloud_audit(ai_service)
    elif choice == "4":
        await run_ctf_mode(ai_service)
    elif choice == "5":
        await run_osint_mode(ai_service)
    elif choice == "6":
        await run_custom_agents(ai_service, attack_tree)


async def run_full_pentest(ai_service, attack_tree=None):
    """Run full penetration test with all 12 agents"""
    
    target = Prompt.ask("\n[bold]Target[/bold] (IP/hostname/URL)")
    if not target:
        return
    
    max_rounds = int(Prompt.ask("Max rounds", default="20"))
    
    console.print(f"\n[cyan]Initializing 12-agent pentest against {target}...[/cyan]\n")
    
    try:
        from kali_gpt.agents_v4 import MultiAgentPentest
        
        pentest = MultiAgentPentest(
            target=target,
            ai_service=ai_service,
            scope=[target]
        )
        
        console.print(f"[green]✓ Initialized {pentest.get_agent_count()} agents[/green]\n")
        
        # Run the pentest
        results = await pentest.run(max_rounds=max_rounds)
        
        # Display results
        display_results(results)
        
        # Update attack tree if available
        if attack_tree and results.get('all_findings'):
            for finding in results['all_findings']:
                if finding.get('type') == 'vulnerability':
                    attack_tree.add_finding(
                        finding['value'],
                        "vulnerability",
                        finding.get('agent', 'unknown')
                    )
        
    except ImportError:
        console.print("[yellow]⚠ Full agent system not available, using inline version[/yellow]")
        await run_inline_multiagent(ai_service, target, attack_tree)


async def run_quick_scan(ai_service, attack_tree=None):
    """Quick 3-phase scan: Recon → Web → Exploit"""
    
    target = Prompt.ask("\n[bold]Target[/bold]")
    if not target:
        return
    
    console.print(f"\n[cyan]Quick scan: Recon → Web → Exploit[/cyan]\n")
    
    # Phase 1: Recon
    console.print("[bold cyan]Phase 1: Reconnaissance[/bold cyan]")
    await run_agent_phase(ai_service, "recon", target, [
        f"nmap -sV -sC -T4 {target}",
        f"whatweb {target}" if target.startswith(('http://', 'https://')) else None
    ])
    
    # Phase 2: Web (if applicable)
    if target.startswith(('http://', 'https://')) or Confirm.ask("Run web scans?", default=True):
        console.print("\n[bold green]Phase 2: Web Testing[/bold green]")
        url = target if target.startswith('http') else f"http://{target}"
        await run_agent_phase(ai_service, "web", url, [
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 30 -q 2>/dev/null | head -20",
            f"nikto -h {url} -Tuning 123 2>/dev/null | head -30"
        ])
    
    # Phase 3: Exploit suggestions
    console.print("\n[bold red]Phase 3: Exploitation Analysis[/bold red]")
    prompt = f"""Based on a scan of {target}, suggest potential exploitation paths.
Consider common vulnerabilities for any services discovered.
Format as a prioritized list with commands."""
    
    response = ai_service.ask(prompt)
    console.print(Panel(response, title="Exploit Suggestions", border_style="red"))
    
    Prompt.ask("\nPress Enter to continue")


async def run_cloud_audit(ai_service):
    """Cloud security audit with Cloud + Container agents"""
    
    console.print("\n[bold blue]☁️  Cloud Security Audit[/bold blue]\n")
    
    provider = Prompt.ask(
        "Cloud provider",
        choices=["aws", "azure", "gcp", "k8s", "docker"],
        default="aws"
    )
    
    tools_map = {
        "aws": [
            ("Prowler AWS", "prowler aws --severity critical high -M csv 2>&1 | head -50"),
            ("S3 Buckets", "aws s3 ls 2>/dev/null | head -10"),
            ("IAM Users", "aws iam list-users --query 'Users[*].UserName' 2>/dev/null | head -10"),
        ],
        "azure": [
            ("Scout Suite", "scout azure --cli 2>&1 | head -50"),
            ("Subscriptions", "az account list --query '[].name' -o tsv 2>/dev/null"),
        ],
        "gcp": [
            ("Scout Suite", "scout gcp 2>&1 | head -50"),
            ("Projects", "gcloud projects list 2>/dev/null | head -10"),
        ],
        "k8s": [
            ("Kube-bench", "kube-bench run 2>&1 | head -50"),
            ("Kube-hunter", "kube-hunter --pod 2>&1 | head -50"),
            ("Pods", "kubectl get pods -A 2>/dev/null | head -20"),
        ],
        "docker": [
            ("Docker Bench", "docker-bench-security.sh 2>&1 | head -50"),
            ("Containers", "docker ps --format '{{.Names}}: {{.Image}}' 2>/dev/null | head -10"),
        ]
    }
    
    for name, cmd in tools_map.get(provider, []):
        console.print(f"\n[cyan]Running {name}...[/cyan]")
        await run_command_with_output(cmd)
    
    Prompt.ask("\nPress Enter to continue")


async def run_ctf_mode(ai_service):
    """CTF challenge solving mode"""
    
    console.print("\n[bold magenta]🏆 CTF Challenge Mode[/bold magenta]\n")
    
    challenge_type = Prompt.ask(
        "Challenge type",
        choices=["forensics", "stego", "crypto", "binary", "web", "misc"],
        default="misc"
    )
    
    filepath = Prompt.ask("File path (or Enter to skip)")
    
    if filepath and os.path.exists(filepath):
        console.print(f"\n[cyan]Analyzing {filepath}...[/cyan]\n")
        
        import subprocess
        
        # Common analysis
        subprocess.run(f"file '{filepath}'", shell=True)
        subprocess.run(f"strings '{filepath}' | grep -iE 'flag|ctf|key' | head -10", shell=True)
        
        if challenge_type == "stego":
            subprocess.run(f"exiftool '{filepath}' 2>/dev/null | head -20", shell=True)
            if filepath.endswith('.png'):
                subprocess.run(f"zsteg '{filepath}' 2>/dev/null | head -20", shell=True)
        elif challenge_type == "forensics":
            subprocess.run(f"binwalk '{filepath}' 2>/dev/null | head -20", shell=True)
        elif challenge_type == "binary":
            subprocess.run(f"checksec --file='{filepath}' 2>/dev/null", shell=True)
    
    # AI assistance
    console.print("\n[bold]Ask the AI for help:[/bold]")
    question = Prompt.ask("Describe your challenge")
    if question:
        prompt = f"""You are a CTF expert. Help solve this {challenge_type} challenge:

{question}

Provide:
1. Likely challenge type
2. Tools to use
3. Step-by-step approach
4. Specific commands"""
        
        response = ai_service.ask(prompt)
        console.print(Panel(response, border_style="magenta"))
    
    Prompt.ask("\nPress Enter to continue")


async def run_osint_mode(ai_service):
    """OSINT reconnaissance mode"""
    
    console.print("\n[bold cyan]🔎 OSINT Mode[/bold cyan]\n")
    
    target_type = Prompt.ask(
        "Target type",
        choices=["domain", "email", "username", "company", "person"],
        default="domain"
    )
    
    target = Prompt.ask(f"Enter {target_type}")
    if not target:
        return
    
    console.print(f"\n[cyan]Running OSINT on {target}...[/cyan]\n")
    
    import subprocess
    import shutil
    
    if target_type == "domain":
        tools = [
            ("Subfinder", f"subfinder -d {target} -silent 2>/dev/null | head -20"),
            ("Amass", f"amass enum -passive -d {target} 2>/dev/null | head -20"),
            ("theHarvester", f"theHarvester -d {target} -b all 2>/dev/null | head -30"),
            ("DNS Records", f"dig ANY {target} +short 2>/dev/null"),
            ("Whois", f"whois {target} 2>/dev/null | head -30"),
        ]
    elif target_type == "email":
        tools = [
            ("Holehe", f"holehe {target} 2>/dev/null | head -30"),
            ("h8mail", f"h8mail -t {target} 2>/dev/null | head -20"),
        ]
    elif target_type == "username":
        tools = [
            ("Sherlock", f"sherlock {target} --timeout 10 2>/dev/null | head -30"),
            ("Maigret", f"maigret {target} 2>/dev/null | head -30"),
        ]
    else:
        tools = [
            ("Google Dorks", f"echo 'site:linkedin.com \"{target}\"'"),
        ]
    
    for name, cmd in tools:
        tool_bin = cmd.split()[0]
        if shutil.which(tool_bin) or tool_bin == "echo":
            console.print(f"\n[bold]{name}:[/bold]")
            subprocess.run(cmd, shell=True)
        else:
            console.print(f"\n[dim]{name}: not installed[/dim]")
    
    Prompt.ask("\nPress Enter to continue")


async def run_custom_agents(ai_service, attack_tree=None):
    """Select specific agents to run"""
    
    console.print("\n[bold]Select agents to activate:[/bold]\n")
    
    agents = {
        "1": ("Recon", "🔍"),
        "2": ("Network", "🌐"),
        "3": ("Web", "🕸️"),
        "4": ("Exploit", "💥"),
        "5": ("PostExploit", "🔓"),
        "6": ("Cloud", "☁️"),
        "7": ("Container", "📦"),
        "8": ("Binary", "🔬"),
        "9": ("CTF", "🏆"),
        "a": ("OSINT", "🔎"),
        "b": ("Reporting", "📝"),
    }
    
    for key, (name, icon) in agents.items():
        console.print(f"  [{key}] {icon} {name}")
    
    selection = Prompt.ask("\nEnter agent numbers (e.g., 1,3,4)", default="1,3,4")
    
    selected = []
    for key in selection.replace(" ", "").split(","):
        if key in agents:
            selected.append(agents[key][0])
    
    if not selected:
        console.print("[yellow]No agents selected[/yellow]")
        return
    
    console.print(f"\n[green]Selected: {', '.join(selected)}[/green]")
    
    target = Prompt.ask("Target")
    if target:
        console.print(f"\n[cyan]Running {len(selected)} agents against {target}...[/cyan]\n")
        # Run selected agents
        await run_inline_multiagent(ai_service, target, attack_tree, selected)


async def run_agent_phase(ai_service, phase_name: str, target: str, commands: List[str]):
    """Run a single agent phase"""
    import subprocess
    import shutil
    
    for cmd in commands:
        if cmd is None:
            continue
        
        tool = cmd.split()[0]
        if not shutil.which(tool):
            console.print(f"[dim]Skipping {tool} (not installed)[/dim]")
            continue
        
        console.print(f"[cyan]$ {cmd[:80]}...[/cyan]")
        
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=120
            )
            output = (result.stdout + result.stderr)[:1000]
            if output.strip():
                console.print(output)
        except subprocess.TimeoutExpired:
            console.print("[yellow]Command timed out[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


async def run_command_with_output(cmd: str):
    """Run a command and display output"""
    import subprocess
    import shutil
    
    tool = cmd.split()[0]
    if not shutil.which(tool):
        console.print(f"[dim]{tool} not installed[/dim]")
        return
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        output = (result.stdout + result.stderr)[:2000]
        if output.strip():
            console.print(output)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


async def run_inline_multiagent(ai_service, target: str, attack_tree=None, agents=None):
    """Inline multi-agent implementation"""
    
    import subprocess
    import shutil
    
    if agents is None:
        agents = ["Recon", "Web", "Exploit"]
    
    findings = []
    
    for agent_name in agents:
        console.print(f"\n[bold cyan]{'='*20} {agent_name} Agent {'='*20}[/bold cyan]\n")
        
        # Get AI suggestion for this agent
        prompt = f"""You are the {agent_name} agent in a penetration test.
Target: {target}
Previous findings: {findings[-5:] if findings else 'None yet'}

Suggest ONE specific command to run. Just the command, nothing else."""
        
        try:
            cmd = ai_service.ask(prompt).strip()
            # Clean command
            cmd = cmd.replace('```', '').replace('bash', '').strip()
            if '\n' in cmd:
                cmd = cmd.split('\n')[0]
            
            console.print(f"[cyan]$ {cmd}[/cyan]")
            
            # Execute
            tool = cmd.split()[0] if cmd else ""
            if tool and shutil.which(tool):
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                output = (result.stdout + result.stderr)[:1500]
                console.print(output)
                
                # Extract findings
                if 'open' in output.lower():
                    findings.append(f"Open ports found by {agent_name}")
                if 'vulnerable' in output.lower() or 'vulnerability' in output.lower():
                    findings.append(f"Vulnerability found by {agent_name}")
            else:
                console.print(f"[dim]Tool not available: {tool}[/dim]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    # Summary
    console.print(f"\n[bold green]{'='*50}[/bold green]")
    console.print(f"[bold]Scan Complete - {len(findings)} findings[/bold]")
    for f in findings:
        console.print(f"  • {f}")
    
    Prompt.ask("\nPress Enter to continue")


def display_results(results: Dict):
    """Display multi-agent results"""
    
    console.print(Panel(
        f"[bold]Target:[/bold] {results.get('target', 'N/A')}\n"
        f"[bold]Rounds:[/bold] {results.get('rounds', 0)}\n"
        f"[bold]Commands:[/bold] {results.get('commands', 0)}\n"
        f"[bold]Credentials:[/bold] {len(results.get('credentials', []))}\n"
        f"[bold]Flags:[/bold] {len(results.get('flags', []))}",
        title="📊 Results Summary",
        border_style="green"
    ))
    
    # Findings table
    findings = results.get('findings', {})
    
    if findings.get('by_risk'):
        table = Table(title="Findings by Risk", box=box.ROUNDED)
        table.add_column("Risk", style="bold")
        table.add_column("Count", justify="right")
        
        risk_colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
            "info": "dim"
        }
        
        for risk, count in findings['by_risk'].items():
            if count > 0:
                color = risk_colors.get(risk, "white")
                table.add_row(f"[{color}]{risk.upper()}[/{color}]", str(count))
        
        console.print(table)
    
    # All findings
    all_findings = results.get('all_findings', [])
    if all_findings:
        console.print("\n[bold]All Findings:[/bold]")
        for f in all_findings[:20]:
            risk = f.get('risk', 'info')
            color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(risk, "dim")
            console.print(f"  [{color}]•[/{color}] [{f.get('type', '?')}] {f.get('value', '')}")


# Import os for file operations
import os
