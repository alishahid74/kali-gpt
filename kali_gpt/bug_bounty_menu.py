"""
Kali-GPT v4.1 - AI Bug Bounty Hunter (Part 2)

Interactive menu, report generation, and program management.

Author: Kali-GPT Team
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from bug_bounty_hunter import (
    BugBountyHunter, BountyProgram, BugReport, Asset,
    Severity, VulnCategory, Platform
)

console = Console()


# =============================================================================
# BUILT-IN BUG BOUNTY PROGRAMS DATABASE
# =============================================================================

POPULAR_PROGRAMS = {
    "hackerone_example": BountyProgram(
        name="Example Program (HackerOne)",
        platform=Platform.HACKERONE,
        url="https://hackerone.com/example",
        scope=["*.example.com", "api.example.com"],
        out_of_scope=["staging.example.com", "*.dev.example.com"],
        vuln_types=["XSS", "SQLI", "SSRF", "IDOR", "RCE"],
        bounty_range={
            "critical": (5000, 15000),
            "high": (1500, 5000),
            "medium": (500, 1500),
            "low": (100, 500),
        },
        response_time="~3 days"
    ),
}


# =============================================================================
# REPORT TEMPLATES
# =============================================================================

class ReportGenerator:
    """Generate bug bounty reports in various formats"""
    
    @staticmethod
    def to_hackerone(report: BugReport) -> str:
        """Generate HackerOne formatted report"""
        return f"""## Summary
{report.description}

## Steps To Reproduce
{chr(10).join([f'{i+1}. {step}' for i, step in enumerate(report.steps_to_reproduce)])}

## Supporting Material/References
```
{report.poc}
```

## Impact
{report.impact}

## Suggested Severity
{report.severity.value.upper()} (CVSS: {report.cvss})
"""
    
    @staticmethod
    def to_bugcrowd(report: BugReport) -> str:
        """Generate Bugcrowd formatted report"""
        return f"""### Title
{report.title}

### URL/Location
{report.endpoint}

### Vulnerability Type
{report.category.value}

### Description
{report.description}

### Steps to Reproduce
{chr(10).join([f'{i+1}. {step}' for i, step in enumerate(report.steps_to_reproduce)])}

### Proof of Concept
```
{report.poc}
```

### Business Impact
{report.impact}

### Severity Justification
Suggested: {report.severity.value.upper()}
CVSS Score: {report.cvss}
"""
    
    @staticmethod
    def to_markdown(report: BugReport) -> str:
        """Generate detailed markdown report"""
        return report.to_markdown()
    
    @staticmethod
    def to_json(report: BugReport) -> str:
        """Generate JSON report for automation"""
        return json.dumps({
            "id": report.id,
            "title": report.title,
            "severity": report.severity.value,
            "category": report.category.value,
            "target": report.target,
            "endpoint": report.endpoint,
            "description": report.description,
            "steps_to_reproduce": report.steps_to_reproduce,
            "poc": report.poc,
            "impact": report.impact,
            "cvss": report.cvss,
            "cwe": report.cwe,
            "confidence": report.confidence,
            "duplicate_risk": report.duplicate_risk,
            "estimated_bounty": report.estimated_bounty,
            "created_at": report.created_at
        }, indent=2)


# =============================================================================
# BUG BOUNTY MENU
# =============================================================================

async def bug_bounty_menu(ai_service):
    """Main bug bounty hunter menu"""
    
    console.print(Panel(
        "[bold red]🎯 AI BUG BOUNTY HUNTER[/bold red]\n\n"
        "[bold]Automated bug bounty hunting with AI:[/bold]\n"
        "  🔍 Intelligent reconnaissance\n"
        "  🎯 Vulnerability hunting (OWASP Top 10+)\n"
        "  🧠 AI-powered finding analysis\n"
        "  📊 Smart duplicate detection\n"
        "  📝 Platform-ready report generation\n"
        "  💰 Bounty estimation\n\n"
        "[yellow]⚠️ Only hunt on programs you're authorized for![/yellow]",
        title="Bug Bounty Hunter",
        border_style="red"
    ))
    
    while True:
        table = Table(show_header=False, box=box.ROUNDED)
        table.add_column("", width=5)
        table.add_column("")
        table.add_column("", style="dim")
        
        table.add_row("1", "🚀 Quick Hunt", "Full auto recon + hunt on domain")
        table.add_row("2", "🔍 Recon Only", "Subdomain & asset discovery")
        table.add_row("3", "🎯 Hunt Only", "Vulnerability scan on targets")
        table.add_row("4", "📋 New Program", "Add bug bounty program")
        table.add_row("5", "💾 View Programs", "Saved programs")
        table.add_row("6", "📊 View Findings", "All discovered bugs")
        table.add_row("7", "📝 Generate Report", "Create submission report")
        table.add_row("8", "🧠 AI Assistant", "Ask AI about hunting")
        table.add_row("9", "📈 Statistics", "Hunting stats")
        table.add_row("b", "⬅️  Back", "")
        
        console.print(table)
        
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice == 'b':
            break
        
        elif choice == '1':
            await quick_hunt(ai_service)
        
        elif choice == '2':
            await recon_only(ai_service)
        
        elif choice == '3':
            await hunt_only(ai_service)
        
        elif choice == '4':
            await add_program()
        
        elif choice == '5':
            view_programs()
        
        elif choice == '6':
            await view_findings(ai_service)
        
        elif choice == '7':
            await generate_report_menu(ai_service)
        
        elif choice == '8':
            await ai_assistant(ai_service)
        
        elif choice == '9':
            show_statistics()


async def quick_hunt(ai_service):
    """Quick hunt - full automated recon and vulnerability hunting"""
    
    console.print(Panel(
        "[bold cyan]🚀 QUICK HUNT MODE[/bold cyan]\n\n"
        "I'll perform:\n"
        "1. Full subdomain enumeration\n"
        "2. Live host detection\n"
        "3. Technology fingerprinting\n"
        "4. Endpoint discovery\n"
        "5. Comprehensive vulnerability hunting\n"
        "6. AI analysis and prioritization\n\n"
        "[dim]This may take 10-30 minutes depending on target size[/dim]",
        border_style="cyan"
    ))
    
    domain = Prompt.ask("\nTarget domain (e.g., example.com)")
    
    if not domain:
        return
    
    # Clean domain
    domain = domain.replace('https://', '').replace('http://', '').strip('/')
    
    # Confirm scope
    console.print(f"\n[yellow]⚠️ Confirm you have authorization to test {domain}[/yellow]")
    if not Confirm.ask("I have permission to test this target", default=False):
        console.print("[red]Hunting cancelled - authorization required![/red]")
        return
    
    # Create program if not exists
    program = BountyProgram(
        name=f"Hunt - {domain}",
        platform=Platform.CUSTOM,
        url=f"https://{domain}",
        scope=[f"*.{domain}", domain]
    )
    
    # Initialize hunter
    hunter = BugBountyHunter(ai_service, program)
    
    def callback(msg):
        console.print(msg)
    
    console.print(f"\n[bold green]🎯 Starting hunt on {domain}[/bold green]\n")
    
    try:
        # Phase 1: Reconnaissance
        console.print("=" * 60)
        console.print("[bold]PHASE 1: RECONNAISSANCE[/bold]")
        console.print("=" * 60)
        
        await hunter.recon(domain, callback)
        
        # Phase 2: Hunting
        console.print("\n" + "=" * 60)
        console.print("[bold]PHASE 2: VULNERABILITY HUNTING[/bold]")
        console.print("=" * 60)
        
        await hunter.hunt(callback)
        
        # Results
        console.print("\n" + "=" * 60)
        console.print("[bold green]🏆 HUNT COMPLETE[/bold green]")
        console.print("=" * 60)
        
        display_hunt_results(hunter)
        
        # Save findings
        if hunter.findings:
            save_path = f"~/kali-gpt-reports/hunt_{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}"
            save_path = os.path.expanduser(save_path)
            os.makedirs(save_path, exist_ok=True)
            
            # Save JSON
            with open(f"{save_path}/findings.json", 'w') as f:
                json.dump([ReportGenerator.to_json(r) for r in hunter.findings], f, indent=2)
            
            # Save individual reports
            for report in hunter.findings:
                filename = f"{save_path}/{report.id}_{report.severity.value}.md"
                with open(filename, 'w') as f:
                    f.write(report.to_markdown())
            
            console.print(f"\n[green]✓ Findings saved to {save_path}[/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Hunt interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error during hunt: {e}[/red]")
    
    Prompt.ask("\nPress Enter to continue")


async def recon_only(ai_service):
    """Reconnaissance only mode"""
    
    console.print(Panel(
        "[bold blue]🔍 RECON MODE[/bold blue]\n\n"
        "Subdomain enumeration and asset discovery only.\n"
        "No active vulnerability testing.",
        border_style="blue"
    ))
    
    domain = Prompt.ask("\nTarget domain")
    
    if not domain:
        return
    
    domain = domain.replace('https://', '').replace('http://', '').strip('/')
    
    program = BountyProgram(
        name=f"Recon - {domain}",
        platform=Platform.CUSTOM,
        url=f"https://{domain}",
        scope=[f"*.{domain}", domain]
    )
    
    hunter = BugBountyHunter(ai_service, program)
    
    def callback(msg):
        console.print(msg)
    
    console.print(f"\n[cyan]Starting recon on {domain}...[/cyan]\n")
    
    try:
        await hunter.recon(domain, callback)
        
        # Display results
        console.print("\n[bold]📊 RECON RESULTS[/bold]\n")
        
        # Subdomains
        subdomains = [a for a in hunter.assets if a.type == "subdomain"]
        if subdomains:
            console.print(f"[green]Subdomains ({len(subdomains)}):[/green]")
            for s in subdomains[:30]:
                status = "✓" if s.alive else "✗"
                console.print(f"  {status} {s.value}")
            if len(subdomains) > 30:
                console.print(f"  ... and {len(subdomains) - 30} more")
        
        # Interesting endpoints
        interesting = [a for a in hunter.assets if a.interesting]
        if interesting:
            console.print(f"\n[yellow]Interesting Findings ({len(interesting)}):[/yellow]")
            for a in interesting[:20]:
                console.print(f"  ⭐ {a.value}")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Recon interrupted[/yellow]")
    
    Prompt.ask("\nPress Enter to continue")


async def hunt_only(ai_service):
    """Vulnerability hunting on provided targets"""
    
    console.print(Panel(
        "[bold red]🎯 HUNT MODE[/bold red]\n\n"
        "Active vulnerability testing on provided URLs.\n"
        "Enter URLs one per line, or provide a file path.",
        border_style="red"
    ))
    
    console.print("Enter targets (URLs or file path):")
    console.print("[dim]For multiple URLs, enter them one per line. Type 'done' when finished.[/dim]\n")
    
    targets = []
    
    while True:
        line = Prompt.ask("Target")
        
        if line.lower() == 'done':
            break
        
        if os.path.isfile(line):
            # Load from file
            with open(line) as f:
                targets.extend([l.strip() for l in f if l.strip()])
            console.print(f"[green]Loaded {len(targets)} targets from file[/green]")
            break
        
        if line:
            targets.append(line)
    
    if not targets:
        console.print("[yellow]No targets provided[/yellow]")
        return
    
    if not Confirm.ask(f"Test {len(targets)} target(s)?", default=True):
        return
    
    hunter = BugBountyHunter(ai_service)
    
    # Add targets as assets
    for t in targets:
        hunter.assets.append(Asset(
            type="endpoint",
            value=t,
            source="manual",
            alive=True
        ))
    
    def callback(msg):
        console.print(msg)
    
    console.print("\n[cyan]Starting vulnerability hunt...[/cyan]\n")
    
    try:
        await hunter.hunt(callback)
        display_hunt_results(hunter)
    except KeyboardInterrupt:
        console.print("\n[yellow]Hunt interrupted[/yellow]")
    
    Prompt.ask("\nPress Enter to continue")


def display_hunt_results(hunter: BugBountyHunter):
    """Display hunt results"""
    
    stats = hunter.stats
    findings = hunter.findings
    
    # Statistics
    table = Table(title="📊 Hunt Statistics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Subdomains Found", str(stats['subdomains_found']))
    table.add_row("Endpoints Found", str(stats['endpoints_found']))
    table.add_row("Parameters Found", str(stats['params_found']))
    table.add_row("Vulnerabilities Found", str(stats['vulns_found']))
    table.add_row("Est. Total Bounty", f"${stats['estimated_bounty']:,}")
    
    if stats['scan_start'] and stats['scan_end']:
        duration = stats['scan_end'] - stats['scan_start']
        table.add_row("Duration", str(duration).split('.')[0])
    
    console.print(table)
    
    # Findings by severity
    if findings:
        console.print("\n[bold]🐛 FINDINGS[/bold]\n")
        
        severity_order = ['critical', 'high', 'medium', 'low', 'informational']
        
        for severity in severity_order:
            sev_findings = [f for f in findings if f.severity.value == severity]
            
            if sev_findings:
                color = {
                    'critical': 'red',
                    'high': 'yellow',
                    'medium': 'blue',
                    'low': 'green',
                    'informational': 'dim'
                }.get(severity, 'white')
                
                console.print(f"[{color}][{severity.upper()}][/{color}]")
                
                for f in sev_findings:
                    dup_warning = " ⚠️ likely dupe" if f.duplicate_risk > 0.7 else ""
                    bounty = f"${f.estimated_bounty[0]}-{f.estimated_bounty[1]}"
                    console.print(f"  • {f.title} [{bounty}]{dup_warning}")
    else:
        console.print("\n[yellow]No vulnerabilities found[/yellow]")


async def add_program():
    """Add a new bug bounty program"""
    
    console.print(Panel(
        "[bold green]📋 ADD BUG BOUNTY PROGRAM[/bold green]",
        border_style="green"
    ))
    
    name = Prompt.ask("Program name")
    platform = Prompt.ask(
        "Platform",
        choices=["hackerone", "bugcrowd", "intigriti", "yeswehack", "custom"],
        default="hackerone"
    )
    url = Prompt.ask("Program URL (e.g., https://hackerone.com/company)")
    
    console.print("\nEnter in-scope domains (one per line, 'done' to finish):")
    scope = []
    while True:
        domain = Prompt.ask("Domain")
        if domain.lower() == 'done':
            break
        if domain:
            scope.append(domain)
    
    console.print("\nBounty ranges (enter 0 to skip):")
    bounty_range = {}
    for sev in ['critical', 'high', 'medium', 'low']:
        min_b = int(Prompt.ask(f"  {sev.capitalize()} min $", default="0"))
        if min_b > 0:
            max_b = int(Prompt.ask(f"  {sev.capitalize()} max $", default=str(min_b * 3)))
            bounty_range[sev] = (min_b, max_b)
    
    program = BountyProgram(
        name=name,
        platform=Platform(platform),
        url=url,
        scope=scope,
        bounty_range=bounty_range
    )
    
    # Save to file
    programs_file = os.path.expanduser("~/.kali-gpt/bb_programs.json")
    
    programs = []
    if os.path.exists(programs_file):
        with open(programs_file) as f:
            programs = json.load(f)
    
    programs.append({
        'name': name,
        'platform': platform,
        'url': url,
        'scope': scope,
        'bounty_range': bounty_range
    })
    
    os.makedirs(os.path.dirname(programs_file), exist_ok=True)
    with open(programs_file, 'w') as f:
        json.dump(programs, f, indent=2)
    
    console.print(f"\n[green]✓ Program '{name}' saved![/green]")
    
    Prompt.ask("\nPress Enter to continue")


def view_programs():
    """View saved programs"""
    
    programs_file = os.path.expanduser("~/.kali-gpt/bb_programs.json")
    
    if not os.path.exists(programs_file):
        console.print("[yellow]No saved programs[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    with open(programs_file) as f:
        programs = json.load(f)
    
    table = Table(title="💾 Saved Programs", box=box.ROUNDED)
    table.add_column("#")
    table.add_column("Name")
    table.add_column("Platform")
    table.add_column("Scope")
    table.add_column("Max Bounty")
    
    for i, p in enumerate(programs, 1):
        max_bounty = max([r[1] for r in p.get('bounty_range', {}).values()] or [0])
        table.add_row(
            str(i),
            p['name'],
            p['platform'],
            str(len(p.get('scope', []))) + " domains",
            f"${max_bounty:,}" if max_bounty else "N/A"
        )
    
    console.print(table)
    Prompt.ask("\nPress Enter to continue")


async def view_findings(ai_service):
    """View and manage findings"""
    
    reports_dir = os.path.expanduser("~/kali-gpt-reports")
    
    if not os.path.exists(reports_dir):
        console.print("[yellow]No findings saved yet[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    # Find all finding files
    findings = []
    for root, dirs, files in os.walk(reports_dir):
        for file in files:
            if file.endswith('.json') and 'findings' in file:
                filepath = os.path.join(root, file)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            findings.extend(data)
                        else:
                            findings.append(data)
                except:
                    continue
    
    if not findings:
        console.print("[yellow]No findings found[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    table = Table(title=f"🐛 All Findings ({len(findings)})", box=box.ROUNDED)
    table.add_column("#")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Target")
    table.add_column("Bounty Est.")
    
    for i, f in enumerate(findings[:50], 1):
        sev = f.get('severity', 'unknown')
        color = {'critical': 'red', 'high': 'yellow', 'medium': 'blue', 'low': 'green'}.get(sev, 'dim')
        
        bounty = f.get('estimated_bounty', [0, 0])
        if isinstance(bounty, list) and len(bounty) == 2:
            bounty_str = f"${bounty[0]}-{bounty[1]}"
        else:
            bounty_str = "N/A"
        
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            (f.get('title', '')[:40] + "...") if len(f.get('title', '')) > 40 else f.get('title', ''),
            f.get('target', '')[:20],
            bounty_str
        )
    
    console.print(table)
    
    if len(findings) > 50:
        console.print(f"\n[dim]Showing 50 of {len(findings)} findings[/dim]")
    
    Prompt.ask("\nPress Enter to continue")


async def generate_report_menu(ai_service):
    """Generate submission-ready report"""
    
    console.print(Panel(
        "[bold cyan]📝 REPORT GENERATOR[/bold cyan]\n\n"
        "Generate platform-ready bug reports:\n"
        "  • HackerOne format\n"
        "  • Bugcrowd format\n"
        "  • Markdown\n"
        "  • JSON",
        border_style="cyan"
    ))
    
    # Get finding details
    console.print("\n[bold]Enter finding details:[/bold]\n")
    
    title = Prompt.ask("Title")
    severity = Prompt.ask("Severity", choices=["critical", "high", "medium", "low"], default="medium")
    vuln_type = Prompt.ask("Vulnerability type (e.g., XSS, SQLI, IDOR)")
    target = Prompt.ask("Target domain/app")
    endpoint = Prompt.ask("Vulnerable endpoint/URL")
    
    console.print("\nSteps to reproduce (one per line, 'done' to finish):")
    steps = []
    step_num = 1
    while True:
        step = Prompt.ask(f"Step {step_num}")
        if step.lower() == 'done':
            break
        if step:
            steps.append(step)
            step_num += 1
    
    poc = Prompt.ask("Proof of concept (command/payload)")
    impact = Prompt.ask("Impact description")
    
    # Create report
    report = BugReport(
        id=f"RPT-{datetime.now().strftime('%Y%m%d%H%M')}",
        title=title,
        severity=Severity(severity),
        category=VulnCategory.XSS,  # Will be enhanced by AI
        target=target,
        endpoint=endpoint,
        description=f"{vuln_type} vulnerability found at {endpoint}",
        steps_to_reproduce=steps,
        poc=poc,
        impact=impact
    )
    
    # Enhance with AI
    if ai_service:
        console.print("\n[cyan]🧠 AI enhancing report...[/cyan]")
        
        prompt = f"""Enhance this bug bounty report with:
1. Better description
2. Impact assessment
3. CVSS score estimate
4. CWE ID
5. Remediation suggestion

Title: {title}
Type: {vuln_type}
Endpoint: {endpoint}
Steps: {steps}
Impact: {impact}

Respond in JSON: {{"description": "...", "impact": "...", "cvss": X.X, "cwe": "CWE-XXX", "remediation": "..."}}"""

        try:
            response = ai_service.ask(prompt)
            import re
            json_match = re.search(r'\{[^{}]+\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                report.description = data.get('description', report.description)
                report.impact = data.get('impact', report.impact)
                report.cvss = float(data.get('cvss', 0))
                report.cwe = data.get('cwe', '')
                report.remediation = data.get('remediation', '')
        except:
            pass
    
    # Generate reports
    console.print("\n[bold]Select format:[/bold]")
    console.print("  [1] HackerOne")
    console.print("  [2] Bugcrowd")
    console.print("  [3] Markdown")
    console.print("  [4] All formats")
    
    fmt = Prompt.ask("Format", default="4")
    
    output_dir = os.path.expanduser(f"~/kali-gpt-reports/report_{datetime.now().strftime('%Y%m%d_%H%M')}")
    os.makedirs(output_dir, exist_ok=True)
    
    if fmt in ['1', '4']:
        with open(f"{output_dir}/hackerone_report.md", 'w') as f:
            f.write(ReportGenerator.to_hackerone(report))
        console.print(f"[green]✓ HackerOne report saved[/green]")
    
    if fmt in ['2', '4']:
        with open(f"{output_dir}/bugcrowd_report.md", 'w') as f:
            f.write(ReportGenerator.to_bugcrowd(report))
        console.print(f"[green]✓ Bugcrowd report saved[/green]")
    
    if fmt in ['3', '4']:
        with open(f"{output_dir}/report.md", 'w') as f:
            f.write(ReportGenerator.to_markdown(report))
        console.print(f"[green]✓ Markdown report saved[/green]")
    
    with open(f"{output_dir}/report.json", 'w') as f:
        f.write(ReportGenerator.to_json(report))
    console.print(f"[green]✓ JSON report saved[/green]")
    
    console.print(f"\n[bold green]Reports saved to: {output_dir}[/bold green]")
    
    Prompt.ask("\nPress Enter to continue")


async def ai_assistant(ai_service):
    """AI assistant for bug bounty questions"""
    
    console.print(Panel(
        "[bold blue]🧠 AI BUG BOUNTY ASSISTANT[/bold blue]\n\n"
        "Ask me anything about:\n"
        "• Bug hunting techniques\n"
        "• Vulnerability exploitation\n"
        "• Report writing\n"
        "• Program scope interpretation\n"
        "• Tool recommendations\n\n"
        "[dim]Type 'exit' to return[/dim]",
        border_style="blue"
    ))
    
    context = """You are an expert bug bounty hunter AI assistant. Help users with:
- Finding vulnerabilities (XSS, SQLI, SSRF, IDOR, etc.)
- Writing high-quality bug reports
- Understanding program scope
- Recommending tools and techniques
- Estimating bug severity and bounty
Be practical, give specific commands and payloads when helpful."""
    
    while True:
        question = Prompt.ask("\n[bold]You[/bold]")
        
        if question.lower() in ['exit', 'quit', 'back']:
            break
        
        if not question:
            continue
        
        response = ai_service.ask(f"{context}\n\nUser question: {question}")
        console.print(f"\n[cyan]AI:[/cyan] {response}")


def show_statistics():
    """Show bug bounty hunting statistics"""
    
    reports_dir = os.path.expanduser("~/kali-gpt-reports")
    
    # Gather stats
    total_findings = 0
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
    total_bounty = 0
    
    if os.path.exists(reports_dir):
        for root, dirs, files in os.walk(reports_dir):
            for file in files:
                if file.endswith('.json'):
                    try:
                        with open(os.path.join(root, file)) as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                for item in data:
                                    total_findings += 1
                                    sev = item.get('severity', 'unknown')
                                    if sev in by_severity:
                                        by_severity[sev] += 1
                                    bounty = item.get('estimated_bounty', [0, 0])
                                    if isinstance(bounty, list) and len(bounty) >= 1:
                                        total_bounty += bounty[0]
                    except:
                        continue
    
    console.print(Panel(
        f"[bold]📊 BUG BOUNTY STATISTICS[/bold]\n\n"
        f"[cyan]Total Findings:[/cyan] {total_findings}\n"
        f"[red]Critical:[/red] {by_severity['critical']}\n"
        f"[yellow]High:[/yellow] {by_severity['high']}\n"
        f"[blue]Medium:[/blue] {by_severity['medium']}\n"
        f"[green]Low:[/green] {by_severity['low']}\n"
        f"[dim]Info:[/dim] {by_severity['informational']}\n\n"
        f"[green]Est. Total Bounty: ${total_bounty:,}[/green]",
        title="Statistics",
        border_style="green"
    ))
    
    Prompt.ask("\nPress Enter to continue")


# =============================================================================
# MAIN ENTRY
# =============================================================================

if __name__ == "__main__":
    print("Bug Bounty Hunter module loaded")
    print("Use bug_bounty_menu(ai_service) to start")
