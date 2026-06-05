#!/usr/bin/env python3
"""
Kali-GPT v5.0 - THE WORLD'S BEST AI PENTESTER

Usage:
  python3 kali-gpt-v5.py https://target.com
  python3 kali-gpt-v5.py https://target.com --source /path/to/code
  python3 kali-gpt-v5.py https://target.com --quick
"""

import argparse
import asyncio
import sys
import os
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

VERSION = "5.0.0"


def print_banner():
    banner = r"""
    ██╗  ██╗ █████╗ ██╗     ██╗       ██████╗ ██████╗ ████████╗
    ██║ ██╔╝██╔══██╗██║     ██║      ██╔════╝ ██╔══██╗╚══██╔══╝
    █████╔╝ ███████║██║     ██║█████╗██║  ███╗██████╔╝   ██║
    ██╔═██╗ ██╔══██║██║     ██║╚════╝██║   ██║██╔═══╝    ██║
    ██║  ██╗██║  ██║███████╗██║      ╚██████╔╝██║        ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚═╝        ╚═╝
                                                         v5.0
    ════════════════════════════════════════════════════════════
    THE WORLD'S BEST OPEN-SOURCE AI PENTESTER
    ════════════════════════════════════════════════════════════

    🔥 Proof-by-Exploitation  │  ⚡ 12 Parallel Agents
    📝 Source Code Analysis   │  🌐 Browser Automation
    💯 100% FREE & Offline    │  📊 Professional Reports
    """
    if RICH_AVAILABLE:
        Console().print(Panel(banner, style="bold cyan"))
    else:
        print(banner)


def print_summary_table(report):
    if RICH_AVAILABLE:
        console = Console()
        table = Table(title="🔍 Vulnerability Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="center")
        table.add_column("Status", justify="center")
        for sev, color, key in [("🔴 Critical", "red", "critical"), ("🟠 High", "orange1", "high"),
                                 ("🟡 Medium", "yellow", "medium"), ("🟢 Low", "green", "low")]:
            count = report.stats.get(key, 0)
            table.add_row(f"[{color}]{sev}[/{color}]", str(count),
                          f"[{color}]EXPLOITED[/{color}]" if count > 0 else "[dim]None[/dim]")
        console.print(table)

        vtable = Table(title="✅ Validation Results")
        vtable.add_column("Metric", style="bold")
        vtable.add_column("Value", justify="center")
        vtable.add_row("Findings Tested", str(report.stats.get("total_findings_tested", 0)))
        vtable.add_row("[green]✓ Validated Exploits[/green]", str(len(report.validated_exploits)))
        vtable.add_row("[red]✗ False Positives Eliminated[/red]", str(len(report.discarded_findings)))
        vtable.add_row("Source Code Findings", str(len(report.source_code_findings)))
        console.print(vtable)


async def run_pentest(args):
    from kali_gpt.v5.workflow.orchestrator import PentestOrchestrator, PentestConfig
    config = PentestConfig(
        target_url=args.target, source_code_path=args.source, output_dir=args.output,
        scan_type="quick" if args.quick else ("deep" if args.deep else "full"),
        skip_recon=args.skip_recon, skip_exploitation=args.skip_exploit,
        max_exploitation_attempts=args.max_attempts, timeout_minutes=args.timeout,
    )
    if args.agents:
        config.enabled_agents = args.agents.split(",")
    return await PentestOrchestrator(config).run()


def main():
    parser = argparse.ArgumentParser(description="Kali-GPT v5.0 - The World's Best AI Pentester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  %(prog)s https://target.com\n  %(prog)s https://target.com --source ./code\n  %(prog)s https://target.com --agents sqli,xss")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--source", "-s", help="Source code repo path")
    parser.add_argument("--output", "-o", default="./reports")
    parser.add_argument("--quick", "-q", action="store_true")
    parser.add_argument("--deep", "-d", action="store_true")
    parser.add_argument("--agents", "-a", help="Comma-separated agents")
    parser.add_argument("--skip-recon", action="store_true")
    parser.add_argument("--skip-exploit", action="store_true")
    parser.add_argument("--max-attempts", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--version", "-v", action="version", version=f"Kali-GPT v{VERSION}")
    args = parser.parse_args()

    if not args.target.startswith(("http://", "https://")):
        args.target = f"https://{args.target}"

    print_banner()

    try:
        report = asyncio.run(run_pentest(args))
        print_summary_table(report)
        if RICH_AVAILABLE:
            Console().print(f"\n[bold green]✓ Report saved to: {args.output}[/bold green]")
        sys.exit(2 if report.stats.get("critical", 0) > 0 else (1 if report.stats.get("high", 0) > 0 else 0))
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if os.environ.get("DEBUG"):
            import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
