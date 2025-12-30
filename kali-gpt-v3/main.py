#!/usr/bin/env python3
"""
Kali-GPT v3 - Autonomous AI Penetration Testing Assistant

Main entry point with interactive CLI interface.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box

from core.app import KaliGPTApp, AppConfig
from llm import LLMProvider, SECURITY_SYSTEM_PROMPTS
from agents import AgentState, AgentAction, AgentObservation, AgentThought, PentestPhase


console = Console()


def display_banner():
    """Display the application banner"""
    banner = """
[bold cyan]
██╗  ██╗ █████╗ ██╗     ██╗       ██████╗ ██████╗ ████████╗    ██╗   ██╗██████╗ 
██║ ██╔╝██╔══██╗██║     ██║      ██╔════╝ ██╔══██╗╚══██╔══╝    ██║   ██║╚════██╗
█████╔╝ ███████║██║     ██║█████╗██║  ███╗██████╔╝   ██║       ██║   ██║ █████╔╝
██╔═██╗ ██╔══██║██║     ██║╚════╝██║   ██║██╔═══╝    ██║       ╚██╗ ██╔╝ ╚═══██╗
██║  ██╗██║  ██║███████╗██║      ╚██████╔╝██║        ██║        ╚████╔╝ ██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚═╝        ╚═╝         ╚═══╝  ╚═════╝ 
[/bold cyan]
[bold green]        Autonomous AI-Powered Penetration Testing Assistant[/bold green]
[dim]                        Version 3.0.0 - Phase 1[/dim]

[yellow]Features:[/yellow]
  • 🤖 Autonomous ReAct Agent - Reasons and acts like a human pentester
  • 🧠 Local LLM Support - Free, private AI with Ollama
  • 💾 Persistent Memory - Learns from past engagements  
  • 🔧 Safe Tool Execution - Validated command execution
  • 📊 MITRE ATT&CK Aligned - Follows established methodology

[dim]Type 'help' for commands or start with 'scan <target>'[/dim]
"""
    console.print(banner)


def display_main_menu():
    """Display the main menu"""
    table = Table(title="Main Menu", box=box.ROUNDED, show_header=False)
    table.add_column("Option", style="cyan", width=5)
    table.add_column("Action", style="white")
    table.add_column("Description", style="dim")
    
    menu_items = [
        ("1", "🎯 New Engagement", "Start autonomous pentest"),
        ("2", "💬 Interactive Mode", "Step-by-step guided testing"),
        ("3", "🔧 Quick Command", "Execute a single tool"),
        ("4", "❓ Ask AI", "Ask security questions"),
        ("5", "📊 Statistics", "View learning statistics"),
        ("6", "⚙️  Settings", "Configure options"),
        ("7", "📚 Help", "Show help information"),
        ("0", "🚪 Exit", "Exit application"),
    ]
    
    for opt, action, desc in menu_items:
        table.add_row(opt, action, desc)
    
    console.print(table)


async def display_state_change(state: AgentState):
    """Callback for agent state changes"""
    state_icons = {
        AgentState.IDLE: "⏸️",
        AgentState.THINKING: "🤔",
        AgentState.PLANNING: "📋",
        AgentState.EXECUTING: "⚡",
        AgentState.OBSERVING: "👁️",
        AgentState.PAUSED: "⏸️",
        AgentState.COMPLETED: "✅",
        AgentState.ERROR: "❌"
    }
    icon = state_icons.get(state, "❓")
    console.print(f"\n[bold]{icon} Agent State:[/bold] {state.value}")


async def display_thought(thought: AgentThought):
    """Callback for agent thoughts"""
    panel = Panel(
        f"[cyan]{thought.situation_analysis}[/cyan]\n\n"
        f"[yellow]Chosen Action:[/yellow] {thought.chosen_action}\n"
        f"[dim]Confidence: {thought.confidence:.0%}[/dim]",
        title="🧠 Agent Thinking",
        border_style="cyan"
    )
    console.print(panel)


async def confirm_action(action: AgentAction) -> bool:
    """Callback to confirm agent actions"""
    console.print(f"\n[bold yellow]⚠️  Action Requires Confirmation[/bold yellow]")
    console.print(f"[cyan]Tool:[/cyan] {action.tool}")
    console.print(f"[cyan]Command:[/cyan] {action.command}")
    console.print(f"[cyan]Risk Level:[/cyan] {action.risk_level}")
    console.print(f"[dim]Reasoning: {action.reasoning[:200]}...[/dim]")
    
    return Confirm.ask("Execute this action?", default=False)


async def display_observation(observation: AgentObservation):
    """Callback for agent observations"""
    status = "[green]✓ Success[/green]" if observation.success else "[red]✗ Failed[/red]"
    
    # Truncate output for display
    output = observation.output[:500] + "..." if len(observation.output) > 500 else observation.output
    
    panel = Panel(
        f"{status}\n\n"
        f"[dim]{output}[/dim]\n\n"
        f"[yellow]Findings:[/yellow] {len(observation.findings)}",
        title=f"📊 Result: {observation.action.tool}",
        border_style="green" if observation.success else "red"
    )
    console.print(panel)


async def run_new_engagement(app: KaliGPTApp):
    """Start a new autonomous engagement"""
    console.print("\n[bold cyan]🎯 New Penetration Testing Engagement[/bold cyan]\n")
    
    # Get target
    target = Prompt.ask("Enter target (IP/domain/URL)")
    if not target:
        console.print("[red]No target specified[/red]")
        return
    
    # Get scope
    scope_input = Prompt.ask("Additional scope (comma-separated, or press Enter for target only)", default="")
    scope = [target]
    if scope_input:
        scope.extend([s.strip() for s in scope_input.split(",")])
    
    # Engagement type
    engagement_type = Prompt.ask(
        "Engagement type",
        choices=["black_box", "grey_box", "white_box"],
        default="black_box"
    )
    
    # Autonomous mode
    autonomous = Confirm.ask("Run autonomously? (No = step-by-step)", default=False)
    
    console.print(f"\n[bold green]Starting engagement against {target}...[/bold green]\n")
    
    try:
        if autonomous:
            # Run fully autonomous
            context = await app.run_autonomous(
                target=target,
                scope=scope,
                engagement_type=engagement_type,
                on_state_change=display_state_change,
                on_thought=display_thought,
                on_action=confirm_action,
                on_observation=display_observation
            )
            
            # Display results
            display_engagement_results(context)
        else:
            # Interactive mode
            agent = await app.start_engagement(
                target=target,
                scope=scope,
                engagement_type=engagement_type
            )
            
            # Set callbacks
            agent.on_state_change = display_state_change
            agent.on_thought = display_thought
            agent.on_action = confirm_action
            agent.on_observation = display_observation
            
            console.print("[yellow]Interactive mode - press Enter to execute each step, 'q' to quit[/yellow]\n")
            
            while True:
                user_input = Prompt.ask("Press Enter for next step (or 'q' to quit)", default="")
                
                if user_input.lower() == 'q':
                    break
                
                observation = await app.interactive_step()
                
                if observation is None:
                    console.print("[green]Engagement complete![/green]")
                    break
            
            # Display final results
            display_engagement_results(agent.context)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Engagement interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")


def display_engagement_results(context):
    """Display engagement results summary"""
    console.print("\n")
    
    # Summary panel
    summary = f"""
[bold]Target:[/bold] {context.target}
[bold]Phase Reached:[/bold] {context.current_phase.value}
[bold]Actions Taken:[/bold] {len(context.actions_taken)}
[bold]Duration:[/bold] {context.start_time}

[bold cyan]Discovered:[/bold cyan]
  • Hosts: {len(context.discovered_hosts)}
  • Services: {len(context.discovered_services)}
  • Vulnerabilities: {len(context.discovered_vulnerabilities)}
  • Credentials: {len(context.credentials_found)}
"""
    
    console.print(Panel(summary, title="📊 Engagement Results", border_style="green"))
    
    # Show vulnerabilities if any
    if context.discovered_vulnerabilities:
        vuln_table = Table(title="Discovered Vulnerabilities", box=box.ROUNDED)
        vuln_table.add_column("Type", style="red")
        vuln_table.add_column("Target", style="cyan")
        vuln_table.add_column("Details", style="white")
        
        for vuln in context.discovered_vulnerabilities[:10]:
            if isinstance(vuln, dict):
                vuln_table.add_row(
                    vuln.get("type", "Unknown"),
                    vuln.get("target", context.target),
                    str(vuln.get("description", ""))[:50]
                )
        
        console.print(vuln_table)


async def run_quick_command(app: KaliGPTApp):
    """Execute a quick command"""
    console.print("\n[bold cyan]🔧 Quick Command Execution[/bold cyan]\n")
    
    command = Prompt.ask("Enter command to execute")
    if not command:
        return
    
    # Ask for AI analysis
    analyze = Confirm.ask("Analyze output with AI?", default=True)
    
    console.print(f"\n[yellow]Executing: {command}[/yellow]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running command...", total=None)
        
        result = await app.execute_tool(command)
        
        progress.update(task, completed=True)
    
    if result["success"]:
        console.print(Panel(result["output"][:2000], title="Output", border_style="green"))
        
        if analyze and result["output"]:
            console.print("\n[cyan]Analyzing output...[/cyan]")
            
            analysis_prompt = f"""Analyze this penetration testing command output:

Command: {command}
Output:
```
{result['output'][:3000]}
```

Provide:
1. Key findings
2. Security implications
3. Recommended next steps
"""
            analysis = await app.ask(analysis_prompt)
            console.print(Panel(Markdown(analysis), title="🧠 AI Analysis", border_style="cyan"))
    else:
        console.print(Panel(
            f"[red]{result.get('error', 'Unknown error')}[/red]",
            title="Error",
            border_style="red"
        ))


async def ask_ai(app: KaliGPTApp):
    """Interactive AI Q&A"""
    console.print("\n[bold cyan]❓ Ask AI[/bold cyan]")
    console.print("[dim]Ask any security question. Type 'back' to return to menu.[/dim]\n")
    
    while True:
        question = Prompt.ask("\n[bold]You[/bold]")
        
        if question.lower() in ['back', 'exit', 'quit', 'q']:
            break
        
        if not question:
            continue
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Thinking...", total=None)
            response = await app.ask(question)
            progress.update(task, completed=True)
        
        console.print(Panel(Markdown(response), title="🤖 Kali-GPT", border_style="cyan"))


async def show_statistics(app: KaliGPTApp):
    """Show learning statistics"""
    console.print("\n[bold cyan]📊 Statistics[/bold cyan]\n")
    
    stats = await app.get_statistics()
    
    if "error" in stats:
        console.print(f"[yellow]{stats['error']}[/yellow]")
        return
    
    table = Table(title="Learning Statistics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Engagements", str(stats.get('total_engagements', 0)))
    table.add_row("Total Vulnerabilities Found", str(stats.get('total_vulnerabilities', 0)))
    table.add_row("Total Actions Logged", str(stats.get('total_actions', 0)))
    table.add_row("Average Success Rate", f"{stats.get('average_success_rate', 0):.1%}")
    
    console.print(table)
    
    # Top vulnerability types
    if stats.get('top_vulnerability_types'):
        vuln_table = Table(title="Top Vulnerability Types", box=box.ROUNDED)
        vuln_table.add_column("Type", style="red")
        vuln_table.add_column("Count", style="white")
        
        for vt in stats['top_vulnerability_types']:
            vuln_table.add_row(vt['type'], str(vt['count']))
        
        console.print(vuln_table)


async def show_settings(app: KaliGPTApp):
    """Show and modify settings"""
    console.print("\n[bold cyan]⚙️ Settings[/bold cyan]\n")
    
    # Current settings
    table = Table(title="Current Settings", box=box.ROUNDED)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("LLM Provider", app.config.llm_provider.value)
    table.add_row("LLM Model", app.config.llm_model)
    table.add_row("Temperature", str(app.config.llm_temperature))
    table.add_row("Specialist Mode", app.config.specialist_mode)
    table.add_row("Require Confirmation", str(app.config.require_confirmation))
    table.add_row("Memory Enabled", str(app.config.enable_memory))
    
    console.print(table)
    
    # Change settings
    if Confirm.ask("\nModify settings?", default=False):
        console.print("\n[yellow]Available specialist modes:[/yellow]")
        for mode in SECURITY_SYSTEM_PROMPTS.keys():
            console.print(f"  • {mode}")
        
        new_mode = Prompt.ask("Specialist mode", default=app.config.specialist_mode)
        if new_mode in SECURITY_SYSTEM_PROMPTS:
            app.set_specialist_mode(new_mode)
            console.print(f"[green]Mode changed to: {new_mode}[/green]")


def show_help():
    """Show help information"""
    help_text = """
# Kali-GPT v3 Help

## Quick Start
1. **New Engagement**: Start an autonomous penetration test
2. **Interactive Mode**: Step-by-step guided testing with confirmation
3. **Quick Command**: Execute individual tools

## Features

### Autonomous Agent
The AI agent follows the ReAct pattern:
- **Observe**: Gathers current state information
- **Think**: Analyzes situation and plans next action
- **Act**: Executes tools and commands
- **Learn**: Updates knowledge from results

### Local LLM Support
Uses Ollama for free, private AI:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended model
ollama pull llama3.2
```

### Memory System
Learns from past engagements:
- Remembers successful patterns
- Suggests actions based on similar targets
- Tracks vulnerability discoveries

## Specialist Modes
- **autonomous_pentester**: Full penetration testing
- **recon_specialist**: Reconnaissance focus
- **exploit_specialist**: Exploitation focus
- **web_specialist**: Web application testing

## Safety
- All commands validated before execution
- High-risk actions require confirmation
- Scope enforcement prevents accidental testing
"""
    console.print(Panel(Markdown(help_text), title="📚 Help", border_style="blue"))


async def main():
    """Main application entry point"""
    display_banner()
    
    # Initialize application
    console.print("\n[cyan]Initializing Kali-GPT v3...[/cyan]\n")
    
    app = KaliGPTApp()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Loading components...", total=None)
        
        success = await app.initialize()
        
        progress.update(task, completed=True)
    
    if not success:
        console.print("[red]Failed to initialize. Please check your setup.[/red]")
        console.print("\n[yellow]Troubleshooting:[/yellow]")
        console.print("1. Ensure Ollama is running: ollama serve")
        console.print("2. Or set OPENAI_API_KEY environment variable")
        return
    
    console.print("[green]✓ Initialization complete![/green]\n")
    
    # Main loop
    while True:
        try:
            display_main_menu()
            choice = Prompt.ask("\nSelect option", default="0")
            
            if choice == "0":
                console.print("\n[cyan]Goodbye! Happy hacking! 🐉[/cyan]\n")
                break
            elif choice == "1":
                await run_new_engagement(app)
            elif choice == "2":
                # Interactive mode is part of new engagement with autonomous=False
                await run_new_engagement(app)
            elif choice == "3":
                await run_quick_command(app)
            elif choice == "4":
                await ask_ai(app)
            elif choice == "5":
                await show_statistics(app)
            elif choice == "6":
                await show_settings(app)
            elif choice == "7":
                show_help()
            else:
                console.print("[red]Invalid option[/red]")
                
        except KeyboardInterrupt:
            console.print("\n")
            if Confirm.ask("Exit Kali-GPT?", default=False):
                break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    await app.close()


if __name__ == "__main__":
    asyncio.run(main())
