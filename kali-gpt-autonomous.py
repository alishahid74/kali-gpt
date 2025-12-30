#!/usr/bin/env python3
"""
Kali-GPT v3 - Autonomous Mode

Run autonomous penetration testing with ReAct agent.
Uses local LLM (Ollama) by default - FREE and PRIVATE!

Usage:
    python kali-gpt-autonomous.py
    python kali-gpt-autonomous.py --target 192.168.1.1
    python kali-gpt-autonomous.py --provider ollama --model llama3.2
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Rich terminal UI
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich import box

# Import modules
from kali_gpt.modules.ai_service import AIService
from kali_gpt.modules.command_executor import CommandExecutor
from kali_gpt.agents.autonomous_agent import (
    AutonomousAgent, 
    AgentState, 
    AgentAction,
    AgentObservation,
    AgentThought,
    EngagementContext,
    PentestPhase
)
from kali_gpt.knowledge.mitre_attack import get_mitre_kb, Tactic
from kali_gpt.knowledge.tool_chains import ToolChainBuilder
from kali_gpt.memory.store import MemoryStore

console = Console()


def display_banner():
    """Display the application banner"""
    banner = """
[bold cyan]
██╗  ██╗ █████╗ ██╗     ██╗       ██████╗ ██████╗ ████████╗
██║ ██╔╝██╔══██╗██║     ██║      ██╔════╝ ██╔══██╗╚══██╔══╝
█████╔╝ ███████║██║     ██║█████╗██║  ███╗██████╔╝   ██║   
██╔═██╗ ██╔══██║██║     ██║╚════╝██║   ██║██╔═══╝    ██║   
██║  ██╗██║  ██║███████╗██║      ╚██████╔╝██║        ██║   
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚═╝        ╚═╝   
[/bold cyan]
[bold green]    🤖 AUTONOMOUS MODE - v3.0[/bold green]
[dim]    AI-Powered Penetration Testing Assistant[/dim]

[yellow]New Features:[/yellow]
  • 🧠 ReAct Agent - Thinks and acts like a human pentester
  • 🔓 Local LLM - Free AI with Ollama (no API costs!)
  • 📚 MITRE ATT&CK - Follows established methodology
  • ⛓️  Smart Tool Chains - Automatic tool selection
  • 💾 Memory - Learns from past engagements
"""
    console.print(banner)


def display_menu():
    """Display main menu"""
    table = Table(title="Main Menu", box=box.ROUNDED, show_header=False)
    table.add_column("Option", style="cyan", width=5)
    table.add_column("Action", style="white")
    table.add_column("Description", style="dim")
    
    menu_items = [
        ("1", "🎯 Autonomous Test", "Start autonomous pentest"),
        ("2", "👣 Step-by-Step", "Interactive guided testing"),
        ("3", "🔧 Quick Scan", "Run a quick scan"),
        ("4", "❓ Ask AI", "Ask security questions"),
        ("5", "📊 Statistics", "View past engagements"),
        ("6", "⚙️  Provider", "Switch AI provider"),
        ("0", "🚪 Exit", "Exit application"),
    ]
    
    for opt, action, desc in menu_items:
        table.add_row(opt, action, desc)
    
    console.print(table)


async def display_state(state: AgentState):
    """Display agent state change"""
    icons = {
        AgentState.IDLE: "⏸️",
        AgentState.THINKING: "🤔",
        AgentState.PLANNING: "📋",
        AgentState.EXECUTING: "⚡",
        AgentState.OBSERVING: "👁️",
        AgentState.COMPLETED: "✅",
        AgentState.ERROR: "❌"
    }
    console.print(f"\n{icons.get(state, '❓')} [bold]State:[/bold] {state.value}")


async def display_thought(thought: AgentThought):
    """Display agent thought"""
    panel = Panel(
        f"[cyan]{thought.situation_analysis}[/cyan]\n\n"
        f"[yellow]Action:[/yellow] {thought.chosen_action}\n"
        f"[dim]Confidence: {thought.confidence:.0%}[/dim]",
        title="🧠 Thinking",
        border_style="cyan"
    )
    console.print(panel)


async def confirm_action(action: AgentAction) -> bool:
    """Confirm before executing action"""
    console.print(f"\n[yellow]⚠️  Confirm Action[/yellow]")
    console.print(f"  Tool: [cyan]{action.tool}[/cyan]")
    console.print(f"  Command: [white]{action.command}[/white]")
    console.print(f"  Risk: [red]{action.risk_level}[/red]")
    
    return Confirm.ask("Execute?", default=True)


async def display_observation(observation: AgentObservation):
    """Display observation/result"""
    status = "[green]✓[/green]" if observation.success else "[red]✗[/red]"
    output = observation.output[:300] + "..." if len(observation.output) > 300 else observation.output
    
    console.print(Panel(
        f"{status} {observation.action.tool}\n\n[dim]{output}[/dim]",
        title="📊 Result",
        border_style="green" if observation.success else "red"
    ))


async def run_autonomous(ai_service: AIService, target: str):
    """Run autonomous penetration test"""
    console.print(f"\n[bold green]🎯 Starting autonomous test on {target}[/bold green]\n")
    
    # Initialize components
    memory = MemoryStore()
    await memory.initialize()
    
    mitre_kb = get_mitre_kb()
    tool_chain_builder = ToolChainBuilder()
    
    # Create wrapper for tool execution that uses existing CommandExecutor
    class ToolExecutorWrapper:
        def __init__(self):
            # Create a simple config object for CommandExecutor
            class SimpleConfig:
                def get(self, key, default=None):
                    defaults = {
                        "command_timeout": 300,
                        "allow_dangerous": False,
                    }
                    return defaults.get(key, default)
            
            try:
                self.executor = CommandExecutor(SimpleConfig())
            except TypeError:
                # If CommandExecutor doesn't need config, use without
                self.executor = CommandExecutor()
        
        async def execute(self, tool: str, command: str = None, **kwargs):
            cmd = command or tool
            try:
                result = self.executor.execute(cmd)
                return {
                    "success": result.get("returncode", 1) == 0,
                    "output": result.get("stdout", "") + result.get("stderr", ""),
                    "error": result.get("error"),
                    "findings": []
                }
            except Exception as e:
                return {
                    "success": False,
                    "output": "",
                    "error": str(e),
                    "findings": []
                }
    
    # Create wrapper for LLM that uses existing AIService
    class LLMWrapper:
        def __init__(self, ai_service):
            self.ai = ai_service
            self.config = type('Config', (), {'system_prompt': None})()
        
        async def generate(self, prompt: str, **kwargs):
            response = self.ai.ask(prompt, system_prompt=kwargs.get('system_prompt'))
            
            # Parse ReAct format
            thought, action, action_input = None, None, None
            for line in response.split('\n'):
                if line.upper().startswith('THOUGHT:'):
                    thought = line.split(':', 1)[1].strip()
                elif line.upper().startswith('ACTION:'):
                    action = line.split(':', 1)[1].strip()
                elif 'ACTION_INPUT' in line.upper() or 'ACTION INPUT' in line.upper():
                    action_input = line.split(':', 1)[1].strip() if ':' in line else None
            
            return type('Response', (), {
                'content': response,
                'thought': thought,
                'action': action,
                'action_input': action_input
            })()
        
        def set_system_prompt(self, name: str):
            pass
        
        def clear_history(self):
            self.ai.clear_history()
    
    llm_wrapper = LLMWrapper(ai_service)
    tool_executor = ToolExecutorWrapper()
    
    # Create agent
    agent = AutonomousAgent(
        llm=llm_wrapper,
        tool_executor=tool_executor
    )
    
    # Set callbacks
    agent.on_state_change = display_state
    agent.on_thought = display_thought
    agent.on_action = confirm_action
    agent.on_observation = display_observation
    
    # Initialize engagement
    await agent.initialize(target=target, scope=[target])
    
    # Create engagement in memory
    engagement_id = await memory.create_engagement(target)
    
    try:
        # Run agent
        console.print("[yellow]Running autonomous agent... (Press Ctrl+C to stop)[/yellow]\n")
        context = await agent.run(autonomous=False)  # With confirmation
        
        # Show results
        display_results(context)
        
        # Save to memory
        await memory.update_engagement(
            engagement_id,
            phase_reached=context.current_phase.value,
            total_actions=len(context.actions_taken),
            vulnerabilities_found=len(context.discovered_vulnerabilities)
        )
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
        agent.stop()


def display_results(context: EngagementContext):
    """Display engagement results"""
    summary = f"""
[bold]Target:[/bold] {context.target}
[bold]Phase:[/bold] {context.current_phase.value}
[bold]Actions:[/bold] {len(context.actions_taken)}

[cyan]Discovered:[/cyan]
  • Hosts: {len(context.discovered_hosts)}
  • Services: {len(context.discovered_services)}
  • Vulnerabilities: {len(context.discovered_vulnerabilities)}
"""
    console.print(Panel(summary, title="📊 Results", border_style="green"))


async def quick_scan(ai_service: AIService):
    """Run a quick scan"""
    target = Prompt.ask("Enter target")
    if not target:
        return
    
    scan_type = Prompt.ask(
        "Scan type",
        choices=["quick", "full", "stealth"],
        default="quick"
    )
    
    commands = {
        "quick": f"nmap -T4 -F {target}",
        "full": f"nmap -sV -sC -p- {target}",
        "stealth": f"nmap -sS -T2 -f {target}"
    }
    
    command = commands[scan_type]
    console.print(f"\n[cyan]Running: {command}[/cyan]\n")
    
    executor = CommandExecutor()
    result = executor.execute(command)
    
    console.print(Panel(
        result.get("stdout", result.get("error", "No output")),
        title="Scan Results"
    ))
    
    # AI analysis
    if Confirm.ask("Analyze with AI?", default=True):
        analysis = ai_service.analyze_output(command, result.get("stdout", ""))
        console.print(Panel(Markdown(analysis), title="🧠 AI Analysis", border_style="cyan"))


async def ask_ai(ai_service: AIService):
    """Interactive AI Q&A"""
    console.print("\n[cyan]Ask any security question (type 'back' to return)[/cyan]\n")
    
    while True:
        question = Prompt.ask("[bold]You[/bold]")
        
        if question.lower() in ['back', 'exit', 'quit']:
            break
        
        if not question:
            continue
        
        with console.status("Thinking..."):
            response = ai_service.ask(question)
        
        console.print(Panel(Markdown(response), title="🤖 Kali-GPT", border_style="cyan"))


async def show_stats():
    """Show engagement statistics"""
    memory = MemoryStore()
    await memory.initialize()
    
    stats = await memory.get_statistics()
    
    table = Table(title="📊 Statistics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Engagements", str(stats.get('total_engagements', 0)))
    table.add_row("Vulnerabilities Found", str(stats.get('total_vulnerabilities', 0)))
    table.add_row("Actions Logged", str(stats.get('total_actions', 0)))
    
    console.print(table)


def switch_provider(ai_service: AIService):
    """Switch AI provider"""
    info = ai_service.get_provider_info()
    
    console.print(f"\n[cyan]Current: {info['provider']} ({info['model']})[/cyan]")
    console.print(f"  Ollama available: {'✅' if info['ollama_available'] else '❌'}")
    console.print(f"  OpenAI available: {'✅' if info['openai_available'] else '❌'}")
    
    new_provider = Prompt.ask("Switch to", choices=["ollama", "openai"], default=info['provider'])
    
    try:
        ai_service.switch_provider(new_provider)
        console.print(f"[green]Switched to {new_provider}[/green]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Kali-GPT Autonomous Mode")
    parser.add_argument("--target", "-t", help="Target for immediate scan")
    parser.add_argument("--provider", "-p", choices=["ollama", "openai", "auto"], 
                       default="auto", help="AI provider")
    parser.add_argument("--model", "-m", help="Model name")
    args = parser.parse_args()
    
    # Set model if specified
    if args.model:
        os.environ["OLLAMA_MODEL"] = args.model
    
    display_banner()
    
    # Initialize AI service
    console.print("[cyan]Initializing AI service...[/cyan]")
    
    try:
        ai_service = AIService(provider=args.provider)
        info = ai_service.get_provider_info()
        console.print(f"[green]✓ Using {info['provider']} ({info['model']})[/green]\n")
    except Exception as e:
        console.print(f"[red]Failed to initialize AI: {e}[/red]")
        console.print("\n[yellow]To fix:[/yellow]")
        console.print("  1. Install Ollama: curl -fsSL https://ollama.com/install.sh | sh")
        console.print("  2. Pull model: ollama pull llama3.2")
        console.print("  3. Start: ollama serve")
        return
    
    # If target provided, run immediately
    if args.target:
        await run_autonomous(ai_service, args.target)
        return
    
    # Interactive menu
    while True:
        try:
            display_menu()
            choice = Prompt.ask("\nSelect", default="0")
            
            if choice == "0":
                console.print("\n[cyan]Goodbye! 🐉[/cyan]\n")
                break
            elif choice == "1":
                target = Prompt.ask("Enter target (IP/domain)")
                if target:
                    await run_autonomous(ai_service, target)
            elif choice == "2":
                target = Prompt.ask("Enter target")
                if target:
                    await run_autonomous(ai_service, target)
            elif choice == "3":
                await quick_scan(ai_service)
            elif choice == "4":
                await ask_ai(ai_service)
            elif choice == "5":
                await show_stats()
            elif choice == "6":
                switch_provider(ai_service)
            
        except KeyboardInterrupt:
            console.print("\n")
            if Confirm.ask("Exit?", default=False):
                break


if __name__ == "__main__":
    asyncio.run(main())
