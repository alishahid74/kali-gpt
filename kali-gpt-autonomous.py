#!/usr/bin/env python3
"""
Kali-GPT Autonomous Mode

AI-powered penetration testing with local LLMs.
Supports uncensored models for better results.

Usage:
    python3 kali-gpt-autonomous.py
    python3 kali-gpt-autonomous.py --model kali-pentester
    python3 kali-gpt-autonomous.py -t 192.168.1.1
"""

import asyncio
import argparse
import os
import subprocess
import shutil
import httpx
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich import box

from kali_gpt.modules.ai_service import AIService
from kali_gpt.agents.autonomous_agent import (
    AutonomousAgent, AgentState, AgentAction,
    AgentObservation, AgentThought, EngagementContext, PentestPhase
)
from kali_gpt.knowledge.mitre_attack import get_mitre_kb
from kali_gpt.knowledge.tool_chains import ToolChainBuilder
from kali_gpt.memory.store import MemoryStore

console = Console()

# Tools that are OK to run
VALID_TOOLS = {
    'nmap', 'masscan', 'unicornscan', 'hping3', 'arping',
    'nikto', 'gobuster', 'dirb', 'ffuf', 'wfuzz', 'feroxbuster',
    'whatweb', 'wpscan', 'joomscan', 'droopescan', 'wapiti',
    'dig', 'host', 'nslookup', 'dnsrecon', 'dnsenum', 'fierce',
    'curl', 'wget', 'http',
    'whois', 'theharvester', 'amass', 'sublist3r', 'subfinder',
    'sqlmap', 'commix', 'xsser', 'searchsploit', 'msfconsole',
    'hydra', 'medusa', 'john', 'hashcat', 'crunch', 'cewl',
    'enum4linux', 'smbclient', 'smbmap', 'crackmapexec', 'rpcclient',
    'netcat', 'nc', 'ncat', 'socat', 'telnet',
    'tcpdump', 'tshark',
    'nuclei', 'httpx', 'katana', 'gau', 'waybackurls',
    'sslscan', 'sslyze', 'testssl',
    'python', 'python3', 'perl', 'ruby', 'bash', 'sh',
    'cat', 'grep', 'awk', 'sed', 'head', 'tail', 'wc',
    'ls', 'find', 'file', 'strings', 'base64',
    'ping', 'traceroute', 'netstat', 'ss',
}

# Don't try to run these (GUI apps)
GUI_TOOLS = {'burpsuite', 'wireshark', 'zenmap', 'armitage', 'maltego', 'zaproxy'}

# If the LLM output starts with these, it's probably a description not a command
DESCRIPTION_WORDS = {
    'scan', 'review', 'conduct', 'perform', 'execute', 'run', 'use', 'start',
    'open', 'launch', 'check', 'analyze', 'identify', 'gather', 'collect',
    'find', 'search', 'look', 'examine', 'investigate', 'assess', 'test',
    'verify', 'confirm', 'enumerate', 'discover', 'detect', 'exploit',
    'attempt', 'try', 'begin', 'initiate', 'continue', 'move', 'next',
    'now', 'then', 'should', 'would', 'could', 'let', 'need', 'want',
    'going', 'will', 'shall', 'the', 'a', 'an'
}

# Models that won't refuse security queries
UNCENSORED_MODELS = [
    'kali-pentester', 'kali-redteam',
    'dolphin-llama3', 'dolphin-mistral', 'dolphin-mixtral',
    'openhermes', 'nous-hermes', 'wizard-vicuna-uncensored',
]

# Track current model globally
CURRENT_MODEL = None
CURRENT_PROVIDER = None


def get_ollama_models():
    """Get list of models from Ollama"""
    try:
        r = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if r.status_code == 200:
            return [m.get("name", "") for m in r.json().get("models", [])]
    except:
        pass
    return []


def pick_best_model(models):
    """Auto-select the best uncensored model"""
    for preferred in UNCENSORED_MODELS:
        for m in models:
            if preferred in m.lower():
                return m
    return models[0] if models else "llama3.2"


def is_uncensored(model_name):
    """Check if model is uncensored"""
    m = model_name.lower()
    return any(u in m for u in UNCENSORED_MODELS)


def is_valid_command(action):
    """Check if this looks like a real command"""
    if not action or len(action) < 3:
        return False
    first = action.split()[0].lower().strip('`"\'')
    if first in VALID_TOOLS:
        return True
    if first in DESCRIPTION_WORDS:
        return False
    return False


def add_target_if_missing(cmd, target):
    """Make sure target is in the command"""
    if not target or not cmd:
        return cmd
    if target in cmd:
        return cmd
    
    tool = cmd.split()[0].lower()
    
    if tool == 'nmap':
        return f"{cmd} {target}"
    elif tool == 'nikto' and '-h' not in cmd:
        return f"{cmd} -h https://{target}"
    elif tool == 'gobuster' and '-u' not in cmd:
        return f"gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -k -q"
    elif tool == 'whatweb':
        return f"{cmd} https://{target}"
    elif tool == 'curl' and 'http' not in cmd:
        return f"{cmd} https://{target}"
    elif tool in ['dig', 'whois', 'host', 'dnsrecon', 'sslscan']:
        return f"{cmd} {target}"
    
    return cmd


def get_timeout(tool):
    """Get timeout for a tool"""
    t = tool.lower().split()[0]
    if t in ['nmap', 'masscan']:
        return 300
    elif t in ['nikto', 'wpscan', 'sqlmap', 'nuclei']:
        return 180
    elif t in ['gobuster', 'dirb', 'ffuf']:
        return 180
    return 90


def show_banner():
    """Show the banner"""
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
[dim]    AI-Powered Penetration Testing[/dim]
"""
    console.print(banner)


def show_menu():
    """Show main menu"""
    table = Table(title="Main Menu", box=box.ROUNDED, show_header=False)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    table.add_column("", style="dim")
    
    items = [
        ("1", "🎯 Autonomous Test", "AI-driven pentest"),
        ("2", "👣 Step-by-Step", "Guided testing"),
        ("3", "🔧 Quick Scan", "Just nmap"),
        ("4", "❓ Ask AI", "Chat mode"),
        ("5", "📊 Statistics", "Past engagements"),
        ("6", "⚙️  Models", "Select model"),
        ("0", "🚪 Exit", ""),
    ]
    
    for opt, action, desc in items:
        table.add_row(opt, action, desc)
    
    console.print(table)


# Agent callbacks
async def on_state_change(state):
    icons = {
        AgentState.IDLE: "⏸️", AgentState.THINKING: "🤔",
        AgentState.PLANNING: "📋", AgentState.EXECUTING: "⚡",
        AgentState.OBSERVING: "👁️", AgentState.COMPLETED: "✅",
        AgentState.ERROR: "❌"
    }
    console.print(f"\n{icons.get(state, '❓')} [bold]{state.value}[/bold]")


async def on_thought(thought):
    panel = Panel(
        f"[cyan]{thought.situation_analysis}[/cyan]\n\n"
        f"[yellow]Action:[/yellow] {thought.chosen_action}\n"
        f"[dim]Confidence: {thought.confidence:.0%}[/dim]",
        title="🧠 Thinking", border_style="cyan"
    )
    console.print(panel)


async def on_action(action):
    console.print(f"\n[yellow]⚠️  Confirm Action[/yellow]")
    console.print(f"  Tool: [cyan]{action.tool}[/cyan]")
    console.print(f"  Command: [white]`{action.command}`[/white]")
    risk = 'red' if action.risk_level in ['high', 'critical'] else 'yellow'
    console.print(f"  Risk: [{risk}]{action.risk_level}[/]")
    return Confirm.ask("Execute?", default=True)


async def on_observation(obs):
    status = "[green]✓[/green]" if obs.success else "[red]✗[/red]"
    output = obs.output[:1500] + "..." if len(obs.output) > 1500 else obs.output
    err = f"\n[red]Error: {obs.error}[/red]" if obs.error else ""
    cmd = obs.action.command if obs.action else "?"
    console.print(Panel(
        f"{status} Command: [cyan]{cmd}[/cyan]{err}\n\n{output}",
        title="📊 Result",
        border_style="green" if obs.success else "red"
    ))


async def run_pentest(ai_service, target):
    """Run autonomous pentest"""
    global CURRENT_MODEL
    
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    console.print(f"\n[bold green]🎯 Starting pentest on {target}[/bold green]\n")
    
    info = ai_service.get_provider_info()
    model = CURRENT_MODEL or info.get('model', '')
    uncensored = is_uncensored(model)
    
    if uncensored:
        console.print(f"[green]🐬 Using: {model}[/green]\n")
    else:
        console.print(f"[yellow]⚠️ Using: {model} (standard model)[/yellow]")
        console.print(f"[dim]Tip: Use option 6 to pick an uncensored model[/dim]\n")
    
    memory = MemoryStore()
    await memory.initialize()
    
    # Tool executor
    class ToolRunner:
        def __init__(self, target):
            self.target = target
            self.ran = set()
        
        async def execute(self, tool, command=None, **kw):
            cmd = (command or tool).strip().strip('`')
            cmd = add_target_if_missing(cmd, self.target)
            
            if not is_valid_command(cmd):
                console.print(f"[red]✗ Bad command: {cmd[:50]}[/red]")
                return {"success": False, "output": "", "error": "Invalid", "findings": []}
            
            tool_name = cmd.split()[0].lower()
            
            if tool_name in GUI_TOOLS:
                return {"success": False, "output": "", "error": "GUI tool", "findings": []}
            
            if not shutil.which(tool_name):
                console.print(f"[yellow]⚠️ Not installed: {tool_name}[/yellow]")
                return {"success": False, "output": "", "error": "Not found", "findings": []}
            
            if cmd in self.ran:
                return {"success": True, "output": "Already ran", "error": None, "findings": []}
            
            self.ran.add(cmd)
            console.print(f"[cyan]$ {cmd}[/cyan]")
            
            timeout = get_timeout(tool_name)
            
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                out = r.stdout + r.stderr
                ok = r.returncode == 0 or len(out.strip()) > 10
                return {"success": ok, "output": out or "Done", "error": None, "findings": []}
            except subprocess.TimeoutExpired:
                return {"success": False, "output": "", "error": f"Timeout ({timeout}s)", "findings": []}
            except Exception as e:
                return {"success": False, "output": "", "error": str(e), "findings": []}
    
    # LLM wrapper
    class LLMWrapper:
        def __init__(self, ai, target, uncensored=False):
            self.ai = ai
            self.target = target
            self.config = type('C', (), {'system_prompt': None})()
            self.history = set()
            self.fb_idx = 0
            
            # Fallback commands - all have target
            self.fallbacks = [
                f"nmap -sV -sC -T4 {target}",
                f"curl -sIk https://{target}",
                f"whatweb https://{target}",
                f"dig {target} ANY +short",
                f"whois {target}",
                f"gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -k -q -t 30",
                f"nikto -h https://{target} -maxtime 60",
                f"curl -sk https://{target}/robots.txt",
                f"curl -sk https://{target}/sitemap.xml",
                f"nmap --script=vuln -p80,443 {target}",
                f"nmap --script=http-enum -p80,443 {target}",
                f"host {target}",
                f"sslscan {target}",
                f"curl -sk https://{target}/.git/HEAD",
                f"curl -sk https://{target}/admin",
                f"nmap -sV -p21,22,25,80,443,3306,8080 {target}",
            ]
            
            self.prompt = f"""You are a penetration tester. Target: {target}

IMPORTANT: Every command must include the target {target}

Format:
THOUGHT: Brief analysis
ACTION: Complete command with {target}

Examples:
THOUGHT: Scan ports
ACTION: nmap -sV -sC -T4 {target}

THOUGHT: Check web
ACTION: whatweb https://{target}

THOUGHT: Find dirs
ACTION: gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -k -q

WRONG:
ACTION: nmap           <- missing target
ACTION: Scan ports     <- description, not command

Always include {target} in your command!"""
        
        async def generate(self, prompt, **kw):
            resp = self.ai.ask(prompt, system_prompt=self.prompt)
            
            thought, action = None, None
            
            for line in resp.split('\n'):
                line = line.strip()
                up = line.upper()
                
                if up.startswith('THOUGHT:'):
                    thought = line.split(':', 1)[1].strip()
                
                elif up.startswith('ACTION:') and 'INPUT' not in up:
                    potential = line.split(':', 1)[1].strip().strip('`"\'')
                    potential = add_target_if_missing(potential, self.target)
                    
                    if is_valid_command(potential) and len(potential.split()) > 1:
                        action = potential
                        console.print(f"[green]✓ {action.split()[0]}[/green]")
                    else:
                        w = potential.split()[0] if potential else "?"
                        console.print(f"[yellow]✗ Incomplete: {w}[/yellow]")
            
            # Fallback
            if not action:
                while self.fb_idx < len(self.fallbacks):
                    action = self.fallbacks[self.fb_idx]
                    self.fb_idx += 1
                    if action not in self.history:
                        console.print(f"[yellow]→ Fallback: {action.split()[0]}[/yellow]")
                        thought = f"Running: {action.split()[0]}"
                        break
                else:
                    action = None
            
            # Skip dupes
            if action and action in self.history:
                console.print(f"[dim]Duplicate, next...[/dim]")
                while self.fb_idx < len(self.fallbacks):
                    action = self.fallbacks[self.fb_idx]
                    self.fb_idx += 1
                    if action not in self.history:
                        break
                else:
                    action = None
            
            if action:
                self.history.add(action)
            
            return type('R', (), {
                'content': resp,
                'thought': thought or "...",
                'action': action,
                'action_input': self.target
            })()
        
        def set_system_prompt(self, n): pass
        def clear_history(self):
            self.ai.clear_history()
            self.history = set()
            self.fb_idx = 0
    
    llm = LLMWrapper(ai_service, target, uncensored)
    runner = ToolRunner(target)
    
    agent = AutonomousAgent(llm=llm, tool_executor=runner)
    agent.on_state_change = on_state_change
    agent.on_thought = on_thought
    agent.on_action = on_action
    agent.on_observation = on_observation
    
    await agent.initialize(target=target, scope=[target])
    agent.max_iterations = 20
    
    eid = await memory.create_engagement(target)
    
    try:
        console.print("[yellow]Running... (Ctrl+C to stop)[/yellow]\n")
        ctx = await agent.run(autonomous=False)
        show_results(ctx)
        await memory.update_engagement(eid,
            phase_reached=ctx.current_phase.value,
            total_actions=len(ctx.actions_taken),
            vulnerabilities_found=len(ctx.discovered_vulnerabilities))
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped[/yellow]")
        agent.stop()


def show_results(ctx):
    """Show pentest results"""
    s = f"""
[bold]Target:[/bold] {ctx.target}
[bold]Phase:[/bold] {ctx.current_phase.value}
[bold]Actions:[/bold] {len(ctx.actions_taken)}

[cyan]Found:[/cyan]
  • Hosts: {len(ctx.discovered_hosts)}
  • Services: {len(ctx.discovered_services)}
  • Vulns: {len(ctx.discovered_vulnerabilities)}
"""
    console.print(Panel(s, title="📊 Results", border_style="green"))


async def quick_scan(ai):
    """Quick nmap scan"""
    target = Prompt.ask("Target")
    if not target:
        return
    
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    
    scan = Prompt.ask("Type", choices=["quick", "full", "stealth", "vuln"], default="quick")
    
    cmds = {
        "quick": f"nmap -T4 -F {target}",
        "full": f"nmap -sV -sC -p- {target}",
        "stealth": f"nmap -sS -T2 -f {target}",
        "vuln": f"nmap --script=vuln {target}"
    }
    
    cmd = cmds[scan]
    timeout = 600 if scan == "full" else 300
    
    console.print(f"\n[cyan]$ {cmd}[/cyan]\n")
    
    try:
        with console.status("[green]Scanning...[/green]"):
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        
        out = r.stdout + r.stderr or "Done"
        console.print(Panel(out, title="Results", border_style="green" if r.returncode == 0 else "red"))
        
        if Confirm.ask("Analyze with AI?", default=True):
            with console.status("[cyan]Analyzing...[/cyan]"):
                analysis = ai.analyze_output(cmd, out)
            console.print(Panel(Markdown(analysis), title="🧠 Analysis", border_style="cyan"))
    
    except subprocess.TimeoutExpired:
        console.print("[red]Timeout[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


async def ask_ai(ai):
    """Chat with AI"""
    console.print("\n[cyan]Ask anything ('back' to return)[/cyan]\n")
    
    while True:
        q = Prompt.ask("[bold]You[/bold]")
        if q.lower() in ['back', 'exit', 'quit', 'q']:
            break
        if not q.strip():
            continue
        
        with console.status("..."):
            r = ai.ask(q)
        console.print(Panel(Markdown(r), title="🤖 AI", border_style="cyan"))


async def show_stats():
    """Show stats"""
    mem = MemoryStore()
    await mem.initialize()
    stats = await mem.get_statistics()
    
    t = Table(title="📊 Stats", box=box.ROUNDED)
    t.add_column("", style="cyan")
    t.add_column("", style="green")
    t.add_row("Engagements", str(stats.get('total_engagements', 0)))
    t.add_row("Vulns Found", str(stats.get('total_vulnerabilities', 0)))
    t.add_row("Actions", str(stats.get('total_actions', 0)))
    console.print(t)


def model_menu(ai):
    """Model selection"""
    global CURRENT_MODEL, CURRENT_PROVIDER
    
    while True:
        info = ai.get_provider_info()
        cur_model = CURRENT_MODEL or info.get('model', '?')
        cur_prov = CURRENT_PROVIDER or info.get('provider', '?')
        
        models = get_ollama_models()
        
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold]                    ⚙️  MODEL SELECTION[/bold]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        
        console.print(f"  Current: [green]{cur_prov} → {cur_model}[/green]")
        if is_uncensored(cur_model):
            console.print(f"  [green]🐬 Uncensored[/green]")
        else:
            console.print(f"  [yellow]⚠️ Standard[/yellow]")
        
        console.print(f"\n  Ollama: {'[green]✅[/green]' if models else '[red]❌[/red]'}")
        console.print(f"  OpenAI: {'[green]✅[/green]' if info.get('openai_available') else '[yellow]⚠️[/yellow]'}")
        
        all_models = []
        
        if models:
            console.print(f"\n[bold]Ollama Models:[/bold]")
            t = Table(box=box.SIMPLE)
            t.add_column("#", style="cyan", width=3)
            t.add_column("Model", width=30)
            t.add_column("Type", width=15)
            t.add_column("", width=10)
            
            for i, m in enumerate(models, 1):
                mtype = "[green]🐬 Uncensored[/green]" if is_uncensored(m) else "[dim]Standard[/dim]"
                cur = "[green]◀[/green]" if m == cur_model else ""
                t.add_row(str(i), m, mtype, cur)
                all_models.append(("ollama", m))
            
            console.print(t)
        
        if info.get('openai_available'):
            console.print(f"\n[bold]OpenAI:[/bold]")
            t = Table(box=box.SIMPLE)
            t.add_column("#", style="cyan", width=3)
            t.add_column("Model", width=30)
            t.add_column("Type", width=15)
            t.add_column("", width=10)
            
            for m in ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"]:
                idx = len(all_models) + 1
                cur = "[green]◀[/green]" if m == cur_model else ""
                t.add_row(str(idx), m, "[dim]Cloud ($)[/dim]", cur)
                all_models.append(("openai", m))
            
            console.print(t)
        
        # Recommendations
        console.print(f"\n[yellow]Recommended:[/yellow]")
        for i, (p, m) in enumerate(all_models, 1):
            if is_uncensored(m):
                console.print(f"   [green]→ {i}. {m}[/green]")
        
        console.print(f"\n[dim]Enter number or 'b' to go back[/dim]")
        
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice.lower() == 'b':
            break
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(all_models):
                prov, model = all_models[idx]
                try:
                    os.environ["OLLAMA_MODEL"] = model
                    ai.switch_provider(prov)
                    CURRENT_MODEL = model
                    CURRENT_PROVIDER = prov
                    console.print(f"\n[green]✅ Switched to {model}[/green]")
                    if is_uncensored(model):
                        console.print(f"   [green]🐬 Uncensored mode![/green]")
                    input("\nEnter to continue...")
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")


async def main():
    """Main"""
    global CURRENT_MODEL, CURRENT_PROVIDER
    
    parser = argparse.ArgumentParser(description="Kali-GPT")
    parser.add_argument("--target", "-t", help="Target")
    parser.add_argument("--provider", "-p", choices=["ollama", "openai", "auto"], default="auto")
    parser.add_argument("--model", "-m", help="Model")
    args = parser.parse_args()
    
    # Auto-pick best model
    if args.model:
        os.environ["OLLAMA_MODEL"] = args.model
        CURRENT_MODEL = args.model
    else:
        models = get_ollama_models()
        if models:
            best = pick_best_model(models)
            os.environ["OLLAMA_MODEL"] = best
            CURRENT_MODEL = best
    
    show_banner()
    console.print("[cyan]Initializing...[/cyan]")
    
    try:
        ai = AIService(provider=args.provider)
        info = ai.get_provider_info()
        
        CURRENT_PROVIDER = info.get('provider', 'ollama')
        if not CURRENT_MODEL:
            CURRENT_MODEL = info.get('model', '?')
        
        if is_uncensored(CURRENT_MODEL):
            console.print(f"[green]🐬 {CURRENT_PROVIDER} → {CURRENT_MODEL}[/green]\n")
        else:
            console.print(f"[yellow]⚠️ {CURRENT_PROVIDER} → {CURRENT_MODEL}[/yellow]")
            console.print(f"[dim]Use option 6 for uncensored model[/dim]\n")
            
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        console.print("\n[yellow]Setup:[/yellow]")
        console.print("  curl -fsSL https://ollama.com/install.sh | sh")
        console.print("  ./install-models.sh")
        return
    
    # Direct target
    if args.target:
        await run_pentest(ai, args.target)
        return
    
    # Menu loop
    while True:
        try:
            show_menu()
            c = Prompt.ask("\nSelect", default="0")
            
            if c == "0":
                console.print("\n[cyan]Bye![/cyan]\n")
                break
            elif c in ["1", "2"]:
                t = Prompt.ask("Target")
                if t:
                    await run_pentest(ai, t)
            elif c == "3":
                await quick_scan(ai)
            elif c == "4":
                await ask_ai(ai)
            elif c == "5":
                await show_stats()
            elif c == "6":
                model_menu(ai)
                
        except KeyboardInterrupt:
            console.print("\n")
            if Confirm.ask("Exit?", default=False):
                break


if __name__ == "__main__":
    asyncio.run(main())
