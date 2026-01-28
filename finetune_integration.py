"""
Kali-GPT Fine-Tuning Integration

Integrates Google Colab fine-tuning into Kali-GPT menu.
- Generate training data from pentest sessions
- Open Colab notebook in browser
- Export custom training examples
"""

import os
import json
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# Colab notebook URL (update with your GitHub repo)
COLAB_URL = "https://colab.research.google.com/github/alishahid74/kali-gpt/blob/main/fine_tune/Kali_GPT_Fine_Tuning.ipynb"

# Local paths
TRAINING_DATA_FILE = "custom_training_data.jsonl"
FINE_TUNE_DIR = Path.home() / ".kali-gpt" / "fine_tune"


class TrainingDataGenerator:
    """Generate training data from pentest sessions"""
    
    def __init__(self):
        self.examples: List[Dict] = []
        FINE_TUNE_DIR.mkdir(parents=True, exist_ok=True)
    
    def add_example(self, instruction: str, thought: str, action: str):
        """Add a training example"""
        example = {
            "instruction": instruction,
            "output": f"THOUGHT: {thought}\nACTION: {action}"
        }
        self.examples.append(example)
    
    def add_from_session(self, target: str, commands: List[Dict]):
        """Generate training examples from a pentest session"""
        for i, cmd in enumerate(commands):
            tool = cmd.get('tool', '')
            command = cmd.get('command', '')
            context = cmd.get('context', '')
            output_summary = cmd.get('output_summary', '')
            
            if not command:
                continue
            
            # Generate instruction based on context
            if i == 0:
                instruction = f"You are a pentester. Target is {target}. What's the first command?"
            elif context:
                instruction = f"{context} on {target}"
            else:
                instruction = f"Continue pentesting {target}. Previous findings: {output_summary[:100]}"
            
            # Generate thought
            thought = self._generate_thought(tool, context)
            
            self.add_example(instruction, thought, command)
    
    def _generate_thought(self, tool: str, context: str) -> str:
        """Generate a thought for the training example"""
        tool_thoughts = {
            'nmap': 'Port scanning to identify open services and versions',
            'nikto': 'Web vulnerability scanning for common issues',
            'gobuster': 'Directory enumeration to find hidden paths',
            'whatweb': 'Technology fingerprinting to identify web stack',
            'wpscan': 'WordPress-specific vulnerability scanning',
            'sqlmap': 'SQL injection testing and exploitation',
            'hydra': 'Brute force authentication testing',
            'enum4linux': 'SMB enumeration for shares and users',
            'sslscan': 'SSL/TLS configuration analysis',
            'nuclei': 'Template-based vulnerability scanning',
            'curl': 'HTTP request for manual testing',
            'dig': 'DNS reconnaissance',
        }
        
        tool_lower = tool.lower().split()[0] if tool else ''
        return tool_thoughts.get(tool_lower, context or 'Executing next step in methodology')
    
    def save(self, filepath: str = None) -> str:
        """Save training data to JSONL file"""
        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = FINE_TUNE_DIR / f"training_data_{timestamp}.jsonl"
        
        with open(filepath, 'w') as f:
            for example in self.examples:
                f.write(json.dumps(example) + '\n')
        
        return str(filepath)
    
    def load(self, filepath: str) -> int:
        """Load existing training data"""
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    self.examples.append(json.loads(line))
        return len(self.examples)
    
    def get_stats(self) -> Dict:
        """Get statistics about training data"""
        tools = {}
        for ex in self.examples:
            output = ex.get('output', '')
            if 'ACTION:' in output:
                action = output.split('ACTION:')[1].strip().split()[0]
                tools[action] = tools.get(action, 0) + 1
        
        return {
            'total_examples': len(self.examples),
            'tools_covered': len(tools),
            'tool_distribution': tools
        }


def show_finetune_menu():
    """Display fine-tuning menu"""
    
    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print(f"[bold]            🧠 FINE-TUNE YOUR OWN MODEL[/bold]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
    
    console.print("[dim]Train a custom AI model optimized for YOUR pentesting style![/dim]\n")
    
    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    table.add_column("", style="dim")
    
    options = [
        ("1", "🚀 Open Google Colab", "Train in browser (free GPU)"),
        ("2", "📝 Create Training Data", "Add custom examples"),
        ("3", "📊 View Training Data", "See your examples"),
        ("4", "📤 Export for Colab", "Save & get instructions"),
        ("5", "🎯 Generate from Session", "Convert pentest to training data"),
        ("b", "⬅️  Back", "Return to main menu"),
    ]
    
    for opt, name, desc in options:
        table.add_row(opt, name, desc)
    
    console.print(table)


def open_colab():
    """Open Google Colab notebook in browser"""
    console.print("\n[cyan]🚀 Opening Google Colab...[/cyan]\n")
    
    console.print(Panel(
        f"""[bold]Google Colab Fine-Tuning[/bold]

1. The notebook will open in your browser
2. Click [cyan]Runtime → Change runtime type → T4 GPU[/cyan]
3. Click [cyan]Runtime → Run all[/cyan]
4. Wait ~20 minutes for training
5. Download your fine-tuned model!

[yellow]Tip:[/yellow] Upload your custom training data in Step 2 (Option B)

[dim]URL: {COLAB_URL}[/dim]""",
        title="📋 Instructions",
        border_style="cyan"
    ))
    
    if Confirm.ask("\nOpen Colab now?", default=True):
        webbrowser.open(COLAB_URL)
        console.print("[green]✓ Opened in browser![/green]")
    else:
        console.print(f"\n[dim]Open manually: {COLAB_URL}[/dim]")


def create_training_example(generator: TrainingDataGenerator):
    """Interactively create a training example"""
    console.print("\n[bold cyan]📝 Create Training Example[/bold cyan]\n")
    console.print("[dim]Enter the details for a new training example.[/dim]\n")
    
    # Get instruction (the prompt)
    console.print("[yellow]Instruction:[/yellow] What would you ask the AI?")
    console.print("[dim]Example: 'Scan ports on 192.168.1.100' or 'Found WordPress, what next?'[/dim]")
    instruction = Prompt.ask("\nInstruction")
    
    if not instruction:
        console.print("[red]Cancelled[/red]")
        return
    
    # Get thought (reasoning)
    console.print("\n[yellow]Thought:[/yellow] What should the AI think?")
    console.print("[dim]Example: 'Need to identify open services for attack surface'[/dim]")
    thought = Prompt.ask("Thought")
    
    # Get action (command)
    console.print("\n[yellow]Action:[/yellow] What command should it output?")
    console.print("[dim]Example: 'nmap -sV -sC -T4 192.168.1.100'[/dim]")
    action = Prompt.ask("Action")
    
    if not action:
        console.print("[red]Cancelled[/red]")
        return
    
    # Preview
    console.print("\n[bold]Preview:[/bold]")
    console.print(Panel(
        f"[cyan]Instruction:[/cyan] {instruction}\n\n"
        f"[yellow]Output:[/yellow]\n"
        f"THOUGHT: {thought}\n"
        f"ACTION: {action}",
        border_style="green"
    ))
    
    if Confirm.ask("Add this example?", default=True):
        generator.add_example(instruction, thought, action)
        console.print(f"[green]✓ Added! Total examples: {len(generator.examples)}[/green]")


def view_training_data(generator: TrainingDataGenerator):
    """View current training data"""
    console.print("\n[bold cyan]📊 Training Data[/bold cyan]\n")
    
    if not generator.examples:
        console.print("[yellow]No training examples yet.[/yellow]")
        console.print("[dim]Use option 2 to create examples or option 5 to generate from sessions.[/dim]")
        return
    
    stats = generator.get_stats()
    
    console.print(f"[green]Total examples:[/green] {stats['total_examples']}")
    console.print(f"[green]Tools covered:[/green] {stats['tools_covered']}")
    
    if stats['tool_distribution']:
        console.print("\n[bold]Tool distribution:[/bold]")
        for tool, count in sorted(stats['tool_distribution'].items(), key=lambda x: -x[1])[:10]:
            bar = "█" * min(count, 20)
            console.print(f"  {tool:<15} {bar} {count}")
    
    # Show recent examples
    console.print(f"\n[bold]Recent examples:[/bold]")
    for i, ex in enumerate(generator.examples[-5:], 1):
        instruction = ex['instruction'][:50] + "..." if len(ex['instruction']) > 50 else ex['instruction']
        console.print(f"  {i}. {instruction}")
    
    if Confirm.ask("\nView all examples?", default=False):
        for i, ex in enumerate(generator.examples, 1):
            console.print(f"\n[cyan]Example {i}:[/cyan]")
            console.print(f"  [yellow]Q:[/yellow] {ex['instruction']}")
            console.print(f"  [green]A:[/green] {ex['output'][:100]}...")


def export_training_data(generator: TrainingDataGenerator):
    """Export training data for use in Colab"""
    console.print("\n[bold cyan]📤 Export Training Data[/bold cyan]\n")
    
    if not generator.examples:
        console.print("[yellow]No training examples to export.[/yellow]")
        console.print("[dim]Create some examples first (option 2 or 5).[/dim]")
        return
    
    # Save to file
    filepath = generator.save()
    
    console.print(f"[green]✓ Saved {len(generator.examples)} examples to:[/green]")
    console.print(f"  [cyan]{filepath}[/cyan]\n")
    
    console.print(Panel(
        f"""[bold]How to use in Google Colab:[/bold]

1. Open the Colab notebook (option 1)

2. In [cyan]Step 2[/cyan], use [yellow]Option B[/yellow]:
   - Uncomment the upload cell
   - Run it and upload: [cyan]{Path(filepath).name}[/cyan]

3. Continue with the rest of the notebook

[bold]File location:[/bold]
{filepath}

[dim]You can also merge this with the default training data
for better results![/dim]""",
        title="📋 Instructions",
        border_style="green"
    ))


def generate_from_attack_tree(generator: TrainingDataGenerator, attack_tree):
    """Generate training examples from an attack tree"""
    console.print("\n[bold cyan]🎯 Generate from Attack Tree[/bold cyan]\n")
    
    if not attack_tree or len(attack_tree.nodes) <= 1:
        console.print("[yellow]No attack tree data available.[/yellow]")
        console.print("[dim]Run a pentest first to generate attack tree data.[/dim]")
        return
    
    target = attack_tree.target
    commands = []
    
    # Extract commands from attack tree
    def extract_commands(node, context=""):
        if node.node_type == "action" and node.command:
            commands.append({
                'tool': node.label.replace('✓ ', '').replace('✗ ', ''),
                'command': node.command,
                'context': context,
                'output_summary': node.details[:100] if node.details else ""
            })
        
        for child in node.children:
            child_context = node.label if node.node_type == "discovery" else context
            extract_commands(child, child_context)
    
    extract_commands(attack_tree.root)
    
    if not commands:
        console.print("[yellow]No commands found in attack tree.[/yellow]")
        return
    
    console.print(f"[green]Found {len(commands)} commands from pentest on {target}[/green]\n")
    
    # Preview
    console.print("[bold]Commands to convert:[/bold]")
    for i, cmd in enumerate(commands[:5], 1):
        console.print(f"  {i}. {cmd['command'][:60]}...")
    
    if len(commands) > 5:
        console.print(f"  ... and {len(commands) - 5} more")
    
    if Confirm.ask(f"\nGenerate {len(commands)} training examples?", default=True):
        generator.add_from_session(target, commands)
        console.print(f"[green]✓ Added {len(commands)} examples! Total: {len(generator.examples)}[/green]")


def quick_add_examples(generator: TrainingDataGenerator):
    """Quick add common training examples"""
    console.print("\n[bold cyan]⚡ Quick Add Examples[/bold cyan]\n")
    
    common_examples = [
        {
            "instruction": "You are a pentester. Target is {target}. What's the first command?",
            "thought": "Start with port scanning to identify open services",
            "action": "nmap -sV -sC -T4 {target}"
        },
        {
            "instruction": "Port 80 is open on {target}. Identify the web technology.",
            "thought": "Web server detected, fingerprint technologies",
            "action": "whatweb http://{target}"
        },
        {
            "instruction": "Found Apache on {target}. Scan for vulnerabilities.",
            "thought": "Run web vulnerability scanner",
            "action": "nikto -h http://{target}"
        },
        {
            "instruction": "Find hidden directories on {target}",
            "thought": "Directory enumeration for hidden content",
            "action": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt"
        },
        {
            "instruction": "Port 445 SMB is open on {target}. Enumerate it.",
            "thought": "SMB enumeration for shares and users",
            "action": "enum4linux -a {target}"
        },
        {
            "instruction": "Check for SQL injection on http://{target}/search?q=test",
            "thought": "SQL injection testing",
            "action": "sqlmap -u \"http://{target}/search?q=test\" --batch --dbs"
        },
        {
            "instruction": "WordPress detected on {target}. What tool should I use?",
            "thought": "WordPress-specific vulnerability scanner",
            "action": "wpscan --url http://{target} --enumerate ap,at,u"
        },
        {
            "instruction": "Check SSL/TLS security on {target}",
            "thought": "SSL/TLS configuration analysis",
            "action": "sslscan {target}"
        },
    ]
    
    target = Prompt.ask("Enter target IP/domain to use in examples", default="192.168.1.100")
    
    console.print(f"\n[bold]Available example templates:[/bold]")
    for i, ex in enumerate(common_examples, 1):
        instruction = ex['instruction'].format(target=target)[:50]
        console.print(f"  {i}. {instruction}...")
    
    console.print(f"\n  [cyan]a[/cyan] - Add all ({len(common_examples)} examples)")
    console.print(f"  [cyan]c[/cyan] - Cancel")
    
    choice = Prompt.ask("\nSelect", default="a")
    
    if choice.lower() == 'c':
        return
    
    if choice.lower() == 'a':
        for ex in common_examples:
            generator.add_example(
                ex['instruction'].format(target=target),
                ex['thought'],
                ex['action'].format(target=target)
            )
        console.print(f"[green]✓ Added {len(common_examples)} examples! Total: {len(generator.examples)}[/green]")
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(common_examples):
            ex = common_examples[idx]
            generator.add_example(
                ex['instruction'].format(target=target),
                ex['thought'],
                ex['action'].format(target=target)
            )
            console.print(f"[green]✓ Added 1 example! Total: {len(generator.examples)}[/green]")


async def finetune_menu(attack_tree=None):
    """Main fine-tuning menu loop"""
    generator = TrainingDataGenerator()
    
    # Try to load existing data
    existing_files = list(FINE_TUNE_DIR.glob("training_data_*.jsonl"))
    if existing_files:
        latest = max(existing_files, key=lambda x: x.stat().st_mtime)
        try:
            count = generator.load(str(latest))
            console.print(f"[dim]Loaded {count} existing examples from {latest.name}[/dim]")
        except:
            pass
    
    while True:
        show_finetune_menu()
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice == "b":
            # Save before exiting
            if generator.examples:
                generator.save()
                console.print(f"[dim]Auto-saved {len(generator.examples)} examples[/dim]")
            break
        
        elif choice == "1":
            open_colab()
        
        elif choice == "2":
            console.print("\n[bold]Add training examples:[/bold]")
            console.print("  [cyan]1[/cyan] - Create manually")
            console.print("  [cyan]2[/cyan] - Quick add common examples")
            sub = Prompt.ask("Select", default="1")
            
            if sub == "1":
                create_training_example(generator)
            elif sub == "2":
                quick_add_examples(generator)
        
        elif choice == "3":
            view_training_data(generator)
        
        elif choice == "4":
            export_training_data(generator)
        
        elif choice == "5":
            if attack_tree:
                generate_from_attack_tree(generator, attack_tree)
            else:
                console.print("[yellow]No attack tree available.[/yellow]")
                console.print("[dim]Run a pentest first (option 1 in main menu).[/dim]")
        
        input("\nPress Enter to continue...")
    
    return generator


# Standalone test
if __name__ == "__main__":
    import asyncio
    asyncio.run(finetune_menu())
