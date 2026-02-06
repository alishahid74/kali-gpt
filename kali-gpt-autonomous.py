#!/usr/bin/env python3
"""
Kali-GPT v4.1 - Ultimate AI Penetration Testing Framework

🚀 NEW IN v4.1:
- Command Sanitizer (fixes AI command parsing bug)
- REST API Server with WebSocket support
- Bug Bounty Hunter module
- Enhanced Report Generator
- Persistent Memory across sessions
- Auto-Exploitation Engine

🚀 FEATURES FROM v4.0:
- 220+ Security Tools (vs HexStrike's 150+)
- 12 Specialized AI Agents
- Cloud Security Module (AWS/Azure/GCP/K8s)
- Binary Analysis & CTF Toolkit
- Browser Automation (Selenium/Playwright)
- MCP Server for IDE Integration
- 100% FREE - Runs locally with Ollama

Features:
- Option 1: Autonomous AI Pentest
- Option 2: Step-by-Step Guided Mode
- Option 3: Quick Scan (nmap)
- Option 4: Ask AI (Chat mode)
- Option 5: Statistics
- Option 6: Model Selection
- Option 7: Attack Tree Visualization
- Option 8: Fine-tune Custom Model
- Option 9: Multi-Agent Collaboration (12 agents)
- Option 10: Cloud Security Assessment
- Option 11: CTF Mode
- Option 12: Browser Automation

Usage:
    python3 kali-gpt-autonomous.py
    python3 kali-gpt-autonomous.py --model kali-pentester
    python3 kali-gpt-autonomous.py --mcp  # Start MCP server
"""

import asyncio
import argparse
import os
import subprocess
import shutil
import httpx
import re
import webbrowser
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich.tree import Tree as RichTree
from rich import box

from kali_gpt.modules.ai_service import AIService
from kali_gpt.agents.autonomous_agent import (
    AutonomousAgent, AgentState, AgentAction,
    AgentObservation, AgentThought, EngagementContext, PentestPhase
)
from kali_gpt.knowledge.mitre_attack import get_mitre_kb
from kali_gpt.knowledge.tool_chains import ToolChainBuilder
from kali_gpt.memory.store import MemoryStore

# Try to import fine-tuning integration (optional)
try:
    from kali_gpt.finetune_integration import finetune_menu
    FINETUNE_AVAILABLE = True
except ImportError:
    FINETUNE_AVAILABLE = False

# Try to import multi-agent system (optional)
try:
    from kali_gpt.multi_agent import MultiAgentPentest, multi_agent_menu
    MULTIAGENT_AVAILABLE = True
except ImportError:
    MULTIAGENT_AVAILABLE = False

# Try to import v4 agents
try:
    from kali_gpt.agents.agents_v4 import MultiAgentPentest as MultiAgentV4
    AGENTS_V4_AVAILABLE = True
except ImportError:
    AGENTS_V4_AVAILABLE = False

# Try to import tool registry
try:
    from kali_gpt.tools.tool_registry import TOOLS, count as tool_count, stats as tool_stats
    TOOL_REGISTRY_AVAILABLE = True
except ImportError:
    TOOL_REGISTRY_AVAILABLE = False
    tool_count = lambda: 50
    tool_stats = lambda: {}

# Try to import browser agent
try:
    from kali_gpt.tools.browser_agent import BrowserAgent, display_browser_result
    BROWSER_AVAILABLE = True
except ImportError:
    BROWSER_AVAILABLE = False

# v4.1 Feature Imports
try:
    from kali_gpt.report_generator import ReportGenerator, report_menu
    REPORTS_AVAILABLE = True
except ImportError:
    REPORTS_AVAILABLE = False

try:
    from kali_gpt.persistent_memory import MemoryManager, memory_menu
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False

try:
    from kali_gpt.exploit_engine import ExploitEngine, exploit_menu
    EXPLOIT_AVAILABLE = True
except ImportError:
    EXPLOIT_AVAILABLE = False

try:
    from kali_gpt.bug_bounty_menu import bug_bounty_menu
    BUGBOUNTY_AVAILABLE = True
except ImportError:
    BUGBOUNTY_AVAILABLE = False

try:
    from kali_gpt.api_server import app as api_app
    API_AVAILABLE = True
except Exception:
    API_AVAILABLE = False

# Try to import MCP server
try:
    from kali_gpt.tools.mcp_server import KALI_TOOLS, execute_tool
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

console = Console()

# ============================================================================
# ATTACK TREE (Phase 4)
# ============================================================================

class NodeType:
    ROOT = "root"
    DISCOVERY = "discovery"
    ACTION = "action"
    FINDING = "finding"
    CREDENTIAL = "credential"
    ACCESS = "access"


class AttackNode:
    """Single node in attack tree"""
    def __init__(self, id: str, label: str, node_type: str, details: str = "", 
                 command: str = "", risk: str = "info"):
        self.id = id
        self.label = label
        self.node_type = node_type
        self.details = details
        self.command = command
        self.risk = risk
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.children = []
        self.parent = None
    
    def add_child(self, child):
        child.parent = self
        self.children.append(child)
        return child


class AttackTree:
    """
    Tracks attack path during pentest
    """
    def __init__(self, target: str):
        self.target = target
        self.root = AttackNode("root", f"🎯 {target}", NodeType.ROOT)
        self.nodes = {"root": self.root}
        self.counter = 0
        self.current_node = self.root
        self.start_time = datetime.now()
    
    def _new_id(self) -> str:
        self.counter += 1
        return f"n{self.counter}"
    
    def add_discovery(self, label: str, details: str = "", parent=None) -> AttackNode:
        """Add discovery (port, service, etc)"""
        node = AttackNode(self._new_id(), f"🔍 {label}", NodeType.DISCOVERY, details)
        (parent or self.root).add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_action(self, tool: str, command: str, success: bool = True, 
                   output: str = "", parent=None) -> AttackNode:
        """Add tool execution"""
        icon = "✓" if success else "✗"
        label = f"{icon} {tool}"
        node = AttackNode(self._new_id(), label, NodeType.ACTION, 
                         command=command, details=output[:200])
        (parent or self.current_node).add_child(node)
        self.nodes[node.id] = node
        self.current_node = node
        return node
    
    def add_finding(self, label: str, risk: str = "info", parent=None) -> AttackNode:
        """Add finding/vulnerability"""
        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
        icon = icons.get(risk, "🔵")
        node = AttackNode(self._new_id(), f"{icon} {label}", NodeType.FINDING, risk=risk)
        (parent or self.current_node).add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_credential(self, label: str, parent=None) -> AttackNode:
        """Add found credential"""
        node = AttackNode(self._new_id(), f"🔑 {label}", NodeType.CREDENTIAL, risk="critical")
        (parent or self.current_node).add_child(node)
        self.nodes[node.id] = node
        return node
    
    def add_access(self, label: str, parent=None) -> AttackNode:
        """Add access gained"""
        node = AttackNode(self._new_id(), f"💻 {label}", NodeType.ACCESS, risk="critical")
        (parent or self.current_node).add_child(node)
        self.nodes[node.id] = node
        return node
    
    def to_ascii(self) -> str:
        """Generate ASCII tree"""
        lines = []
        lines.append("")
        lines.append("╔═══════════════════════════════════════════════════════════════╗")
        lines.append("║                       ATTACK TREE                             ║")
        lines.append("╚═══════════════════════════════════════════════════════════════╝")
        lines.append("")
        
        def render(node, prefix="", is_last=True):
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{node.label}")
            
            if node.command:
                p = prefix + ("    " if is_last else "│   ")
                cmd = node.command[:60] + "..." if len(node.command) > 60 else node.command
                lines.append(f"{p}[dim]$ {cmd}[/dim]")
            
            child_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(node.children):
                render(child, child_prefix, i == len(node.children) - 1)
        
        lines.append(f"🎯 {self.target}")
        for i, child in enumerate(self.root.children):
            render(child, "", i == len(self.root.children) - 1)
        
        # Stats
        lines.append("")
        lines.append("─" * 60)
        discoveries = sum(1 for n in self.nodes.values() if n.node_type == NodeType.DISCOVERY)
        actions = sum(1 for n in self.nodes.values() if n.node_type == NodeType.ACTION)
        findings = sum(1 for n in self.nodes.values() if n.node_type == NodeType.FINDING)
        lines.append(f"Discoveries: {discoveries} | Actions: {actions} | Findings: {findings}")
        lines.append("")
        
        return "\n".join(lines)
    
    def to_rich_tree(self) -> RichTree:
        """Generate Rich tree for terminal"""
        tree = RichTree(f"[bold red]🎯 {self.target}[/bold red]")
        
        def add_nodes(parent_tree, node):
            for child in node.children:
                style = "green" if "✓" in child.label else "yellow"
                if "🔴" in child.label:
                    style = "red bold"
                elif "🟠" in child.label:
                    style = "yellow bold"
                
                branch = parent_tree.add(f"[{style}]{child.label}[/{style}]")
                
                if child.command:
                    branch.add(f"[dim]$ {child.command[:50]}...[/dim]" if len(child.command) > 50 
                              else f"[dim]$ {child.command}[/dim]")
                
                add_nodes(branch, child)
        
        add_nodes(tree, self.root)
        return tree
    
    def export_html(self, filepath: str = None) -> str:
        """Export interactive HTML visualization"""
        if not filepath:
            filepath = f"attack_tree_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Build nodes and edges for vis.js
        nodes_data = []
        edges_data = []
        
        def process(node, level=0):
            colors = {
                NodeType.ROOT: "#e74c3c",
                NodeType.DISCOVERY: "#3498db",
                NodeType.ACTION: "#2ecc71",
                NodeType.FINDING: "#f39c12",
                NodeType.CREDENTIAL: "#9b59b6",
                NodeType.ACCESS: "#e74c3c"
            }
            
            risk_colors = {"critical": "#e74c3c", "high": "#e67e22", 
                          "medium": "#f1c40f", "low": "#2ecc71", "info": "#3498db"}
            
            color = colors.get(node.node_type, "#888")
            if node.node_type == NodeType.FINDING:
                color = risk_colors.get(node.risk, "#f39c12")
            
            # Clean label for HTML
            label = ''.join(c for c in node.label if ord(c) < 128 or c in '✓✗')
            label = label.replace('🎯', '[TARGET]').replace('🔍', '[FOUND]')
            label = label.replace('🔴', '[CRIT]').replace('🟠', '[HIGH]')
            label = label.replace('🟡', '[MED]').replace('🟢', '[LOW]').replace('🔵', '[INFO]')
            label = label.replace('🔑', '[CRED]').replace('💻', '[ACCESS]')
            
            nodes_data.append({
                "id": node.id,
                "label": label,
                "level": level,
                "color": {"background": color, "border": color},
                "title": node.command or node.details or "",
                "shape": "box" if node.node_type == NodeType.ACTION else "ellipse"
            })
            
            for child in node.children:
                edges_data.append({"from": node.id, "to": child.id, "arrows": "to"})
                process(child, level + 1)
        
        process(self.root)
        
        import json
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Attack Tree - {self.target}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/vis-network.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; }}
        .header {{ background: #16213e; padding: 20px; border-bottom: 3px solid #e74c3c; }}
        .header h1 {{ color: #e74c3c; }}
        .header .target {{ color: #3498db; margin-top: 5px; }}
        .stats {{ margin-top: 10px; }}
        .stats span {{ margin-right: 15px; padding: 5px 10px; background: #1a1a2e; border-radius: 4px; }}
        #network {{ width: 100%; height: calc(100vh - 120px); }}
        .legend {{ position: fixed; bottom: 20px; right: 20px; background: #16213e; padding: 15px; border-radius: 8px; }}
        .legend-item {{ display: flex; align-items: center; margin: 5px 0; font-size: 12px; }}
        .legend-color {{ width: 16px; height: 16px; border-radius: 50%; margin-right: 8px; }}
        .btn {{ position: fixed; top: 100px; right: 20px; padding: 10px 20px; background: #3498db; 
               color: white; border: none; border-radius: 4px; cursor: pointer; }}
        .btn:hover {{ background: #2980b9; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 ATTACK TREE</h1>
        <div class="target">Target: {self.target}</div>
        <div class="stats">
            <span>Discoveries: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.DISCOVERY)}</span>
            <span>Actions: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.ACTION)}</span>
            <span>Findings: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.FINDING)}</span>
        </div>
    </div>
    <div id="network"></div>
    <button class="btn" onclick="network.fit()">Fit View</button>
    <div class="legend">
        <strong>Legend</strong>
        <div class="legend-item"><div class="legend-color" style="background:#e74c3c"></div>Target/Critical</div>
        <div class="legend-item"><div class="legend-color" style="background:#3498db"></div>Discovery</div>
        <div class="legend-item"><div class="legend-color" style="background:#2ecc71"></div>Action</div>
        <div class="legend-item"><div class="legend-color" style="background:#f39c12"></div>Finding</div>
        <div class="legend-item"><div class="legend-color" style="background:#9b59b6"></div>Credential</div>
    </div>
    <script>
        var nodes = new vis.DataSet({json.dumps(nodes_data)});
        var edges = new vis.DataSet({json.dumps(edges_data)});
        var container = document.getElementById('network');
        var options = {{
            layout: {{ hierarchical: {{ direction: 'UD', sortMethod: 'directed', levelSeparation: 100 }} }},
            nodes: {{ font: {{ color: '#fff' }}, borderWidth: 2, shadow: true }},
            edges: {{ color: '#555', width: 2, smooth: {{ type: 'cubicBezier' }} }},
            physics: false
        }};
        var network = new vis.Network(container, {{ nodes: nodes, edges: edges }}, options);
        network.on('click', function(p) {{
            if (p.nodes.length > 0) {{
                var n = nodes.get(p.nodes[0]);
                if (n.title) alert(n.label + '\\n\\n' + n.title);
            }}
        }});
    </script>
</body>
</html>'''
        
        with open(filepath, 'w') as f:
            f.write(html)
        
        return filepath


# ============================================================================
# CONFIGURATION
# ============================================================================

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

GUI_TOOLS = {'burpsuite', 'wireshark', 'zenmap', 'armitage', 'maltego', 'zaproxy'}

DESCRIPTION_WORDS = {
    'scan', 'review', 'conduct', 'perform', 'execute', 'run', 'use', 'start',
    'open', 'launch', 'check', 'analyze', 'identify', 'gather', 'collect',
    'find', 'search', 'look', 'examine', 'investigate', 'assess', 'test',
    'verify', 'confirm', 'enumerate', 'discover', 'detect', 'exploit',
    'attempt', 'try', 'begin', 'initiate', 'continue', 'move', 'next',
    'now', 'then', 'should', 'would', 'could', 'let', 'need', 'want',
    'going', 'will', 'shall', 'the', 'a', 'an'
}

UNCENSORED_MODELS = [
    'kali-pentester', 'kali-redteam',
    'dolphin-llama3', 'dolphin-mistral', 'dolphin-mixtral',
    'openhermes', 'nous-hermes', 'wizard-vicuna-uncensored',
]

CURRENT_MODEL = None
CURRENT_PROVIDER = None
ATTACK_TREE = None  # Global attack tree


def get_ollama_models():
    try:
        r = httpx.get("http://localhost:11434/api/tags", timeout=5)
        if r.status_code == 200:
            return [m.get("name", "") for m in r.json().get("models", [])]
    except:
        pass
    return []


def pick_best_model(models):
    for preferred in UNCENSORED_MODELS:
        for m in models:
            if preferred in m.lower():
                return m
    return models[0] if models else "llama3.2"


def is_uncensored(model_name):
    return any(u in model_name.lower() for u in UNCENSORED_MODELS)


def sanitize_command(cmd: str, target: str = None) -> str:
    """
    Remove natural language descriptions from command strings.
    Fixes bug: 'nmap -sS 10.10.10.5 Do a full penetration test' -> 'nmap -sS 10.10.10.5'
    """
    if not cmd:
        return ""
    
    cmd = cmd.strip().strip('`"\'')
    
    # Words that indicate start of description (not part of command)
    stop_words = {'do', 'this', 'will', 'should', 'run', 'execute', 'perform',
                  'scan', 'test', 'check', 'find', 'the', 'to', 'for', 'which',
                  'full', 'complete', 'comprehensive', 'penetration', 'pentest',
                  'vulnerability', 'security', 'that', 'it', 'we', 'i', 'please',
                  'conduct', 'assessment', 'audit', 'review', 'analyze'}
    
    words = cmd.split()
    if not words:
        return ""
    
    # First word must be a known tool
    first_word = words[0].lower()
    if first_word not in VALID_TOOLS:
        return cmd  # Return as-is, let validation handle it
    
    clean_parts = [words[0]]
    skip_next = False
    
    for i, word in enumerate(words[1:], 1):
        if skip_next:
            clean_parts.append(word)
            skip_next = False
            continue
        
        # Flags are always included
        if word.startswith('-'):
            clean_parts.append(word)
            # Flags that take values
            if word in ['-p', '-o', '-oN', '-oX', '-oG', '-oA', '-u', '-U',
                       '-l', '-L', '-w', '-W', '-t', '-T', '-d', '-e', '-f', '-h',
                       '-H', '--header', '--data', '--url', '--wordlist',
                       '--threads', '--timeout', '--script', '--host',
                       '--user', '--pass', '--output', '--ports', '-sV', '-sC',
                       '-sS', '-sT', '-sU', '-A', '-O', '-v', '--top-ports', '-n']:
                skip_next = True
            continue
        
        # IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', word):
            clean_parts.append(word)
            continue
        
        # URLs
        if re.match(r'^https?://', word):
            clean_parts.append(word)
            continue
        
        # Domains (basic check)
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', word):
            clean_parts.append(word)
            continue
        
        # Port numbers/ranges
        if re.match(r'^\d+(-\d+)?(,\d+(-\d+)?)*$', word):
            clean_parts.append(word)
            continue
        
        # File paths
        if word.startswith('/') or word.startswith('./'):
            clean_parts.append(word)
            continue
        
        # Stop at description words
        word_lower = word.lower().rstrip('.,;:!?')
        if word_lower in stop_words:
            break
        
        # Stop at capitalized words (likely description start)
        if word[0].isupper() and i > 1:
            break
        
        # Include other args
        clean_parts.append(word)
    
    return ' '.join(clean_parts)


def is_valid_command(action):
    if not action or len(action) < 3:
        return False
    first = action.split()[0].lower().strip('`"\'')
    return first in VALID_TOOLS and first not in DESCRIPTION_WORDS


def add_target_if_missing(cmd, target):
    if not target or not cmd or target in cmd:
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
    t = tool.lower().split()[0]
    if t in ['nmap', 'masscan']:
        return 300
    elif t in ['nikto', 'wpscan', 'sqlmap', 'nuclei']:
        return 180
    elif t in ['gobuster', 'dirb', 'ffuf']:
        return 180
    return 90


def parse_findings(output: str, tool: str) -> list:
    """Parse output for interesting findings"""
    findings = []
    output_lower = output.lower()
    
    # Port discoveries
    port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
    for match in re.finditer(port_pattern, output):
        port, service = match.groups()
        findings.append(("discovery", f"Port {port} ({service})"))
    
    # Vulnerabilities
    if 'vulnerable' in output_lower or 'vulnerability' in output_lower:
        findings.append(("finding", "Potential vulnerability detected", "high"))
    
    if 'wordpress' in output_lower:
        findings.append(("finding", "WordPress detected", "medium"))
    
    if 'sql injection' in output_lower or 'sqli' in output_lower:
        findings.append(("finding", "SQL Injection possible", "critical"))
    
    if 'xss' in output_lower or 'cross-site' in output_lower:
        findings.append(("finding", "XSS possible", "high"))
    
    if 'admin' in output_lower and ('login' in output_lower or 'panel' in output_lower):
        findings.append(("finding", "Admin panel found", "medium"))
    
    if 'password' in output_lower or 'credential' in output_lower:
        findings.append(("finding", "Credentials exposure", "critical"))
    
    if 'backup' in output_lower and ('.zip' in output_lower or '.sql' in output_lower):
        findings.append(("finding", "Backup file found", "high"))
    
    if 'tls 1.0' in output_lower or 'ssl 3' in output_lower:
        findings.append(("finding", "Weak SSL/TLS", "medium"))
    
    if 'directory listing' in output_lower or 'index of' in output_lower:
        findings.append(("finding", "Directory listing enabled", "low"))
    
    return findings


# ============================================================================
# UI
# ============================================================================

def show_banner():
    banner = """
[bold cyan]
██╗  ██╗ █████╗ ██╗     ██╗       ██████╗ ██████╗ ████████╗
██║ ██╔╝██╔══██╗██║     ██║      ██╔════╝ ██╔══██╗╚══██╔══╝
█████╔╝ ███████║██║     ██║█████╗██║  ███╗██████╔╝   ██║   
██╔═██╗ ██╔══██║██║     ██║╚════╝██║   ██║██╔═══╝    ██║   
██║  ██╗██║  ██║███████╗██║      ╚██████╔╝██║        ██║   
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝       ╚═════╝ ╚═╝        ╚═╝   
[/bold cyan]
[bold green]    🤖 KALI-GPT v4.1 - Ultimate AI Pentest Framework[/bold green]
[cyan]    220+ Tools | 12 Agents | API Server | Bug Bounty | 100% FREE[/cyan]
[dim]    220+ Tools | 12 Agents | Cloud/CTF/Browser | 100% FREE[/dim]
"""
    console.print(banner)


def show_menu():
    # Show tool count
    tools = tool_count() if TOOL_REGISTRY_AVAILABLE else 50
    
    table = Table(title=f"Main Menu ({tools}+ Tools Available)", box=box.ROUNDED, show_header=False)
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
        ("7", "🌳 Attack Tree", "View/Export tree"),
        ("8", "🧠 Fine-tune", "Train custom model"),
        ("9", "🤖 Multi-Agent", "12 AI agents collaborate"),
        ("c", "☁️  Cloud Security", "AWS/Azure/GCP/K8s"),
        ("t", "🏆 CTF Mode", "Forensics & stego"),
        ("b", "🌐 Browser", "Web automation"),
        ("i", "📋 Tool Info", "220+ tools list"),
        ("r", "📄 Reports", "PDF/HTML generation"),
        ("m", "🧠 Memory", "Persistent sessions"),
        ("x", "💥 Exploit", "Auto-exploitation"),
        ("h", "🎯 Bug Bounty", "AI bounty hunter"),
        ("a", "🔌 API Server", "REST API"),
        ("0", "🚪 Exit", ""),
    ]
    
    for opt, action, desc in items:
        table.add_row(opt, action, desc)
    
    console.print(table)


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


# ============================================================================
# AUTONOMOUS PENTEST
# ============================================================================

async def run_pentest(ai_service, target):
    global CURRENT_MODEL, ATTACK_TREE
    
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    console.print(f"\n[bold green]🎯 Starting pentest on {target}[/bold green]\n")
    
    # Initialize attack tree
    ATTACK_TREE = AttackTree(target)
    console.print(f"[dim]🌳 Attack tree initialized[/dim]\n")
    
    info = ai_service.get_provider_info()
    model = CURRENT_MODEL or info.get('model', '')
    uncensored = is_uncensored(model)
    
    if uncensored:
        console.print(f"[green]🐬 Using: {model}[/green]\n")
    else:
        console.print(f"[yellow]⚠️ Using: {model}[/yellow]\n")
    
    memory = MemoryStore()
    await memory.initialize()
    
    # Tool executor with tree integration
    class ToolRunner:
        def __init__(self, target, tree):
            self.target = target
            self.tree = tree
            self.ran = set()
            self.port_nodes = {}
        
        async def execute(self, tool, command=None, **kw):
            cmd = (command or tool).strip().strip('`')
            cmd = sanitize_command(cmd, self.target)  # Remove natural language
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
                
                # Add to attack tree
                action_node = self.tree.add_action(tool_name, cmd, ok, out)
                
                # Parse and add findings
                findings = parse_findings(out, tool_name)
                for finding in findings:
                    if finding[0] == "discovery":
                        # Check if we already have this port
                        if finding[1] not in self.port_nodes:
                            node = self.tree.add_discovery(finding[1], parent=self.tree.root)
                            self.port_nodes[finding[1]] = node
                    elif finding[0] == "finding":
                        risk = finding[2] if len(finding) > 2 else "info"
                        self.tree.add_finding(finding[1], risk=risk, parent=action_node)
                
                return {"success": ok, "output": out or "Done", "error": None, "findings": []}
                
            except subprocess.TimeoutExpired:
                self.tree.add_action(tool_name, cmd, False, "Timeout")
                return {"success": False, "output": "", "error": f"Timeout ({timeout}s)", "findings": []}
            except Exception as e:
                self.tree.add_action(tool_name, cmd, False, str(e))
                return {"success": False, "output": "", "error": str(e), "findings": []}
    
    # LLM Wrapper
    class LLMWrapper:
        def __init__(self, ai, target, uncensored=False):
            self.ai = ai
            self.target = target
            self.config = type('C', (), {'system_prompt': None})()
            self.history = set()
            self.fb_idx = 0
            
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

CRITICAL: Every command must include the target {target}

Format:
THOUGHT: [analysis]
ACTION: [complete command with {target}]

Examples:
THOUGHT: Scan ports
ACTION: nmap -sV -sC -T4 {target}

THOUGHT: Check web
ACTION: whatweb https://{target}

Always include {target}!"""
        
        async def generate(self, prompt, **kw):
            resp = self.ai.ask(prompt, system_prompt=self.prompt)
            
            thought, action = None, None
            
            for line in resp.split('\n'):
                line = line.strip()
                up = line.upper()
                
                if up.startswith('THOUGHT:'):
                    thought = line.split(':', 1)[1].strip()
                
                elif up.startswith('ACTION:') and 'INPUT' not in up:
                    raw_potential = line.split(':', 1)[1].strip().strip('`"\'')
                    potential = sanitize_command(raw_potential, self.target)  # Remove natural language
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
                'content': resp, 'thought': thought or "...",
                'action': action, 'action_input': self.target
            })()
        
        def set_system_prompt(self, n): pass
        def clear_history(self):
            self.ai.clear_history()
            self.history = set()
            self.fb_idx = 0
    
    llm = LLMWrapper(ai_service, target, uncensored)
    runner = ToolRunner(target, ATTACK_TREE)
    
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
        
        # Show results
        show_results(ctx)
        
        # Show attack tree
        console.print(ATTACK_TREE.to_ascii())
        
        # Offer to export
        if Confirm.ask("Export attack tree to HTML?", default=True):
            filepath = ATTACK_TREE.export_html()
            console.print(f"[green]✓ Exported: {filepath}[/green]")
        
        await memory.update_engagement(eid,
            phase_reached=ctx.current_phase.value,
            total_actions=len(ctx.actions_taken),
            vulnerabilities_found=len(ctx.discovered_vulnerabilities))
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped[/yellow]")
        
        # Still show tree
        if ATTACK_TREE and len(ATTACK_TREE.nodes) > 1:
            console.print(ATTACK_TREE.to_ascii())
            if Confirm.ask("Export partial tree?", default=False):
                filepath = ATTACK_TREE.export_html()
                console.print(f"[green]✓ Exported: {filepath}[/green]")
        
        agent.stop()


def show_results(ctx):
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


def view_attack_tree():
    """View/export attack tree"""
    global ATTACK_TREE
    
    if not ATTACK_TREE:
        console.print("[yellow]No attack tree yet. Run a pentest first.[/yellow]")
        return
    
    while True:
        console.print(f"\n[bold cyan]🌳 Attack Tree Menu[/bold cyan]\n")
        console.print(f"  Target: [green]{ATTACK_TREE.target}[/green]")
        console.print(f"  Nodes: {len(ATTACK_TREE.nodes)}")
        console.print()
        console.print("  [cyan]1[/cyan] - View ASCII tree")
        console.print("  [cyan]2[/cyan] - View Rich tree")
        console.print("  [cyan]3[/cyan] - Export HTML")
        console.print("  [cyan]4[/cyan] - Export JSON")
        console.print("  [cyan]b[/cyan] - Back")
        
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice == "b":
            break
        elif choice == "1":
            console.print(ATTACK_TREE.to_ascii())
        elif choice == "2":
            console.print(ATTACK_TREE.to_rich_tree())
        elif choice == "3":
            filepath = ATTACK_TREE.export_html()
            console.print(f"[green]✓ Exported: {filepath}[/green]")
            console.print(f"[dim]Open in browser to view interactive graph[/dim]")
        elif choice == "4":
            import json
            filepath = f"attack_tree_{ATTACK_TREE.target.replace('.', '_')}.json"
            with open(filepath, 'w') as f:
                json.dump(ATTACK_TREE.to_dict() if hasattr(ATTACK_TREE, 'to_dict') else {}, f, indent=2, default=str)
            console.print(f"[green]✓ Exported: {filepath}[/green]")


async def quick_scan(ai):
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


# Colab URL
COLAB_URL = "https://colab.research.google.com/github/alishahid74/kali-gpt/blob/main/fine_tune/Kali_GPT_Fine_Tuning.ipynb"


async def inline_finetune_menu():
    """Inline fine-tuning menu (when module not available)"""
    
    while True:
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold]            🧠 FINE-TUNE YOUR OWN MODEL[/bold]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        
        console.print("[dim]Train a custom AI model for pentesting - no local GPU needed![/dim]\n")
        
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("", style="cyan", width=5)
        table.add_column("", style="white")
        table.add_column("", style="dim")
        
        table.add_row("1", "🚀 Open Google Colab", "Train in browser (free GPU)")
        table.add_row("2", "📖 View Instructions", "How it works")
        table.add_row("3", "📊 Generate Training Data", "From attack tree")
        table.add_row("b", "⬅️  Back", "Return to main menu")
        
        console.print(table)
        
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice == "b":
            break
        
        elif choice == "1":
            console.print("\n[cyan]🚀 Opening Google Colab...[/cyan]\n")
            console.print(Panel(
                f"""[bold]Google Colab Fine-Tuning[/bold]

1. The notebook will open in your browser
2. Click [cyan]Runtime → Change runtime type → T4 GPU[/cyan]
3. Click [cyan]Runtime → Run all[/cyan]
4. Wait ~20 minutes for training
5. Download your fine-tuned model!

[yellow]URL:[/yellow] {COLAB_URL}""",
                title="📋 Instructions",
                border_style="cyan"
            ))
            
            if Confirm.ask("\nOpen Colab now?", default=True):
                webbrowser.open(COLAB_URL)
                console.print("[green]✓ Opened in browser![/green]")
        
        elif choice == "2":
            console.print(Panel(
                """[bold]How Fine-Tuning Works:[/bold]

1. [cyan]Training Data[/cyan]
   The Colab notebook includes 85+ pentesting examples.
   You can also add your own custom examples.

2. [cyan]Base Model[/cyan]
   We fine-tune Llama 3 8B using LoRA (efficient training).
   Only needs ~8GB GPU memory.

3. [cyan]Training Time[/cyan]
   ~20 minutes on free Google Colab T4 GPU.

4. [cyan]Result[/cyan]
   A custom model tuned for pentesting commands.
   Export and use with Ollama!

[yellow]Benefits:[/yellow]
• Better command generation
• Fewer refusals on security queries
• Understands your testing style
• Works offline with Ollama""",
                title="ℹ️  Fine-Tuning Guide",
                border_style="blue"
            ))
        
        elif choice == "3":
            global ATTACK_TREE
            if ATTACK_TREE and len(ATTACK_TREE.nodes) > 1:
                console.print(f"\n[green]Attack tree available for {ATTACK_TREE.target}[/green]")
                console.print(f"Nodes: {len(ATTACK_TREE.nodes)}")
                console.print("\n[yellow]To generate training data:[/yellow]")
                console.print("1. Open Google Colab (option 1)")
                console.print("2. In Step 2, manually add examples based on your pentest")
                console.print("\n[dim]Full integration available in kali_gpt/finetune_integration.py[/dim]")
            else:
                console.print("[yellow]No attack tree available yet.[/yellow]")
                console.print("[dim]Run a pentest first (option 1 in main menu).[/dim]")
        
        input("\nPress Enter to continue...")


async def run_multi_agent(ai):
    """Run multi-agent pentest with external module"""
    target = Prompt.ask("Target")
    if not target:
        return
    
    target = target.replace("http://", "").replace("https://", "").rstrip("/")
    
    pentest = MultiAgentPentest(target, ai)
    results = await pentest.run()
    
    console.print(f"\n[bold green]Multi-Agent Pentest Complete![/bold green]")
    console.print(f"Total findings: {results.get('total', 0)}")


async def inline_multi_agent(ai):
    """Inline multi-agent menu"""
    
    while True:
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold]            🤖 MULTI-AGENT MODE[/bold]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        
        console.print("[dim]Multiple AI agents collaborate on penetration testing![/dim]\n")
        
        console.print(Panel(
            """[bold]How it works:[/bold]

[cyan]🔍 Recon Agent[/cyan]
   Discovers ports, services, and attack surface

[green]🕸️  Web Agent[/green]
   Tests web applications, finds directories and vulns

[red]💥 Exploit Agent[/red]
   Attempts exploitation of discovered vulnerabilities

All agents share findings in real-time and work together!""",
            title="Agent Team",
            border_style="cyan"
        ))
        
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("", style="cyan", width=5)
        table.add_column("", style="white")
        
        table.add_row("1", "🚀 Start Multi-Agent Pentest")
        table.add_row("b", "⬅️  Back")
        
        console.print(table)
        
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice == "b":
            break
        
        elif choice == "1":
            target = Prompt.ask("Target IP/domain")
            if not target:
                continue
            
            target = target.replace("http://", "").replace("https://", "").rstrip("/")
            
            console.print(f"\n[bold green]🎯 Starting Multi-Agent Pentest: {target}[/bold green]\n")
            
            # Create simple multi-agent run inline
            await run_simple_multi_agent(ai, target)


async def run_simple_multi_agent(ai, target):
    """Simple inline multi-agent implementation"""
    global ATTACK_TREE
    
    # Initialize attack tree
    ATTACK_TREE = AttackTree(target)
    
    console.print("[cyan]═══ Phase 1: Reconnaissance ═══[/cyan]\n")
    console.print("[cyan]🔍 Recon Agent starting...[/cyan]")
    
    # Recon phase
    cmds_recon = [
        f"nmap -sV -sC -T4 --top-ports 1000 {target}",
        f"whatweb https://{target} -q"
    ]
    
    ports_found = []
    for cmd in cmds_recon:
        console.print(f"  [dim]$ {cmd}[/dim]")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
            output = result.stdout + result.stderr
            
            # Parse ports from nmap
            import re
            for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', output):
                port, service = match.groups()
                ports_found.append((port, service))
                ATTACK_TREE.add_discovery(f"Port {port} ({service})", parent=ATTACK_TREE.root)
                console.print(f"    [green]→ Port {port} ({service})[/green]")
            
            ATTACK_TREE.add_action(cmd.split()[0], cmd, True, output)
        except Exception as e:
            console.print(f"    [red]Error: {e}[/red]")
    
    console.print(f"\n[cyan]Recon complete: {len(ports_found)} ports found[/cyan]\n")
    
    # Web phase
    console.print("[cyan]═══ Phase 2: Web Testing ═══[/cyan]\n")
    console.print("[green]🕸️  Web Agent starting...[/green]")
    
    web_ports = [p for p, s in ports_found if 'http' in s.lower()]
    if not web_ports:
        web_ports = ['80', '443']
    
    dirs_found = []
    for port in web_ports[:2]:  # Test up to 2 web ports
        proto = "https" if port in ['443', '8443'] else "http"
        url = f"{proto}://{target}"
        
        cmd = f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 30 -q -k --no-error 2>/dev/null | head -20"
        console.print(f"  [dim]$ gobuster ... {url}[/dim]")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            for line in result.stdout.split('\n'):
                if '(Status:' in line:
                    dirs_found.append(line.strip())
                    console.print(f"    [green]→ {line.strip()[:60]}[/green]")
            
            web_node = ATTACK_TREE.add_action("gobuster", cmd, True, result.stdout)
            for d in dirs_found[-5:]:
                ATTACK_TREE.add_finding(d[:40], parent=web_node, risk="low")
        except Exception as e:
            console.print(f"    [red]Error: {e}[/red]")
    
    console.print(f"\n[green]Web testing complete: {len(dirs_found)} directories found[/green]\n")
    
    # Exploit analysis phase
    console.print("[cyan]═══ Phase 3: Vulnerability Analysis ═══[/cyan]\n")
    console.print("[red]💥 Exploit Agent analyzing...[/red]")
    
    # Ask AI for exploitation suggestions
    findings_summary = f"""
Target: {target}
Ports found: {[f"{p} ({s})" for p, s in ports_found]}
Directories found: {dirs_found[:10]}
"""
    
    prompt = f"""Based on these pentest findings, suggest 2-3 specific exploitation commands to try:

{findings_summary}

Output format - just the commands, one per line:
[command 1]
[command 2]
[command 3]"""
    
    response = ai.ask(prompt)
    console.print(f"\n[yellow]AI Exploitation Suggestions:[/yellow]")
    for line in response.split('\n')[:5]:
        line = line.strip()
        if line and not line.startswith('#'):
            console.print(f"  • {line}")
    
    # Show results
    console.print(f"\n[bold cyan]═══ Multi-Agent Results ═══[/bold cyan]\n")
    
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Ports:[/bold] {len(ports_found)}")
    console.print(f"[bold]Directories:[/bold] {len(dirs_found)}")
    
    # Show attack tree
    console.print(ATTACK_TREE.to_ascii())
    
    if Confirm.ask("Export attack tree?", default=False):
        filepath = ATTACK_TREE.export_html()
        console.print(f"[green]✓ Exported: {filepath}[/green]")


async def main():
    global CURRENT_MODEL, CURRENT_PROVIDER
    
    parser = argparse.ArgumentParser(description="Kali-GPT")
    parser.add_argument("--target", "-t", help="Target")
    parser.add_argument("--provider", "-p", choices=["ollama", "openai", "auto"], default="auto")
    parser.add_argument("--model", "-m", help="Model")
    args = parser.parse_args()
    
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
            console.print(f"[yellow]⚠️ {CURRENT_PROVIDER} → {CURRENT_MODEL}[/yellow]\n")
            
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        console.print("\n[yellow]Setup:[/yellow]")
        console.print("  curl -fsSL https://ollama.com/install.sh | sh")
        console.print("  ./install-models.sh")
        return
    
    if args.target:
        await run_pentest(ai, args.target)
        return
    
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
            elif c == "7":
                view_attack_tree()
            elif c == "8":
                if FINETUNE_AVAILABLE:
                    await finetune_menu(ATTACK_TREE)
                else:
                    await inline_finetune_menu()
            elif c == "9":
                if MULTIAGENT_AVAILABLE:
                    await multi_agent_menu(ai, ATTACK_TREE)
                else:
                    await inline_multi_agent(ai)
            elif c == "c":
                await cloud_security_menu(ai)
            elif c == "t":
                await ctf_mode_menu(ai)
            elif c == "b":
                await browser_menu(ai)
            elif c == "i":
                show_tool_info()
            elif c == "r":
                if REPORTS_AVAILABLE:
                    await report_menu(ai, findings=[], target="")
                else:
                    console.print("[yellow]📄 Reports module not found.[/yellow]")
                    console.print("   Copy report_generator.py to kali_gpt/")
            elif c == "m":
                if MEMORY_AVAILABLE:
                    mem_mgr = MemoryManager()
                    await memory_menu(mem_mgr)
                else:
                    console.print("[yellow]🧠 Memory module not found.[/yellow]")
                    console.print("   Copy persistent_memory.py to kali_gpt/")
            elif c == "x":
                if EXPLOIT_AVAILABLE:
                    await exploit_menu(ai)
                else:
                    console.print("[yellow]💥 Exploit module not found.[/yellow]")
                    console.print("   Copy exploit_engine.py to kali_gpt/")
            elif c == "h":
                if BUGBOUNTY_AVAILABLE:
                    await bug_bounty_menu(ai)
                else:
                    console.print("[yellow]🎯 Bug Bounty module not found.[/yellow]")
                    console.print("   Copy bug_bounty_hunter.py and bug_bounty_menu.py to kali_gpt/")
            elif c == "a":
                console.print("\n[cyan]🔌 API Server[/cyan]")
                console.print("   Start with: python3 kali_gpt/api_server.py")
                console.print("   Docs: http://localhost:8000/docs")
                if Confirm.ask("Start API server now?", default=False):
                    import subprocess
                    subprocess.Popen(["python3", "kali_gpt/api_server.py"])
                
        except KeyboardInterrupt:
            console.print("\n")
            if Confirm.ask("Exit?", default=False):
                break


# ============================================================================
# CLOUD SECURITY MODULE (NEW in v4.0)
# ============================================================================

async def cloud_security_menu(ai):
    """Cloud Security Assessment Menu"""
    console.print(Panel(
        "[bold]☁️  CLOUD SECURITY ASSESSMENT[/bold]\n\n"
        "Assess cloud infrastructure security:\n"
        "• AWS - S3, IAM, EC2, Lambda\n"
        "• Azure - Storage, AD, VMs\n"
        "• GCP - Storage, IAM, Compute\n"
        "• Kubernetes - Clusters, RBAC, Secrets",
        title="Cloud Security",
        border_style="blue"
    ))
    
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    
    table.add_row("1", "🔶 AWS Security Scan")
    table.add_row("2", "🔷 Azure Security Scan")
    table.add_row("3", "🟢 GCP Security Scan")
    table.add_row("4", "☸️  Kubernetes Audit")
    table.add_row("5", "🐳 Docker Security")
    table.add_row("6", "🔍 S3 Bucket Scan")
    table.add_row("7", "🔐 Secret Scanner")
    table.add_row("b", "⬅️  Back")
    console.print(table)
    
    choice = Prompt.ask("Select", default="b")
    
    if choice == "1":
        await aws_security_scan(ai)
    elif choice == "2":
        await azure_security_scan(ai)
    elif choice == "3":
        await gcp_security_scan(ai)
    elif choice == "4":
        await kubernetes_audit(ai)
    elif choice == "5":
        await docker_security_scan(ai)
    elif choice == "6":
        await s3_bucket_scan(ai)
    elif choice == "7":
        await secret_scanner(ai)


async def aws_security_scan(ai):
    """AWS Security Assessment"""
    console.print("\n[bold cyan]🔶 AWS Security Scan[/bold cyan]\n")
    
    # Check for prowler
    if not shutil.which("prowler"):
        console.print("[yellow]⚠ Prowler not installed. Install: pip install prowler[/yellow]")
        console.print("[dim]Running basic AWS CLI checks instead...[/dim]\n")
    
    checks = [
        ("S3 Public Buckets", "aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null | head -5"),
        ("IAM Users", "aws iam list-users --query 'Users[*].UserName' --output text 2>/dev/null | head -5"),
        ("Security Groups", "aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' --output text 2>/dev/null | head -5"),
    ]
    
    if shutil.which("prowler"):
        console.print("[cyan]Running Prowler AWS assessment...[/cyan]")
        console.print("[dim]This may take several minutes[/dim]\n")
        
        try:
            result = subprocess.run(
                "prowler aws --severity critical high -M csv 2>&1 | head -50",
                shell=True, capture_output=True, text=True, timeout=300
            )
            console.print(result.stdout)
        except subprocess.TimeoutExpired:
            console.print("[yellow]Scan timed out[/yellow]")
    else:
        for name, cmd in checks:
            console.print(f"[cyan]Checking {name}...[/cyan]")
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout.strip():
                    console.print(f"  {result.stdout.strip()}")
                else:
                    console.print("  [dim]No results or not configured[/dim]")
            except:
                console.print("  [dim]AWS CLI not configured[/dim]")
    
    console.print("\n[green]✓ AWS scan complete[/green]")
    Prompt.ask("\nPress Enter to continue")


async def azure_security_scan(ai):
    """Azure Security Assessment"""
    console.print("\n[bold blue]🔷 Azure Security Scan[/bold blue]\n")
    
    if not shutil.which("az"):
        console.print("[yellow]⚠ Azure CLI not installed[/yellow]")
        console.print("Install: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
        Prompt.ask("\nPress Enter to continue")
        return
    
    console.print("[cyan]Running Azure security checks...[/cyan]\n")
    
    checks = [
        ("Subscription", "az account show --query name -o tsv 2>/dev/null"),
        ("Storage Accounts", "az storage account list --query '[*].name' -o tsv 2>/dev/null | head -5"),
        ("VMs", "az vm list --query '[*].name' -o tsv 2>/dev/null | head -5"),
    ]
    
    for name, cmd in checks:
        console.print(f"[cyan]{name}:[/cyan]")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                console.print(f"  {result.stdout.strip()}")
            else:
                console.print("  [dim]Not configured or no results[/dim]")
        except:
            console.print("  [dim]Error running check[/dim]")
    
    Prompt.ask("\nPress Enter to continue")


async def gcp_security_scan(ai):
    """GCP Security Assessment"""
    console.print("\n[bold green]🟢 GCP Security Scan[/bold green]\n")
    
    if not shutil.which("gcloud"):
        console.print("[yellow]⚠ gcloud CLI not installed[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    console.print("[cyan]Running GCP security checks...[/cyan]\n")
    
    checks = [
        ("Project", "gcloud config get-value project 2>/dev/null"),
        ("Compute Instances", "gcloud compute instances list --format='value(name)' 2>/dev/null | head -5"),
        ("Storage Buckets", "gcloud storage buckets list --format='value(name)' 2>/dev/null | head -5"),
    ]
    
    for name, cmd in checks:
        console.print(f"[cyan]{name}:[/cyan]")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                console.print(f"  {result.stdout.strip()}")
            else:
                console.print("  [dim]Not configured[/dim]")
        except:
            console.print("  [dim]Error[/dim]")
    
    Prompt.ask("\nPress Enter to continue")


async def kubernetes_audit(ai):
    """Kubernetes Security Audit"""
    console.print("\n[bold cyan]☸️  Kubernetes Security Audit[/bold cyan]\n")
    
    if not shutil.which("kubectl"):
        console.print("[yellow]⚠ kubectl not installed[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    # Check cluster access
    result = subprocess.run("kubectl cluster-info 2>&1", shell=True, capture_output=True, text=True)
    if "error" in result.stdout.lower() or "error" in result.stderr.lower():
        console.print("[yellow]⚠ Cannot connect to Kubernetes cluster[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    console.print("[cyan]Running Kubernetes security checks...[/cyan]\n")
    
    checks = [
        ("Privileged Pods", "kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.containers[*].securityContext.privileged}{\"\\n\"}{end}' 2>/dev/null | grep true | head -5"),
        ("Secrets", "kubectl get secrets -A --no-headers 2>/dev/null | wc -l"),
        ("Service Accounts", "kubectl get serviceaccounts -A --no-headers 2>/dev/null | wc -l"),
        ("RBAC Roles", "kubectl get clusterroles --no-headers 2>/dev/null | wc -l"),
        ("Network Policies", "kubectl get networkpolicies -A --no-headers 2>/dev/null | wc -l"),
    ]
    
    for name, cmd in checks:
        console.print(f"[cyan]{name}:[/cyan]")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout.strip() or "0"
            console.print(f"  {output}")
        except:
            console.print("  [dim]Error[/dim]")
    
    # Run kube-hunter if available
    if shutil.which("kube-hunter"):
        if Confirm.ask("\nRun kube-hunter scan?", default=False):
            console.print("\n[cyan]Running kube-hunter...[/cyan]")
            subprocess.run("kube-hunter --pod 2>&1 | head -50", shell=True)
    
    Prompt.ask("\nPress Enter to continue")


async def docker_security_scan(ai):
    """Docker Security Assessment"""
    console.print("\n[bold cyan]🐳 Docker Security Scan[/bold cyan]\n")
    
    if not shutil.which("docker"):
        console.print("[yellow]⚠ Docker not installed[/yellow]")
        Prompt.ask("\nPress Enter to continue")
        return
    
    console.print("[cyan]Running Docker security checks...[/cyan]\n")
    
    # List containers
    result = subprocess.run("docker ps --format '{{.Names}}: {{.Image}}' 2>/dev/null | head -10", 
                          shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        console.print("[bold]Running Containers:[/bold]")
        console.print(result.stdout)
    
    # Check for privileged containers
    result = subprocess.run(
        "docker ps --quiet 2>/dev/null | xargs -I {} docker inspect {} --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}' 2>/dev/null | grep true",
        shell=True, capture_output=True, text=True
    )
    if result.stdout.strip():
        console.print("\n[red]⚠ Privileged Containers:[/red]")
        console.print(result.stdout)
    
    # Run trivy if available
    if shutil.which("trivy"):
        image = Prompt.ask("\nScan image with Trivy (or Enter to skip)", default="")
        if image:
            console.print(f"\n[cyan]Scanning {image}...[/cyan]")
            subprocess.run(f"trivy image {image} --severity HIGH,CRITICAL 2>&1 | head -50", shell=True)
    
    Prompt.ask("\nPress Enter to continue")


async def s3_bucket_scan(ai):
    """S3 Bucket Security Scan"""
    console.print("\n[bold yellow]🔍 S3 Bucket Scanner[/bold yellow]\n")
    
    bucket = Prompt.ask("Bucket name (or keyword to search)")
    
    if not bucket:
        return
    
    console.print(f"\n[cyan]Checking bucket: {bucket}[/cyan]\n")
    
    # Try direct access
    checks = [
        f"aws s3 ls s3://{bucket} --no-sign-request 2>&1 | head -10",
        f"curl -s -I https://{bucket}.s3.amazonaws.com/ | head -5",
    ]
    
    for cmd in checks:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if "AccessDenied" not in result.stdout and "NoSuchBucket" not in result.stdout:
            if result.stdout.strip():
                console.print(f"[green]Accessible![/green]")
                console.print(result.stdout[:500])
        else:
            console.print(f"[dim]{result.stdout[:100]}[/dim]")
    
    Prompt.ask("\nPress Enter to continue")


async def secret_scanner(ai):
    """Scan for secrets in code/files"""
    console.print("\n[bold red]🔐 Secret Scanner[/bold red]\n")
    
    path = Prompt.ask("Path to scan", default=".")
    
    if not os.path.exists(path):
        console.print("[red]Path not found[/red]")
        return
    
    console.print(f"\n[cyan]Scanning {path} for secrets...[/cyan]\n")
    
    # Use trufflehog if available
    if shutil.which("trufflehog"):
        console.print("[cyan]Using TruffleHog...[/cyan]")
        subprocess.run(f"trufflehog filesystem {path} --no-update 2>&1 | head -50", shell=True)
    elif shutil.which("gitleaks"):
        console.print("[cyan]Using Gitleaks...[/cyan]")
        subprocess.run(f"gitleaks detect --source {path} --no-git 2>&1 | head -50", shell=True)
    else:
        # Basic grep patterns
        console.print("[cyan]Using basic pattern matching...[/cyan]")
        patterns = [
            ("API Keys", r"['\"][A-Za-z0-9]{32,}['\"]"),
            ("AWS Keys", r"AKIA[0-9A-Z]{16}"),
            ("Private Keys", r"-----BEGIN.*PRIVATE KEY-----"),
            ("Passwords", r"password\s*=\s*['\"][^'\"]+['\"]"),
        ]
        
        for name, pattern in patterns:
            result = subprocess.run(
                f"grep -rn '{pattern}' {path} 2>/dev/null | head -5",
                shell=True, capture_output=True, text=True
            )
            if result.stdout.strip():
                console.print(f"\n[yellow]{name}:[/yellow]")
                console.print(result.stdout)
    
    Prompt.ask("\nPress Enter to continue")


# ============================================================================
# CTF MODE (NEW in v4.0)
# ============================================================================

async def ctf_mode_menu(ai):
    """CTF Challenge Solving Mode"""
    console.print(Panel(
        "[bold]🏆 CTF MODE[/bold]\n\n"
        "Tools for CTF challenges:\n"
        "• Forensics - Memory, disk, file carving\n"
        "• Steganography - Hidden data extraction\n"
        "• Cryptography - Hash cracking, ciphers\n"
        "• Binary - Reversing, exploitation\n"
        "• Web - SQLi, XSS, SSTI",
        title="CTF Mode",
        border_style="magenta"
    ))
    
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    
    table.add_row("1", "🔍 Analyze File")
    table.add_row("2", "🖼️  Steganography")
    table.add_row("3", "🔐 Hash Crack")
    table.add_row("4", "💾 Memory Forensics")
    table.add_row("5", "🔬 Binary Analysis")
    table.add_row("6", "📜 Decode/Encode")
    table.add_row("7", "🤖 AI CTF Helper")
    table.add_row("b", "⬅️  Back")
    console.print(table)
    
    choice = Prompt.ask("Select", default="b")
    
    if choice == "1":
        await analyze_file_ctf(ai)
    elif choice == "2":
        await stego_menu(ai)
    elif choice == "3":
        await hash_crack_menu(ai)
    elif choice == "4":
        await memory_forensics(ai)
    elif choice == "5":
        await binary_analysis_menu(ai)
    elif choice == "6":
        await decode_encode_menu(ai)
    elif choice == "7":
        await ai_ctf_helper(ai)


async def analyze_file_ctf(ai):
    """Analyze a file for CTF"""
    console.print("\n[bold cyan]🔍 File Analysis[/bold cyan]\n")
    
    filepath = Prompt.ask("File path")
    if not filepath or not os.path.exists(filepath):
        console.print("[red]File not found[/red]")
        return
    
    console.print(f"\n[cyan]Analyzing {filepath}...[/cyan]\n")
    
    # File type
    result = subprocess.run(f"file '{filepath}'", shell=True, capture_output=True, text=True)
    console.print(f"[bold]Type:[/bold] {result.stdout.strip()}")
    
    # Strings
    result = subprocess.run(f"strings '{filepath}' | grep -iE 'flag|ctf|key|password|secret' | head -10", 
                          shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        console.print(f"\n[bold yellow]Interesting strings:[/bold yellow]")
        console.print(result.stdout)
    
    # Check for flag patterns
    result = subprocess.run(f"strings '{filepath}' | grep -oE '(flag|FLAG|CTF|HTB|THM)\\{{[^}}]+\\}}'", 
                          shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        console.print(f"\n[bold green]🚩 FLAGS FOUND:[/bold green]")
        console.print(result.stdout)
    
    # Exiftool
    if shutil.which("exiftool"):
        result = subprocess.run(f"exiftool '{filepath}' 2>/dev/null | head -20", 
                              shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            console.print(f"\n[bold]Metadata:[/bold]")
            console.print(result.stdout)
    
    # Binwalk
    if shutil.which("binwalk"):
        result = subprocess.run(f"binwalk '{filepath}' 2>/dev/null | head -20", 
                              shell=True, capture_output=True, text=True)
        if result.stdout.strip():
            console.print(f"\n[bold]Binwalk:[/bold]")
            console.print(result.stdout)
    
    Prompt.ask("\nPress Enter to continue")


async def stego_menu(ai):
    """Steganography tools"""
    console.print("\n[bold magenta]🖼️  Steganography Tools[/bold magenta]\n")
    
    filepath = Prompt.ask("Image file path")
    if not filepath or not os.path.exists(filepath):
        console.print("[red]File not found[/red]")
        return
    
    console.print(f"\n[cyan]Running stego tools on {filepath}...[/cyan]\n")
    
    # zsteg for PNG
    if filepath.lower().endswith('.png') and shutil.which("zsteg"):
        console.print("[bold]zsteg:[/bold]")
        subprocess.run(f"zsteg '{filepath}' 2>&1 | head -20", shell=True)
    
    # steghide for JPEG
    if filepath.lower().endswith(('.jpg', '.jpeg')) and shutil.which("steghide"):
        console.print("\n[bold]steghide:[/bold]")
        password = Prompt.ask("Password (empty for none)", default="")
        if password:
            subprocess.run(f"steghide extract -sf '{filepath}' -p '{password}' 2>&1", shell=True)
        else:
            subprocess.run(f"steghide info '{filepath}' 2>&1", shell=True)
    
    # strings
    console.print("\n[bold]Hidden strings:[/bold]")
    subprocess.run(f"strings '{filepath}' | grep -iE 'flag|ctf|key|secret|password' | head -10", shell=True)
    
    # Check LSB
    console.print("\n[bold]Hex dump (first 100 bytes):[/bold]")
    subprocess.run(f"xxd '{filepath}' | head -10", shell=True)
    
    Prompt.ask("\nPress Enter to continue")


async def hash_crack_menu(ai):
    """Hash cracking tools"""
    console.print("\n[bold red]🔐 Hash Cracker[/bold red]\n")
    
    hash_value = Prompt.ask("Hash to crack")
    if not hash_value:
        return
    
    # Identify hash
    console.print(f"\n[cyan]Analyzing hash: {hash_value[:50]}...[/cyan]\n")
    
    if shutil.which("hashid"):
        result = subprocess.run(f"hashid '{hash_value}' 2>/dev/null | head -5", 
                              shell=True, capture_output=True, text=True)
        console.print(f"[bold]Possible types:[/bold]\n{result.stdout}")
    
    # Try crackstation-style lookup or john
    if Confirm.ask("Attempt crack with rockyou?", default=False):
        wordlist = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(wordlist):
            wordlist = Prompt.ask("Wordlist path", default="")
        
        if wordlist and os.path.exists(wordlist):
            # Write hash to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(hash_value)
                hash_file = f.name
            
            if shutil.which("john"):
                console.print("\n[cyan]Running John the Ripper...[/cyan]")
                subprocess.run(f"john --wordlist={wordlist} {hash_file} 2>&1 | head -20", shell=True)
                subprocess.run(f"john --show {hash_file} 2>&1", shell=True)
            
            os.unlink(hash_file)
    
    Prompt.ask("\nPress Enter to continue")


async def memory_forensics(ai):
    """Memory forensics with Volatility"""
    console.print("\n[bold cyan]💾 Memory Forensics[/bold cyan]\n")
    
    if not shutil.which("vol") and not shutil.which("volatility"):
        console.print("[yellow]⚠ Volatility not installed[/yellow]")
        console.print("Install: pip install volatility3")
        Prompt.ask("\nPress Enter to continue")
        return
    
    dump_path = Prompt.ask("Memory dump path")
    if not dump_path or not os.path.exists(dump_path):
        console.print("[red]File not found[/red]")
        return
    
    vol_cmd = "vol" if shutil.which("vol") else "volatility"
    
    console.print(f"\n[cyan]Analyzing {dump_path}...[/cyan]\n")
    
    # Get image info
    console.print("[bold]Image Info:[/bold]")
    subprocess.run(f"{vol_cmd} -f '{dump_path}' windows.info 2>&1 | head -20", shell=True)
    
    # List processes
    if Confirm.ask("\nList processes?", default=True):
        subprocess.run(f"{vol_cmd} -f '{dump_path}' windows.pslist 2>&1 | head -30", shell=True)
    
    # Dump passwords
    if Confirm.ask("\nExtract password hashes?", default=False):
        subprocess.run(f"{vol_cmd} -f '{dump_path}' windows.hashdump 2>&1", shell=True)
    
    Prompt.ask("\nPress Enter to continue")


async def binary_analysis_menu(ai):
    """Binary analysis tools"""
    console.print("\n[bold yellow]🔬 Binary Analysis[/bold yellow]\n")
    
    filepath = Prompt.ask("Binary file path")
    if not filepath or not os.path.exists(filepath):
        console.print("[red]File not found[/red]")
        return
    
    console.print(f"\n[cyan]Analyzing {filepath}...[/cyan]\n")
    
    # File info
    subprocess.run(f"file '{filepath}'", shell=True)
    
    # Checksec
    if shutil.which("checksec"):
        console.print("\n[bold]Security:[/bold]")
        subprocess.run(f"checksec --file='{filepath}' 2>&1", shell=True)
    
    # Strings
    console.print("\n[bold]Interesting strings:[/bold]")
    subprocess.run(f"strings '{filepath}' | grep -iE 'flag|password|key|secret|admin' | head -10", shell=True)
    
    # Functions (if radare2)
    if shutil.which("r2"):
        console.print("\n[bold]Functions:[/bold]")
        subprocess.run(f"r2 -q -c 'aaa; afl' '{filepath}' 2>/dev/null | head -20", shell=True)
    
    Prompt.ask("\nPress Enter to continue")


async def decode_encode_menu(ai):
    """Encoding/Decoding tools"""
    console.print("\n[bold green]📜 Decode/Encode[/bold green]\n")
    
    data = Prompt.ask("Data to decode")
    if not data:
        return
    
    import base64
    import codecs
    
    console.print("\n[bold]Attempting decodes:[/bold]\n")
    
    # Base64
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
        if decoded.isprintable():
            console.print(f"[cyan]Base64:[/cyan] {decoded}")
    except:
        pass
    
    # Hex
    try:
        decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
        if decoded.isprintable():
            console.print(f"[cyan]Hex:[/cyan] {decoded}")
    except:
        pass
    
    # ROT13
    try:
        decoded = codecs.decode(data, 'rot_13')
        console.print(f"[cyan]ROT13:[/cyan] {decoded}")
    except:
        pass
    
    # Binary
    try:
        if all(c in '01 ' for c in data):
            decoded = ''.join(chr(int(b, 2)) for b in data.split())
            console.print(f"[cyan]Binary:[/cyan] {decoded}")
    except:
        pass
    
    Prompt.ask("\nPress Enter to continue")


async def ai_ctf_helper(ai):
    """AI-assisted CTF solving"""
    console.print("\n[bold magenta]🤖 AI CTF Helper[/bold magenta]\n")
    console.print("[dim]Describe your CTF challenge and I'll help solve it[/dim]\n")
    
    while True:
        question = Prompt.ask("\n[CTF]", default="")
        if not question or question.lower() in ['exit', 'quit', 'back', 'b']:
            break
        
        prompt = f"""You are a CTF expert. Help solve this challenge:

{question}

Provide:
1. Challenge type identification
2. Tools to use
3. Step-by-step approach
4. Example commands

Be specific and practical."""
        
        response = ai.ask(prompt)
        console.print(Panel(Markdown(response), border_style="magenta"))


# ============================================================================
# BROWSER AUTOMATION (NEW in v4.0)
# ============================================================================

async def browser_menu(ai):
    """Browser automation menu"""
    console.print(Panel(
        "[bold]🌐 BROWSER AUTOMATION[/bold]\n\n"
        "Headless browser testing:\n"
        "• Screenshot capture\n"
        "• Security header analysis\n"
        "• Form detection\n"
        "• Technology fingerprinting\n"
        "• DOM analysis",
        title="Browser Agent",
        border_style="green"
    ))
    
    if not BROWSER_AVAILABLE:
        console.print("[yellow]⚠ Browser module not fully loaded[/yellow]")
        console.print("Install: pip install selenium playwright")
        console.print("         playwright install chromium\n")
    
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    
    table.add_row("1", "🔍 Analyze URL")
    table.add_row("2", "📸 Screenshot")
    table.add_row("3", "🔒 Security Headers")
    table.add_row("4", "📝 Form Detection")
    table.add_row("b", "⬅️  Back")
    console.print(table)
    
    choice = Prompt.ask("Select", default="b")
    
    if choice == "1":
        await browser_analyze_url(ai)
    elif choice == "2":
        await browser_screenshot(ai)
    elif choice == "3":
        await check_security_headers(ai)
    elif choice == "4":
        await detect_forms(ai)


async def browser_analyze_url(ai):
    """Analyze URL with browser"""
    url = Prompt.ask("URL to analyze")
    if not url:
        return
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    console.print(f"\n[cyan]Analyzing {url}...[/cyan]\n")
    
    if BROWSER_AVAILABLE:
        try:
            agent = BrowserAgent(headless=True)
            result = await agent.analyze_url(url)
            display_browser_result(result)
            await agent.close()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    else:
        # Fallback to curl
        console.print("[dim]Using curl (install selenium for full analysis)[/dim]\n")
        subprocess.run(f"curl -sI '{url}' | head -20", shell=True)
    
    Prompt.ask("\nPress Enter to continue")


async def browser_screenshot(ai):
    """Take screenshot of URL"""
    url = Prompt.ask("URL")
    if not url:
        return
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    console.print(f"\n[cyan]Taking screenshot of {url}...[/cyan]")
    
    if BROWSER_AVAILABLE:
        try:
            agent = BrowserAgent(headless=True)
            result = await agent.analyze_url(url)
            if result.screenshot_path:
                console.print(f"\n[green]✓ Screenshot saved: {result.screenshot_path}[/green]")
            await agent.close()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    else:
        # Try cutycapt or wkhtmltoimage
        if shutil.which("cutycapt"):
            outfile = f"/tmp/screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            subprocess.run(f"cutycapt --url='{url}' --out={outfile}", shell=True)
            console.print(f"[green]Screenshot: {outfile}[/green]")
        else:
            console.print("[yellow]Install selenium or cutycapt for screenshots[/yellow]")
    
    Prompt.ask("\nPress Enter to continue")


async def check_security_headers(ai):
    """Check security headers"""
    url = Prompt.ask("URL")
    if not url:
        return
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    console.print(f"\n[cyan]Checking security headers for {url}...[/cyan]\n")
    
    # Get headers
    result = subprocess.run(f"curl -sI '{url}'", shell=True, capture_output=True, text=True)
    headers = result.stdout
    
    # Check security headers
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "X-XSS-Protection": "XSS filter",
        "Content-Security-Policy": "CSP",
        "Referrer-Policy": "Referrer control",
        "Permissions-Policy": "Feature policy",
    }
    
    console.print("[bold]Security Headers Analysis:[/bold]\n")
    
    found = 0
    for header, desc in security_headers.items():
        if header.lower() in headers.lower():
            console.print(f"  [green]✓[/green] {header} ({desc})")
            found += 1
        else:
            console.print(f"  [red]✗[/red] {header} ({desc}) - MISSING")
    
    score = (found / len(security_headers)) * 100
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(f"\n[{color}]Score: {score:.0f}% ({found}/{len(security_headers)})[/{color}]")
    
    Prompt.ask("\nPress Enter to continue")


async def detect_forms(ai):
    """Detect forms on a page"""
    url = Prompt.ask("URL")
    if not url:
        return
    
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    console.print(f"\n[cyan]Detecting forms on {url}...[/cyan]\n")
    
    # Get page content
    result = subprocess.run(f"curl -sL '{url}'", shell=True, capture_output=True, text=True)
    html = result.stdout
    
    # Find forms
    import re
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
    
    console.print(f"[bold]Found {len(forms)} form(s):[/bold]\n")
    
    for i, form in enumerate(forms[:5], 1):
        # Extract action
        action = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
        method = re.search(r'method=["\']([^"\']*)["\']', form, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form, re.IGNORECASE)
        
        console.print(f"[cyan]Form {i}:[/cyan]")
        console.print(f"  Action: {action.group(1) if action else 'self'}")
        console.print(f"  Method: {method.group(1).upper() if method else 'GET'}")
        console.print(f"  Inputs: {', '.join(inputs[:5])}")
    
    Prompt.ask("\nPress Enter to continue")


# ============================================================================
# TOOL INFO (NEW in v4.0)
# ============================================================================

def show_tool_info():
    """Show available tools"""
    console.print(Panel(
        f"[bold]📋 KALI-GPT TOOL REGISTRY[/bold]\n\n"
        f"Total Tools: [green]{tool_count()}[/green]\n\n"
        "Categories available for penetration testing,\n"
        "CTF challenges, cloud security, and more.",
        title="Tool Registry v2.0",
        border_style="cyan"
    ))
    
    if TOOL_REGISTRY_AVAILABLE:
        stats = tool_stats()
        
        table = Table(title="Tools by Category", box=box.ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Examples", style="dim")
        
        examples = {
            "web": "gobuster, ffuf, nuclei, sqlmap",
            "recon": "nmap, masscan, enum4linux",
            "binary": "gdb, radare2, checksec",
            "ctf": "volatility, steghide, binwalk",
            "cloud": "prowler, trivy, aws-cli",
            "osint": "sherlock, amass, shodan",
            "password": "hydra, john, hashcat",
            "container": "trivy, kube-hunter, kubectl",
            "exploit": "metasploit, searchsploit",
            "wireless": "aircrack-ng, wifite",
            "network": "netcat, wireshark, tcpdump",
        }
        
        for cat, count in sorted(stats.items(), key=lambda x: -x[1]):
            table.add_row(cat, str(count), examples.get(cat, ""))
        
        console.print(table)
    
    # Search option
    search = Prompt.ask("\nSearch tool (or Enter to skip)", default="")
    if search and TOOL_REGISTRY_AVAILABLE:
        from kali_gpt.tools.tool_registry import TOOLS
        matches = [t for name, t in TOOLS.items() if search.lower() in name.lower() or search.lower() in t.description.lower()]
        
        if matches:
            console.print(f"\n[bold]Found {len(matches)} tool(s):[/bold]\n")
            for t in matches[:10]:
                console.print(f"  [cyan]{t.name}[/cyan] - {t.description}")
                console.print(f"    [dim]{t.cmd}[/dim]")
        else:
            console.print("[yellow]No matches found[/yellow]")
    
    Prompt.ask("\nPress Enter to continue")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    asyncio.run(main())
if __name__ == '__main__':
    asyncio.run(main())
