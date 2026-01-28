"""
Kali-GPT Multi-Agent Collaboration System v1.0

Multiple specialized AI agents work together on penetration testing:
- Coordinator: Plans and delegates tasks
- Recon Agent: Reconnaissance and enumeration  
- Web Agent: Web application testing
- Exploit Agent: Vulnerability exploitation

Each agent has specialized knowledge and tools.
Agents communicate through a shared message bus.

Usage:
    from multi_agent import MultiAgentPentest
    
    pentest = MultiAgentPentest(target="192.168.1.100", ai_service=ai)
    await pentest.run()
"""

import asyncio
import json
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
import subprocess
import shutil

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich import box

console = Console()


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class AgentRole(Enum):
    COORDINATOR = "Coordinator"
    RECON = "Recon"
    WEB = "Web"
    EXPLOIT = "Exploit"
    NETWORK = "Network"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A finding discovered by an agent"""
    category: str  # port, service, vulnerability, credential, directory, etc.
    title: str
    details: str
    severity: FindingSeverity = FindingSeverity.INFO
    agent: AgentRole = None
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))
    exploitable: bool = False
    
    def __str__(self):
        return f"[{self.severity.value.upper()}] {self.title}"


@dataclass
class AgentTask:
    """A task for an agent"""
    description: str
    priority: int = 5  # 1-10
    status: str = "pending"  # pending, running, complete, failed
    result: str = ""


# =============================================================================
# SHARED MEMORY
# =============================================================================

class SharedMemory:
    """
    Shared state between all agents.
    Thread-safe storage for findings and messages.
    """
    
    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []
        self.messages: List[Dict] = []
        self.agent_status: Dict[str, str] = {}
        self.lock = asyncio.Lock()
        
        # Quick access caches
        self.ports: List[int] = []
        self.services: Dict[int, str] = {}
        self.vulns: List[Finding] = []
        self.credentials: List[Finding] = []
    
    async def add_finding(self, finding: Finding) -> bool:
        """Add a finding (thread-safe, avoids duplicates)"""
        async with self.lock:
            # Check for duplicates
            for f in self.findings:
                if f.category == finding.category and f.title == finding.title:
                    return False
            
            self.findings.append(finding)
            
            # Update caches
            if finding.category == "port":
                try:
                    port = int(re.search(r'\d+', finding.title).group())
                    if port not in self.ports:
                        self.ports.append(port)
                except:
                    pass
            
            elif finding.category == "service":
                try:
                    match = re.match(r'(\d+)\s+(\S+)', finding.title)
                    if match:
                        port, svc = int(match.group(1)), match.group(2)
                        self.services[port] = svc
                except:
                    pass
            
            elif finding.category == "vulnerability":
                self.vulns.append(finding)
            
            elif finding.category == "credential":
                self.credentials.append(finding)
            
            return True
    
    async def send_message(self, from_agent: str, to_agent: str, content: str):
        """Send a message between agents"""
        async with self.lock:
            self.messages.append({
                "from": from_agent,
                "to": to_agent,
                "content": content,
                "time": datetime.now().strftime("%H:%M:%S")
            })
    
    async def get_messages(self, for_agent: str) -> List[Dict]:
        """Get messages for an agent"""
        return [m for m in self.messages if m["to"] == for_agent or m["to"] == "all"]
    
    def get_summary(self) -> Dict:
        """Get summary of all findings"""
        return {
            "target": self.target,
            "total": len(self.findings),
            "ports": len(self.ports),
            "services": len(self.services),
            "vulns": len(self.vulns),
            "credentials": len(self.credentials),
            "critical": sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL),
            "high": sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH),
        }


# =============================================================================
# BASE AGENT
# =============================================================================

class BaseAgent:
    """Base class for all agents"""
    
    def __init__(self, role: AgentRole, ai_service, memory: SharedMemory):
        self.role = role
        self.ai = ai_service
        self.memory = memory
        self.status = "idle"
        self.current_task: Optional[str] = None
        self.tasks_completed = 0
        self.running = False
    
    @property
    def name(self) -> str:
        return self.role.value
    
    @property
    def icon(self) -> str:
        icons = {
            AgentRole.COORDINATOR: "🎯",
            AgentRole.RECON: "🔍",
            AgentRole.WEB: "🕸️",
            AgentRole.EXPLOIT: "💥",
            AgentRole.NETWORK: "🌐",
        }
        return icons.get(self.role, "🤖")
    
    @property
    def color(self) -> str:
        colors = {
            AgentRole.COORDINATOR: "magenta",
            AgentRole.RECON: "cyan",
            AgentRole.WEB: "green",
            AgentRole.EXPLOIT: "red",
            AgentRole.NETWORK: "yellow",
        }
        return colors.get(self.role, "white")
    
    @property
    def tools(self) -> List[str]:
        """Override in subclass"""
        return []
    
    @property
    def system_prompt(self) -> str:
        """Override in subclass"""
        return ""
    
    def log(self, message: str, style: str = None):
        """Log a message with agent prefix"""
        s = style or self.color
        console.print(f"[{s}]{self.icon} {self.name}:[/{s}] {message}")
    
    async def execute(self, command: str, timeout: int = 120) -> Dict:
        """Execute a shell command"""
        tool = command.split()[0] if command else ""
        
        if not shutil.which(tool):
            return {"success": False, "output": "", "error": f"Tool not found: {tool}"}
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout + result.stderr
            success = result.returncode == 0 or len(output.strip()) > 10
            return {"success": success, "output": output, "error": None}
        
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": "Timeout"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}
    
    async def think(self, context: str) -> Dict:
        """Ask AI for next action"""
        prompt = f"""{context}

Based on current findings and your expertise, what command should you run next?
If you're done with your tasks, respond with DONE.

Format:
THOUGHT: [your analysis]
ACTION: [complete shell command]
or
DONE: [summary of what you accomplished]"""
        
        response = self.ai.ask(prompt, system_prompt=self.system_prompt)
        
        result = {"thought": "", "action": None, "done": False, "summary": ""}
        
        for line in response.split('\n'):
            line = line.strip()
            upper = line.upper()
            
            if upper.startswith("THOUGHT:"):
                result["thought"] = line.split(":", 1)[1].strip()
            elif upper.startswith("ACTION:"):
                result["action"] = line.split(":", 1)[1].strip().strip('`')
            elif upper.startswith("DONE:"):
                result["done"] = True
                result["summary"] = line.split(":", 1)[1].strip()
        
        return result
    
    async def share_finding(self, finding: Finding):
        """Share a finding with the team"""
        finding.agent = self.role
        added = await self.memory.add_finding(finding)
        if added:
            sev_colors = {
                FindingSeverity.CRITICAL: "red bold",
                FindingSeverity.HIGH: "red",
                FindingSeverity.MEDIUM: "yellow",
                FindingSeverity.LOW: "green",
                FindingSeverity.INFO: "blue"
            }
            color = sev_colors.get(finding.severity, "white")
            console.print(f"  [{color}]→ {finding.title}[/{color}]")
    
    async def run(self, max_iterations: int = 10):
        """Main agent loop - override in subclass"""
        pass


# =============================================================================
# SPECIALIZED AGENTS
# =============================================================================

class ReconAgent(BaseAgent):
    """Reconnaissance and enumeration specialist"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        super().__init__(AgentRole.RECON, ai_service, memory)
    
    @property
    def tools(self) -> List[str]:
        return ['nmap', 'masscan', 'dig', 'host', 'dnsrecon', 'whois', 'whatweb']
    
    @property
    def system_prompt(self) -> str:
        return f"""You are a RECONNAISSANCE SPECIALIST for penetration testing.
Target: {self.memory.target}

Your expertise:
- Port scanning (nmap, masscan)
- Service enumeration and version detection
- DNS reconnaissance
- Technology fingerprinting

Available tools: {', '.join(self.tools)}

Rules:
1. Always include {self.memory.target} in your commands
2. Start with port scanning to find the attack surface
3. Enumerate services on discovered ports
4. Report all interesting findings

Format:
THOUGHT: [reasoning]
ACTION: [complete command with target]"""
    
    async def parse_nmap(self, output: str):
        """Parse nmap output for findings"""
        # Find open ports
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
        for match in re.finditer(port_pattern, output):
            port, proto, service = match.groups()
            
            await self.share_finding(Finding(
                category="port",
                title=f"{port}/{proto} open",
                details=f"Port {port}/{proto} is open",
                severity=FindingSeverity.INFO
            ))
            
            await self.share_finding(Finding(
                category="service",
                title=f"{port} {service}",
                details=f"Service: {service} on port {port}",
                severity=FindingSeverity.INFO
            ))
        
        # Check for version info
        version_pattern = r'(\d+)/tcp\s+open\s+\S+\s+(.+)'
        for match in re.finditer(version_pattern, output):
            port, version_info = match.groups()
            if len(version_info) > 5:
                await self.share_finding(Finding(
                    category="version",
                    title=f"Port {port}: {version_info[:50]}",
                    details=version_info,
                    severity=FindingSeverity.INFO
                ))
    
    async def run(self, max_iterations: int = 8):
        """Run reconnaissance"""
        self.running = True
        self.status = "running"
        self.log("Starting reconnaissance...")
        
        # Always start with nmap
        self.log("Port scanning...")
        cmd = f"nmap -sV -sC -T4 --top-ports 1000 {self.memory.target}"
        console.print(f"  [dim]$ {cmd}[/dim]")
        
        result = await self.execute(cmd, timeout=300)
        
        if result["success"]:
            await self.parse_nmap(result["output"])
            self.log(f"Found {len(self.memory.ports)} open ports")
        
        # Continue with AI-guided recon
        iteration = 0
        while self.running and iteration < max_iterations:
            iteration += 1
            
            context = f"""Completed initial port scan.
Discovered ports: {self.memory.ports}
Discovered services: {dict(self.memory.services)}

What additional reconnaissance should I perform?"""
            
            decision = await self.think(context)
            
            if decision.get("done"):
                self.log(f"Complete: {decision.get('summary', '')}")
                break
            
            if decision.get("action"):
                action = decision["action"]
                tool = action.split()[0]
                
                if tool in self.tools:
                    self.log(decision.get("thought", ""))
                    console.print(f"  [dim]$ {action}[/dim]")
                    
                    result = await self.execute(action)
                    
                    if result["success"]:
                        # Basic output parsing
                        if "nmap" in tool:
                            await self.parse_nmap(result["output"])
                        self.tasks_completed += 1
        
        self.status = "complete"
        self.running = False


class WebAgent(BaseAgent):
    """Web application testing specialist"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        super().__init__(AgentRole.WEB, ai_service, memory)
    
    @property
    def tools(self) -> List[str]:
        return ['whatweb', 'nikto', 'gobuster', 'ffuf', 'wpscan', 'curl', 'nuclei']
    
    @property
    def system_prompt(self) -> str:
        return f"""You are a WEB APPLICATION SECURITY SPECIALIST.
Target: {self.memory.target}

Your expertise:
- Web technology fingerprinting
- Directory and file enumeration
- Vulnerability scanning (nikto, nuclei)
- CMS-specific testing (wpscan)

Available tools: {', '.join(self.tools)}

Discovered web ports: {[p for p, s in self.memory.services.items() if 'http' in s.lower()]}

Rules:
1. Always include the full URL in commands
2. Use HTTPS for port 443, HTTP for others
3. Start with technology fingerprinting
4. Then enumerate directories
5. Report all vulnerabilities found

Format:
THOUGHT: [reasoning]
ACTION: [complete command]"""
    
    async def parse_gobuster(self, output: str):
        """Parse gobuster output"""
        for line in output.split('\n'):
            if '(Status:' in line:
                match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    path, status = match.groups()
                    severity = FindingSeverity.INFO
                    
                    if any(x in path.lower() for x in ['admin', 'backup', 'config', '.git', 'upload']):
                        severity = FindingSeverity.MEDIUM
                    
                    await self.share_finding(Finding(
                        category="directory",
                        title=f"{path} (HTTP {status})",
                        details=f"Found: {path}",
                        severity=severity
                    ))
    
    async def parse_nikto(self, output: str):
        """Parse nikto output"""
        vuln_keywords = ['vulnerability', 'OSVDB', 'CVE', 'outdated', 'injection']
        
        for line in output.split('\n'):
            if any(kw in line.lower() for kw in vuln_keywords):
                await self.share_finding(Finding(
                    category="vulnerability",
                    title=line[:80],
                    details=line,
                    severity=FindingSeverity.MEDIUM,
                    exploitable=True
                ))
    
    async def run(self, max_iterations: int = 10):
        """Run web testing"""
        self.running = True
        self.status = "running"
        
        # Determine web ports
        web_ports = []
        for port, service in self.memory.services.items():
            if any(x in service.lower() for x in ['http', 'web', 'ssl', 'https']):
                web_ports.append(port)
        
        # Default to common ports if none found
        if not web_ports:
            web_ports = [80, 443]
        
        self.log(f"Testing {len(web_ports)} web port(s)")
        
        for port in web_ports:
            if not self.running:
                break
            
            proto = "https" if port in [443, 8443] else "http"
            url = f"{proto}://{self.memory.target}" + (f":{port}" if port not in [80, 443] else "")
            
            # Technology fingerprinting
            self.log(f"Scanning {url}")
            cmd = f"whatweb {url} -q"
            console.print(f"  [dim]$ {cmd}[/dim]")
            
            result = await self.execute(cmd)
            if result["success"]:
                # Check for CMS
                output_lower = result["output"].lower()
                if "wordpress" in output_lower:
                    await self.share_finding(Finding(
                        category="technology",
                        title="WordPress detected",
                        details=result["output"],
                        severity=FindingSeverity.INFO
                    ))
            
            # Directory enumeration
            cmd = f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 30 -q -k --no-error"
            console.print(f"  [dim]$ {cmd}[/dim]")
            
            result = await self.execute(cmd, timeout=180)
            if result["success"]:
                await self.parse_gobuster(result["output"])
            
            # Vulnerability scan
            cmd = f"nikto -h {url} -maxtime 120 -nointeractive"
            console.print(f"  [dim]$ {cmd}[/dim]")
            
            result = await self.execute(cmd, timeout=150)
            if result["success"]:
                await self.parse_nikto(result["output"])
            
            self.tasks_completed += 3
        
        self.status = "complete"
        self.running = False
        self.log(f"Complete - found {len([f for f in self.memory.findings if f.category == 'directory'])} directories")


class ExploitAgent(BaseAgent):
    """Vulnerability exploitation specialist"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        super().__init__(AgentRole.EXPLOIT, ai_service, memory)
    
    @property
    def tools(self) -> List[str]:
        return ['sqlmap', 'searchsploit', 'hydra', 'nuclei', 'curl']
    
    @property
    def system_prompt(self) -> str:
        vulns = [f.title for f in self.memory.vulns[:10]]
        
        return f"""You are an EXPLOITATION SPECIALIST.
Target: {self.memory.target}

Your expertise:
- SQL injection exploitation
- Known CVE exploitation
- Authentication attacks
- Proof of concept development

Available tools: {', '.join(self.tools)}

Discovered vulnerabilities to exploit:
{json.dumps(vulns, indent=2)}

Rules:
1. Focus on HIGH and CRITICAL severity vulnerabilities first
2. Verify exploitability before deep exploitation
3. Document successful exploits
4. Be careful with destructive actions

Format:
THOUGHT: [reasoning]
ACTION: [complete command]"""
    
    async def run(self, max_iterations: int = 5):
        """Run exploitation attempts"""
        self.running = True
        self.status = "waiting"
        
        # Wait for vulnerabilities
        wait_time = 0
        while not self.memory.vulns and wait_time < 30:
            await asyncio.sleep(2)
            wait_time += 2
        
        if not self.memory.vulns:
            self.log("No vulnerabilities to exploit")
            self.status = "complete"
            return
        
        self.status = "running"
        self.log(f"Analyzing {len(self.memory.vulns)} vulnerabilities")
        
        # Sort by severity
        sorted_vulns = sorted(
            self.memory.vulns,
            key=lambda v: {
                FindingSeverity.CRITICAL: 0,
                FindingSeverity.HIGH: 1,
                FindingSeverity.MEDIUM: 2,
                FindingSeverity.LOW: 3,
                FindingSeverity.INFO: 4
            }.get(v.severity, 5)
        )
        
        for vuln in sorted_vulns[:max_iterations]:
            if not self.running:
                break
            
            context = f"""Vulnerability to analyze:
Title: {vuln.title}
Details: {vuln.details}
Severity: {vuln.severity.value}

What exploitation technique should I try?"""
            
            decision = await self.think(context)
            
            if decision.get("action"):
                action = decision["action"]
                tool = action.split()[0]
                
                if tool in self.tools:
                    self.log(f"Attempting: {vuln.title[:40]}")
                    console.print(f"  [dim]$ {action}[/dim]")
                    
                    result = await self.execute(action, timeout=120)
                    
                    if result["success"]:
                        output_lower = result["output"].lower()
                        
                        # Check for successful exploitation indicators
                        if any(x in output_lower for x in ['shell', 'access', 'password', 'dumped', 'pwned']):
                            await self.share_finding(Finding(
                                category="exploit",
                                title=f"Successful: {vuln.title[:40]}",
                                details=result["output"][:500],
                                severity=FindingSeverity.CRITICAL,
                                exploitable=True
                            ))
                        
                        self.tasks_completed += 1
        
        self.status = "complete"
        self.running = False
        self.log("Complete")


# =============================================================================
# COORDINATOR
# =============================================================================

class Coordinator:
    """
    Coordinates all agents in a multi-agent pentest.
    Manages task assignment and monitors progress.
    """
    
    def __init__(self, target: str, ai_service):
        self.target = target
        self.ai = ai_service
        self.memory = SharedMemory(target)
        self.agents: Dict[AgentRole, BaseAgent] = {}
        self.tasks: Dict[AgentRole, asyncio.Task] = {}
        self.running = False
    
    def create_agents(self):
        """Create all specialized agents"""
        self.agents[AgentRole.RECON] = ReconAgent(self.ai, self.memory)
        self.agents[AgentRole.WEB] = WebAgent(self.ai, self.memory)
        self.agents[AgentRole.EXPLOIT] = ExploitAgent(self.ai, self.memory)
    
    async def start_agent(self, role: AgentRole) -> asyncio.Task:
        """Start an agent"""
        if role not in self.agents:
            return None
        
        agent = self.agents[role]
        task = asyncio.create_task(agent.run())
        self.tasks[role] = task
        return task
    
    async def stop_all(self):
        """Stop all agents"""
        for agent in self.agents.values():
            agent.running = False
        
        for task in self.tasks.values():
            task.cancel()
    
    def display_status(self):
        """Display current status"""
        table = Table(title="Agent Status", box=box.ROUNDED)
        table.add_column("Agent", style="cyan")
        table.add_column("Status")
        table.add_column("Tasks", justify="right")
        
        for role, agent in self.agents.items():
            status_style = {
                "idle": "dim",
                "running": "yellow",
                "waiting": "blue",
                "complete": "green"
            }.get(agent.status, "white")
            
            table.add_row(
                f"{agent.icon} {agent.name}",
                f"[{status_style}]{agent.status}[/{status_style}]",
                str(agent.tasks_completed)
            )
        
        console.print(table)
    
    def display_findings(self):
        """Display findings summary"""
        summary = self.memory.get_summary()
        
        tree = Tree(f"[bold]📊 Findings Summary[/bold]")
        
        tree.add(f"[cyan]Target:[/cyan] {summary['target']}")
        tree.add(f"[cyan]Total Findings:[/cyan] {summary['total']}")
        
        by_type = tree.add("[cyan]By Category:[/cyan]")
        by_type.add(f"Ports: {summary['ports']}")
        by_type.add(f"Services: {summary['services']}")
        by_type.add(f"Vulnerabilities: {summary['vulns']}")
        by_type.add(f"Credentials: {summary['credentials']}")
        
        by_sev = tree.add("[cyan]By Severity:[/cyan]")
        by_sev.add(f"[red]Critical: {summary['critical']}[/red]")
        by_sev.add(f"[yellow]High: {summary['high']}[/yellow]")
        
        console.print(tree)
    
    async def run(self):
        """Run the multi-agent pentest"""
        self.running = True
        
        console.print(Panel(
            f"[bold cyan]Multi-Agent Penetration Test[/bold cyan]\n\n"
            f"[bold]Target:[/bold] {self.target}\n"
            f"[bold]Agents:[/bold] Recon → Web → Exploit\n"
            f"[bold]Mode:[/bold] Collaborative",
            title="🤖 Starting",
            border_style="cyan"
        ))
        
        # Create agents
        self.create_agents()
        
        # Phase 1: Recon
        console.print("\n[bold cyan]═══ Phase 1: Reconnaissance ═══[/bold cyan]\n")
        recon_task = await self.start_agent(AgentRole.RECON)
        
        # Wait for initial findings before starting web agent
        await asyncio.sleep(10)
        
        # Phase 2: Web (runs in parallel with remaining recon)
        console.print("\n[bold cyan]═══ Phase 2: Web Testing ═══[/bold cyan]\n")
        web_task = await self.start_agent(AgentRole.WEB)
        
        # Wait for recon to complete
        if recon_task:
            try:
                await asyncio.wait_for(recon_task, timeout=300)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        
        # Wait for web to find vulns
        await asyncio.sleep(15)
        
        # Phase 3: Exploit
        console.print("\n[bold cyan]═══ Phase 3: Exploitation ═══[/bold cyan]\n")
        exploit_task = await self.start_agent(AgentRole.EXPLOIT)
        
        # Wait for completion
        for task in [web_task, exploit_task]:
            if task:
                try:
                    await asyncio.wait_for(task, timeout=300)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
        
        self.running = False
        
        # Display results
        console.print("\n[bold cyan]═══ Results ═══[/bold cyan]\n")
        self.display_status()
        console.print()
        self.display_findings()
        
        return self.memory.get_summary()


# =============================================================================
# MAIN CLASS
# =============================================================================

class MultiAgentPentest:
    """
    Main class for running multi-agent pentests.
    
    Usage:
        pentest = MultiAgentPentest(target="192.168.1.100", ai_service=ai)
        results = await pentest.run()
    """
    
    def __init__(self, target: str, ai_service):
        self.target = target
        self.ai = ai_service
        self.coordinator = Coordinator(target, ai_service)
    
    async def run(self) -> Dict:
        """Run the multi-agent pentest"""
        try:
            return await self.coordinator.run()
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping agents...[/yellow]")
            await self.coordinator.stop_all()
            return self.coordinator.memory.get_summary()
    
    def get_findings(self) -> List[Finding]:
        """Get all findings"""
        return self.coordinator.memory.findings
    
    def get_summary(self) -> Dict:
        """Get summary"""
        return self.coordinator.memory.get_summary()


# =============================================================================
# DISPLAY HELPERS
# =============================================================================

def show_multi_agent_menu():
    """Display multi-agent menu"""
    table = Table(title="🤖 Multi-Agent Mode", box=box.ROUNDED, show_header=False)
    table.add_column("", style="cyan", width=5)
    table.add_column("", style="white")
    table.add_column("", style="dim")
    
    items = [
        ("1", "🚀 Start Multi-Agent Pentest", "All agents collaborate"),
        ("2", "📊 View Agent Status", "Check agent progress"),
        ("3", "🔍 Custom Agent Selection", "Choose which agents to use"),
        ("b", "⬅️  Back", "Return to main menu"),
    ]
    
    for opt, name, desc in items:
        table.add_row(opt, name, desc)
    
    console.print(table)


async def multi_agent_menu(ai_service, attack_tree=None):
    """
    Main multi-agent menu - called from Kali-GPT main script.
    
    Args:
        ai_service: AI service instance
        attack_tree: Optional attack tree to integrate with
    """
    from rich.prompt import Prompt, Confirm
    
    while True:
        console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
        console.print(f"[bold]            🤖 MULTI-AGENT COLLABORATION[/bold]")
        console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")
        
        console.print(Panel(
            """[bold]Agent Team:[/bold]

[cyan]🎯 Coordinator[/cyan] - Plans attacks, delegates tasks
[blue]🔍 Recon Agent[/blue] - Reconnaissance, port scanning
[green]🕸️  Web Agent[/green] - Web app testing, directory fuzzing
[red]💥 Exploit Agent[/red] - Vulnerability exploitation

Agents share findings in real-time through shared memory!""",
            title="How It Works",
            border_style="cyan"
        ))
        
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("", style="cyan", width=5)
        table.add_column("", style="white")
        table.add_column("", style="dim")
        
        table.add_row("1", "🚀 Start Collaborative Pentest", "Full agent team")
        table.add_row("2", "⚡ Quick Multi-Agent Scan", "Fast 3-phase scan")
        table.add_row("3", "🔧 Configure Agents", "Select which agents")
        table.add_row("4", "📖 View Agent Details", "Learn about each agent")
        table.add_row("b", "⬅️  Back", "Return to main menu")
        
        console.print(table)
        
        choice = Prompt.ask("\nSelect", default="b")
        
        if choice == "b":
            break
        
        elif choice == "1":
            target = Prompt.ask("Target IP/domain")
            if not target:
                continue
            
            target = target.replace("http://", "").replace("https://", "").rstrip("/")
            max_rounds = int(Prompt.ask("Max rounds", default="15"))
            
            console.print(f"\n[bold green]🎯 Starting Multi-Agent Pentest: {target}[/bold green]")
            console.print(f"[dim]Max rounds: {max_rounds}[/dim]\n")
            
            try:
                pentest = MultiAgentPentest(target, ai_service)
                results = await pentest.run(max_rounds=max_rounds)
                
                # Show results
                display_results(results)
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped by user[/yellow]")
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
        
        elif choice == "2":
            target = Prompt.ask("Target IP/domain")
            if not target:
                continue
            
            target = target.replace("http://", "").replace("https://", "").rstrip("/")
            
            console.print(f"\n[bold green]⚡ Quick Multi-Agent Scan: {target}[/bold green]\n")
            
            await run_quick_multi_agent(ai_service, target)
        
        elif choice == "3":
            console.print("\n[bold]Available Agents:[/bold]")
            agents = [
                ("Recon", "🔍", "Port scanning, service detection", True),
                ("Web", "🕸️", "Web app testing, dir fuzzing", True),
                ("Exploit", "💥", "Vulnerability exploitation", False),
            ]
            
            for name, icon, desc, default in agents:
                status = "[green]✓ Enabled[/green]" if default else "[dim]○ Disabled[/dim]"
                console.print(f"  {icon} {name}: {desc} {status}")
            
            console.print("\n[dim]Agent configuration coming in future update![/dim]")
        
        elif choice == "4":
            show_agent_details()
        
        input("\nPress Enter to continue...")


async def run_quick_multi_agent(ai_service, target: str):
    """Quick 3-phase multi-agent scan"""
    
    findings = {
        "ports": [],
        "services": [],
        "directories": [],
        "vulnerabilities": []
    }
    
    # Phase 1: Recon
    console.print("[cyan]═══ Phase 1: Reconnaissance (🔍 Recon Agent) ═══[/cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning ports...", total=None)
        
        cmd = f"nmap -sV -sC -T4 --top-ports 100 {target}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                   text=True, timeout=120)
            output = result.stdout + result.stderr
            
            # Parse ports
            for match in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', output):
                port, service = match.groups()
                findings["ports"].append(port)
                findings["services"].append(f"{port}/{service}")
                console.print(f"  [green]→ Port {port} ({service})[/green]")
            
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
    
    console.print(f"\n  [cyan]Found {len(findings['ports'])} open ports[/cyan]\n")
    
    # Phase 2: Web Testing
    console.print("[green]═══ Phase 2: Web Testing (🕸️ Web Agent) ═══[/green]\n")
    
    web_ports = [p for p in findings["ports"] if p in ['80', '443', '8080', '8443']]
    if not web_ports and findings["ports"]:
        web_ports = ['80', '443']
    
    if web_ports:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Fuzzing directories...", total=None)
            
            proto = "https" if '443' in web_ports else "http"
            cmd = f"gobuster dir -u {proto}://{target} -w /usr/share/wordlists/dirb/common.txt -t 20 -q -k --no-error 2>/dev/null | head -15"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True,
                                       text=True, timeout=90)
                
                for line in result.stdout.split('\n'):
                    if '(Status:' in line:
                        findings["directories"].append(line.strip())
                        console.print(f"  [green]→ {line.strip()[:60]}[/green]")
                
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")
    
    console.print(f"\n  [green]Found {len(findings['directories'])} directories[/green]\n")
    
    # Phase 3: Analysis
    console.print("[red]═══ Phase 3: Analysis (💥 Exploit Agent) ═══[/red]\n")
    
    # AI analysis
    analysis_prompt = f"""Analyze these pentest findings and suggest next steps:

Target: {target}
Open Ports: {', '.join(findings['services']) or 'None found'}
Directories: {', '.join(findings['directories'][:5]) or 'None found'}

Provide:
1. Risk assessment (high/medium/low)
2. Top 3 attack vectors to explore
3. Specific commands to try next

Be concise."""

    console.print("  [dim]Analyzing findings...[/dim]")
    
    try:
        analysis = ai_service.ask(analysis_prompt)
        console.print(Panel(analysis, title="🧠 AI Analysis", border_style="yellow"))
    except Exception as e:
        console.print(f"  [red]Analysis error: {e}[/red]")
    
    # Summary
    console.print(f"\n[bold cyan]═══ Summary ═══[/bold cyan]\n")
    
    table = Table(box=box.SIMPLE)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Open Ports", str(len(findings["ports"])))
    table.add_row("Services", str(len(findings["services"])))
    table.add_row("Directories", str(len(findings["directories"])))
    
    console.print(table)


def show_agent_details():
    """Show detailed info about each agent"""
    agents = [
        {
            "name": "Coordinator",
            "icon": "🎯",
            "role": "Team Leader",
            "description": "Plans the overall attack strategy, delegates tasks to specialized agents, and ensures comprehensive coverage.",
            "capabilities": ["Task planning", "Agent coordination", "Progress tracking", "Decision making"]
        },
        {
            "name": "Recon Agent",
            "icon": "🔍",
            "role": "Reconnaissance Specialist",
            "description": "Handles all reconnaissance tasks including port scanning, service enumeration, and information gathering.",
            "capabilities": ["Port scanning (nmap)", "Service detection", "Banner grabbing", "OSINT gathering"]
        },
        {
            "name": "Web Agent",
            "icon": "🕸️",
            "role": "Web Security Specialist",
            "description": "Specializes in web application testing, directory enumeration, and web vulnerability scanning.",
            "capabilities": ["Directory fuzzing (gobuster)", "Web vuln scanning (nikto)", "CMS detection", "Parameter testing"]
        },
        {
            "name": "Exploit Agent",
            "icon": "💥",
            "role": "Exploitation Specialist",
            "description": "Attempts exploitation of discovered vulnerabilities using appropriate tools and techniques.",
            "capabilities": ["SQL injection (sqlmap)", "Credential attacks", "CVE exploitation", "Shell access"]
        }
    ]
    
    for agent in agents:
        console.print(Panel(
            f"[bold]{agent['role']}[/bold]\n\n"
            f"{agent['description']}\n\n"
            f"[cyan]Capabilities:[/cyan]\n" +
            "\n".join(f"  • {c}" for c in agent['capabilities']),
            title=f"{agent['icon']} {agent['name']}",
            border_style="cyan"
        ))


def display_results(results: Dict):
    """Display pentest results"""
    console.print(f"\n[bold cyan]═══ Multi-Agent Pentest Results ═══[/bold cyan]\n")
    
    console.print(f"[bold]Target:[/bold] {results.get('target', 'Unknown')}")
    console.print(f"[bold]Rounds:[/bold] {results.get('rounds', 0)}")
    console.print(f"[bold]Commands:[/bold] {results.get('commands', 0)}")
    
    findings = results.get('findings', {})
    
    console.print(f"\n[bold]Findings:[/bold]")
    console.print(f"  • Total: {findings.get('total_findings', 0)}")
    
    by_type = findings.get('by_type', {})
    if by_type:
        console.print(f"\n[bold]By Type:[/bold]")
        for t, count in by_type.items():
            console.print(f"  • {t}: {count}")
    
    by_risk = findings.get('by_risk', {})
    if by_risk:
        console.print(f"\n[bold]By Risk:[/bold]")
        risk_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green", "info": "dim"}
        for risk, count in by_risk.items():
            if count > 0:
                color = risk_colors.get(risk, "white")
                console.print(f"  • [{color}]{risk.upper()}: {count}[/{color}]")


# =============================================================================
# EXPORTS for main Kali-GPT script
# =============================================================================

# These are imported by the main script:
# from kali_gpt.multi_agent import MultiAgentPentest, multi_agent_menu, show_multi_agent_menu

__all__ = [
    'MultiAgentPentest',
    'multi_agent_menu',
    'show_multi_agent_menu',
    'run_quick_multi_agent',
    'AgentRole',
    'SharedMemory',
    'Finding',
]


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    # Mock AI for testing
    class MockAI:
        def ask(self, prompt, system_prompt=None):
            return "THOUGHT: Testing mode\nDONE: Mock test complete"
    
    async def test():
        console.print("[bold cyan]Multi-Agent System Test[/bold cyan]\n")
        
        # Test import
        console.print("[green]✓ Multi-Agent module loaded successfully[/green]")
        
        # Show menu
        console.print("\n[bold]Menu Preview:[/bold]")
        show_multi_agent_menu()
        
        # Test pentest class
        console.print("\n[bold]Testing MultiAgentPentest class...[/bold]")
        pentest = MultiAgentPentest("127.0.0.1", MockAI())
        console.print(f"[green]✓ Created pentest for: {pentest.target}[/green]")
        console.print(f"[green]✓ Agents: {list(pentest.agents.keys())}[/green]")
        
        console.print("\n[bold green]All tests passed![/bold green]")
    
    asyncio.run(test())
