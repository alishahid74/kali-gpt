"""
Kali-GPT AI Agents v4.0

12+ Specialized AI Agents for comprehensive penetration testing:
- Coordinator Agent: Orchestrates all agents
- Recon Agent: Reconnaissance and enumeration
- Network Agent: Network scanning and analysis
- Web Agent: Web application testing
- Exploit Agent: Vulnerability exploitation
- Post-Exploit Agent: Post-exploitation activities
- Cloud Agent: Cloud security assessment
- Container Agent: Container/K8s security
- Binary Agent: Binary analysis and reversing
- CTF Agent: CTF challenge solving
- OSINT Agent: Open source intelligence
- Reporting Agent: Report generation
"""

import asyncio
import subprocess
import shutil
import re
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
from abc import ABC, abstractmethod

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()


# =============================================================================
# ENUMS & DATA CLASSES
# =============================================================================

class AgentRole(Enum):
    COORDINATOR = "Coordinator"
    RECON = "Recon"
    NETWORK = "Network"
    WEB = "Web"
    EXPLOIT = "Exploit"
    POST_EXPLOIT = "Post-Exploit"
    CLOUD = "Cloud"
    CONTAINER = "Container"
    BINARY = "Binary"
    CTF = "CTF"
    OSINT = "OSINT"
    REPORTING = "Reporting"


class AgentState(Enum):
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    WAITING = "waiting"
    DONE = "done"
    ERROR = "error"


class FindingType(Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    FILE = "file"
    USER = "user"
    DIRECTORY = "directory"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    BINARY_INFO = "binary_info"
    FLAG = "flag"


@dataclass
class Finding:
    """A single finding/discovery"""
    type: FindingType
    value: str
    details: Dict = field(default_factory=dict)
    source_agent: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 1.0
    risk: str = "info"  # info, low, medium, high, critical
    mitre_tactic: str = ""
    mitre_technique: str = ""


@dataclass
class AgentConfig:
    """Agent configuration"""
    role: AgentRole
    name: str
    description: str
    tools: List[str]
    color: str = "white"
    icon: str = "🤖"
    priority: int = 5  # 1-10, lower = higher priority


# =============================================================================
# SHARED MEMORY
# =============================================================================

class SharedMemory:
    """
    Shared memory between all agents.
    Thread-safe storage for findings and state.
    """
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.commands_executed: List[Dict] = []
        self.agent_states: Dict[str, str] = {}
        self.messages: List[Dict] = []
        self.target: str = ""
        self.scope: List[str] = []
        self.flags: List[str] = []  # For CTF
        self.credentials: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self._lock = asyncio.Lock()
    
    async def add_finding(self, finding: Finding) -> bool:
        """Add a finding (thread-safe)"""
        async with self._lock:
            # Avoid duplicates
            for f in self.findings:
                if f.type == finding.type and f.value == finding.value:
                    return False
            self.findings.append(finding)
            
            # Track special findings
            if finding.type == FindingType.CREDENTIAL:
                self.credentials.append({
                    "value": finding.value,
                    "details": finding.details,
                    "source": finding.source_agent
                })
            elif finding.type == FindingType.VULNERABILITY:
                self.vulnerabilities.append({
                    "value": finding.value,
                    "risk": finding.risk,
                    "details": finding.details,
                    "source": finding.source_agent
                })
            elif finding.type == FindingType.FLAG:
                self.flags.append(finding.value)
            
            return True
    
    async def get_findings(self, 
                          type: FindingType = None, 
                          source: str = None,
                          risk: str = None) -> List[Finding]:
        """Get findings, optionally filtered"""
        async with self._lock:
            results = self.findings.copy()
            if type:
                results = [f for f in results if f.type == type]
            if source:
                results = [f for f in results if f.source_agent == source]
            if risk:
                results = [f for f in results if f.risk == risk]
            return results
    
    async def add_command(self, agent: str, command: str, output: str, success: bool):
        """Record executed command"""
        async with self._lock:
            self.commands_executed.append({
                "agent": agent,
                "command": command,
                "output": output[:2000],  # Truncate
                "success": success,
                "timestamp": datetime.now().isoformat()
            })
    
    async def send_message(self, from_agent: str, to_agent: str, message: str, data: Any = None):
        """Send message between agents"""
        async with self._lock:
            self.messages.append({
                "from": from_agent,
                "to": to_agent,
                "message": message,
                "data": data,
                "timestamp": datetime.now().isoformat()
            })
    
    async def get_messages(self, for_agent: str) -> List[Dict]:
        """Get messages for a specific agent"""
        async with self._lock:
            return [m for m in self.messages if m["to"] == for_agent or m["to"] == "all"]
    
    async def update_agent_state(self, agent: str, state: str):
        """Update agent state"""
        async with self._lock:
            self.agent_states[agent] = state
    
    def get_summary(self) -> Dict:
        """Get summary of all findings"""
        summary = {
            "total_findings": len(self.findings),
            "by_type": {},
            "by_risk": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_agent": {},
            "commands_executed": len(self.commands_executed),
            "credentials_found": len(self.credentials),
            "vulnerabilities_found": len(self.vulnerabilities),
            "flags_captured": len(self.flags),
        }
        
        for f in self.findings:
            t = f.type.value
            summary["by_type"][t] = summary["by_type"].get(t, 0) + 1
            summary["by_risk"][f.risk] = summary["by_risk"].get(f.risk, 0) + 1
            summary["by_agent"][f.source_agent] = summary["by_agent"].get(f.source_agent, 0) + 1
        
        return summary


# =============================================================================
# BASE AGENT
# =============================================================================

class BaseAgent(ABC):
    """
    Base class for all specialized agents.
    """
    
    def __init__(self, config: AgentConfig, ai_service, memory: SharedMemory):
        self.config = config
        self.ai = ai_service
        self.memory = memory
        self.state = AgentState.IDLE
        self.current_task: Optional[str] = None
        self.tasks_completed = 0
        self.findings_count = 0
        self.on_status_change: Optional[Callable] = None
    
    @property
    def name(self) -> str:
        return self.config.name
    
    @property
    def role(self) -> AgentRole:
        return self.config.role
    
    async def set_state(self, state: AgentState):
        """Update agent state"""
        self.state = state
        await self.memory.update_agent_state(self.name, state.value)
        if self.on_status_change:
            await self.on_status_change(self.name, state)
    
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent"""
        return f"""You are {self.config.name}, a specialized {self.config.role.value} agent.

{self.config.description}

Your available tools: {', '.join(self.config.tools)}

RULES:
1. Only use tools you're specialized in
2. Always include the target in commands
3. Output format:
   THOUGHT: [your analysis]
   ACTION: [complete command] or DONE
4. Be thorough but efficient
5. Extract and report all findings

Target: {self.memory.target}
Scope: {', '.join(self.memory.scope)}
"""
    
    async def think(self, context: str) -> tuple:
        """Ask AI what to do next"""
        await self.set_state(AgentState.THINKING)
        
        prompt = f"""{context}

Based on current findings and your expertise, what should you do next?
If nothing more to do in your domain, say "DONE".

Format:
THOUGHT: [analysis]
ACTION: [command] or DONE"""
        
        try:
            response = self.ai.ask(prompt, system_prompt=self.get_system_prompt())
        except:
            response = self.ai.ask(prompt)
        
        thought = ""
        action = ""
        
        for line in response.split('\n'):
            line = line.strip()
            if line.upper().startswith('THOUGHT:'):
                thought = line.split(':', 1)[1].strip()
            elif line.upper().startswith('ACTION:'):
                action = line.split(':', 1)[1].strip()
        
        return thought, action
    
    async def execute(self, command: str) -> tuple:
        """Execute a command"""
        await self.set_state(AgentState.EXECUTING)
        
        if not command or command.upper() == "DONE":
            return True, "Agent completed tasks"
        
        # Validate command has valid tool
        tool = command.split()[0].lower() if command else ""
        
        if not shutil.which(tool):
            return False, f"Tool not found: {tool}"
        
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=180
            )
            output = result.stdout + result.stderr
            success = result.returncode == 0 or len(output) > 10
            
            await self.memory.add_command(self.name, command, output, success)
            
            return success, output
        
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    @abstractmethod
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        """Analyze command output and extract findings - implemented by subclasses"""
        pass
    
    async def run_task(self, task: str, max_iterations: int = 3) -> bool:
        """Run a task with multiple iterations if needed"""
        self.current_task = task
        
        for i in range(max_iterations):
            # Build context
            findings = await self.memory.get_findings()
            messages = await self.memory.get_messages(self.name)
            
            context = f"""Task: {task}
Iteration: {i+1}/{max_iterations}

Known findings ({len(findings)} total):
{self._format_findings(findings[-20:])}

Messages from other agents:
{self._format_messages(messages[-5:])}
"""
            
            # Think
            thought, action = await self.think(context)
            
            if not action or action.upper() == "DONE":
                await self.set_state(AgentState.DONE)
                return True
            
            # Display
            console.print(f"\n[{self.config.color}]{self.config.icon} {self.name}:[/]")
            console.print(f"  [dim]{thought}[/dim]")
            console.print(f"  [cyan]$ {action}[/cyan]")
            
            # Execute
            success, output = await self.execute(action)
            
            if success:
                # Analyze and store findings
                await self.set_state(AgentState.ANALYZING)
                new_findings = await self.analyze_output(action, output)
                
                for finding in new_findings:
                    finding.source_agent = self.name
                    added = await self.memory.add_finding(finding)
                    if added:
                        self.findings_count += 1
                        risk_color = {
                            "critical": "red",
                            "high": "yellow", 
                            "medium": "blue",
                            "low": "green",
                            "info": "dim"
                        }.get(finding.risk, "white")
                        console.print(f"  [{risk_color}]→ {finding.type.value}: {finding.value}[/{risk_color}]")
            
            self.tasks_completed += 1
        
        await self.set_state(AgentState.IDLE)
        return True
    
    def _format_findings(self, findings: List[Finding]) -> str:
        """Format findings for prompt"""
        if not findings:
            return "None yet"
        
        lines = []
        for f in findings:
            lines.append(f"- [{f.risk}] {f.type.value}: {f.value}")
        return '\n'.join(lines)
    
    def _format_messages(self, messages: List[Dict]) -> str:
        """Format messages for prompt"""
        if not messages:
            return "None"
        
        lines = []
        for m in messages:
            lines.append(f"- From {m['from']}: {m['message']}")
        return '\n'.join(lines)


# =============================================================================
# SPECIALIZED AGENTS
# =============================================================================

class ReconAgent(BaseAgent):
    """Reconnaissance Agent - Initial enumeration and discovery"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.RECON,
            name="Recon",
            description="""You specialize in reconnaissance and enumeration:
- Port scanning with nmap, masscan, rustscan
- Service detection and version identification
- Initial target profiling
- Technology fingerprinting""",
            tools=["nmap", "masscan", "rustscan", "whatweb", "dig", "whois", "host"],
            color="cyan",
            icon="🔍",
            priority=1
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        
        # Port detection (nmap style)
        for match in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', output):
            port, proto, service = match.groups()
            findings.append(Finding(
                type=FindingType.PORT,
                value=f"{port}/{proto}",
                details={"service": service, "protocol": proto},
                mitre_tactic="TA0043"
            ))
            findings.append(Finding(
                type=FindingType.SERVICE,
                value=service,
                details={"port": port, "protocol": proto}
            ))
        
        # Host detection
        for match in re.finditer(r'Nmap scan report for (\S+)', output):
            findings.append(Finding(
                type=FindingType.HOST,
                value=match.group(1)
            ))
        
        # Version detection
        version_pattern = r'(\d+)/tcp.*?(\S+)\s+(\d+\.\d+[^\n]*)'
        for match in re.finditer(version_pattern, output):
            findings.append(Finding(
                type=FindingType.TECHNOLOGY,
                value=match.group(2) + " " + match.group(3),
                details={"port": match.group(1)}
            ))
        
        return findings


class NetworkAgent(BaseAgent):
    """Network Agent - Network analysis and SMB/LDAP enumeration"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.NETWORK,
            name="Network",
            description="""You specialize in network analysis:
- SMB enumeration with enum4linux, smbclient, smbmap
- LDAP enumeration
- SNMP enumeration
- Network service analysis""",
            tools=["enum4linux", "smbclient", "smbmap", "rpcclient", "ldapsearch", 
                   "snmpwalk", "netcat", "tcpdump"],
            color="yellow",
            icon="🌐",
            priority=2
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # SMB shares
        share_pattern = r'(\\\\[^\s]+\\[^\s]+|//.+?/\w+)'
        for match in re.finditer(share_pattern, output):
            findings.append(Finding(
                type=FindingType.DIRECTORY,
                value=match.group(1),
                details={"type": "smb_share"},
                risk="low"
            ))
        
        # Users
        user_patterns = [
            r'user:\[([^\]]+)\]',
            r'Account:\s*(\S+)',
            r'Username:\s*(\S+)',
        ]
        for pattern in user_patterns:
            for match in re.finditer(pattern, output, re.IGNORECASE):
                findings.append(Finding(
                    type=FindingType.USER,
                    value=match.group(1),
                    risk="low"
                ))
        
        # Anonymous access
        if 'anonymous' in output_lower and ('success' in output_lower or 'allowed' in output_lower):
            findings.append(Finding(
                type=FindingType.VULNERABILITY,
                value="Anonymous access enabled",
                risk="medium",
                mitre_tactic="TA0001"
            ))
        
        return findings


class WebAgent(BaseAgent):
    """Web Agent - Web application security testing"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.WEB,
            name="Web",
            description="""You specialize in web application testing:
- Directory enumeration with gobuster, ffuf, feroxbuster
- Web vulnerability scanning with nuclei, nikto
- CMS scanning with wpscan
- Parameter fuzzing""",
            tools=["gobuster", "ffuf", "feroxbuster", "dirsearch", "nikto", "nuclei",
                   "wpscan", "whatweb", "curl", "httpx", "katana", "arjun"],
            color="green",
            icon="🕸️",
            priority=3
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # Directory findings
        dir_patterns = [
            r'(/[a-zA-Z0-9._-]+)\s+.*?(200|301|302|403)',
            r'Status:\s*(200|301|302|403).*?(/[^\s]+)',
            r'\[Status:\s*(200|301|302|403)[^\]]*\]\s*(/[^\s]+)',
        ]
        for pattern in dir_patterns:
            for match in re.finditer(pattern, output):
                path = match.group(1) if match.group(1).startswith('/') else match.group(2)
                findings.append(Finding(
                    type=FindingType.DIRECTORY,
                    value=path,
                    risk="info"
                ))
        
        # Vulnerability keywords
        vuln_map = {
            "sql injection": ("SQL Injection", "critical"),
            "sqli": ("SQL Injection", "critical"),
            "xss": ("Cross-Site Scripting", "high"),
            "cross-site scripting": ("Cross-Site Scripting", "high"),
            "lfi": ("Local File Inclusion", "high"),
            "rfi": ("Remote File Inclusion", "critical"),
            "rce": ("Remote Code Execution", "critical"),
            "command injection": ("Command Injection", "critical"),
            "xxe": ("XXE Injection", "high"),
            "ssrf": ("Server-Side Request Forgery", "high"),
            "open redirect": ("Open Redirect", "medium"),
            "directory listing": ("Directory Listing", "low"),
            "wordpress": ("WordPress Detected", "info"),
            "wp-content": ("WordPress Detected", "info"),
            "phpinfo": ("PHP Info Exposed", "medium"),
            ".git": ("Git Repository Exposed", "high"),
            ".env": ("Environment File Exposed", "critical"),
            "backup": ("Backup File Found", "medium"),
        }
        
        for keyword, (name, risk) in vuln_map.items():
            if keyword in output_lower:
                findings.append(Finding(
                    type=FindingType.VULNERABILITY,
                    value=name,
                    risk=risk,
                    details={"detected_by": command.split()[0]}
                ))
        
        # Technology detection
        tech_patterns = [
            (r'nginx[/\s]*([\d.]+)?', "Nginx"),
            (r'apache[/\s]*([\d.]+)?', "Apache"),
            (r'php[/\s]*([\d.]+)?', "PHP"),
            (r'wordpress[/\s]*([\d.]+)?', "WordPress"),
            (r'drupal', "Drupal"),
            (r'joomla', "Joomla"),
            (r'tomcat[/\s]*([\d.]+)?', "Tomcat"),
        ]
        
        for pattern, tech in tech_patterns:
            match = re.search(pattern, output_lower)
            if match:
                version = match.group(1) if match.lastindex else ""
                findings.append(Finding(
                    type=FindingType.TECHNOLOGY,
                    value=f"{tech} {version}".strip()
                ))
        
        return findings


class ExploitAgent(BaseAgent):
    """Exploit Agent - Vulnerability exploitation"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.EXPLOIT,
            name="Exploit",
            description="""You specialize in exploitation:
- SQL injection with sqlmap
- Command injection with commix
- Authentication attacks with hydra
- Known CVE exploitation""",
            tools=["sqlmap", "commix", "hydra", "msfconsole", "searchsploit",
                   "crackmapexec", "netexec"],
            color="red",
            icon="💥",
            priority=4
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # SQLMap findings
        if 'sqlmap' in command.lower():
            if 'is vulnerable' in output_lower:
                findings.append(Finding(
                    type=FindingType.VULNERABILITY,
                    value="SQL Injection Confirmed",
                    risk="critical",
                    mitre_tactic="TA0001"
                ))
            
            # Database extraction
            db_match = re.search(r'\[\*\]\s*(\w+)', output)
            if db_match:
                findings.append(Finding(
                    type=FindingType.VULNERABILITY,
                    value=f"Database: {db_match.group(1)}",
                    risk="critical"
                ))
        
        # Credential findings
        cred_patterns = [
            r'login:\s*(\S+)\s+password:\s*(\S+)',
            r'username:\s*(\S+)\s+password:\s*(\S+)',
            r'\[(\S+)\].*password:\s*(\S+)',
            r'(\w+):(\w+)@',
        ]
        for pattern in cred_patterns:
            for match in re.finditer(pattern, output_lower):
                findings.append(Finding(
                    type=FindingType.CREDENTIAL,
                    value=f"{match.group(1)}:****",
                    risk="critical",
                    details={"username": match.group(1)},
                    mitre_tactic="TA0006"
                ))
        
        # Shell access
        if 'shell' in output_lower or 'session opened' in output_lower or 'meterpreter' in output_lower:
            findings.append(Finding(
                type=FindingType.VULNERABILITY,
                value="Shell Access Gained",
                risk="critical",
                mitre_tactic="TA0002"
            ))
        
        return findings


class PostExploitAgent(BaseAgent):
    """Post-Exploitation Agent - Post-compromise activities"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.POST_EXPLOIT,
            name="PostExploit",
            description="""You specialize in post-exploitation:
- Privilege escalation
- Credential harvesting
- Lateral movement
- Persistence mechanisms""",
            tools=["crackmapexec", "netexec", "evil-winrm", "impacket-secretsdump",
                   "impacket-psexec", "bloodhound-python", "mimikatz"],
            color="magenta",
            icon="🔓",
            priority=5
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # Hash findings
        hash_patterns = [
            r'([a-fA-F0-9]{32}:[a-fA-F0-9]{32})',  # NTLM
            r'(\$[0-9a-z]+\$[^\s:]+)',  # Unix hashes
        ]
        for pattern in hash_patterns:
            for match in re.finditer(pattern, output):
                findings.append(Finding(
                    type=FindingType.CREDENTIAL,
                    value=f"Hash: {match.group(1)[:30]}...",
                    risk="critical",
                    mitre_tactic="TA0006"
                ))
        
        # Privilege escalation vectors
        privesc_keywords = {
            "suid": "SUID binary found",
            "sudo": "Sudo privilege",
            "writable": "Writable path found",
            "admin": "Admin access",
            "root": "Root access",
            "system": "SYSTEM access",
            "nt authority": "NT AUTHORITY access",
        }
        
        for keyword, desc in privesc_keywords.items():
            if keyword in output_lower:
                findings.append(Finding(
                    type=FindingType.VULNERABILITY,
                    value=desc,
                    risk="high",
                    mitre_tactic="TA0004"
                ))
        
        return findings


class CloudAgent(BaseAgent):
    """Cloud Agent - Cloud security assessment"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.CLOUD,
            name="Cloud",
            description="""You specialize in cloud security:
- AWS security assessment with prowler, pacu
- Azure security with scout-suite
- GCP security assessment
- S3 bucket enumeration""",
            tools=["prowler", "scout", "pacu", "aws", "az", "gcloud",
                   "s3scanner", "cloudsploit"],
            color="blue",
            icon="☁️",
            priority=6
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # S3 buckets
        s3_pattern = r's3://([a-zA-Z0-9.-]+)'
        for match in re.finditer(s3_pattern, output):
            findings.append(Finding(
                type=FindingType.CLOUD_RESOURCE,
                value=f"S3 Bucket: {match.group(1)}",
                risk="medium"
            ))
        
        # Public access
        if 'public' in output_lower and ('bucket' in output_lower or 'blob' in output_lower):
            findings.append(Finding(
                type=FindingType.VULNERABILITY,
                value="Public Cloud Storage",
                risk="high",
                mitre_tactic="TA0001"
            ))
        
        # IAM issues
        if 'overprivileged' in output_lower or 'admin' in output_lower:
            findings.append(Finding(
                type=FindingType.VULNERABILITY,
                value="IAM Privilege Issue",
                risk="high"
            ))
        
        # Cloud resources
        resource_patterns = [
            (r'i-[a-f0-9]{8,17}', "EC2 Instance"),
            (r'arn:aws:[^:]+:[^:]*:[^:]*:([^\s]+)', "AWS Resource"),
            (r'projects/([^/\s]+)', "GCP Project"),
        ]
        
        for pattern, rtype in resource_patterns:
            for match in re.finditer(pattern, output):
                findings.append(Finding(
                    type=FindingType.CLOUD_RESOURCE,
                    value=f"{rtype}: {match.group(1) if match.lastindex else match.group(0)}"
                ))
        
        return findings


class ContainerAgent(BaseAgent):
    """Container Agent - Container and Kubernetes security"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.CONTAINER,
            name="Container",
            description="""You specialize in container security:
- Docker security assessment
- Kubernetes security with kube-hunter, kube-bench
- Container vulnerability scanning with trivy
- Container escape techniques""",
            tools=["trivy", "kube-hunter", "kube-bench", "kubectl", "docker",
                   "docker-bench-security"],
            color="cyan",
            icon="📦",
            priority=6
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # Container images
        image_pattern = r'([a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)'
        for match in re.finditer(image_pattern, output):
            findings.append(Finding(
                type=FindingType.CONTAINER,
                value=f"Image: {match.group(1)}"
            ))
        
        # Vulnerabilities from trivy
        vuln_pattern = r'(CVE-\d{4}-\d+)\s+(\w+)'
        for match in re.finditer(vuln_pattern, output):
            cve, severity = match.groups()
            risk = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low"
            }.get(severity.lower(), "info")
            
            findings.append(Finding(
                type=FindingType.VULNERABILITY,
                value=cve,
                risk=risk,
                details={"severity": severity}
            ))
        
        # Kubernetes issues
        k8s_issues = [
            ("privileged", "Privileged container"),
            ("hostnetwork", "Host network access"),
            ("hostpid", "Host PID access"),
            ("capabilities", "Dangerous capabilities"),
        ]
        
        for keyword, desc in k8s_issues:
            if keyword in output_lower:
                findings.append(Finding(
                    type=FindingType.VULNERABILITY,
                    value=desc,
                    risk="high"
                ))
        
        return findings


class BinaryAgent(BaseAgent):
    """Binary Agent - Binary analysis and reverse engineering"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.BINARY,
            name="Binary",
            description="""You specialize in binary analysis:
- Binary security checks with checksec
- String extraction and analysis
- Disassembly with objdump, radare2
- Debugging with gdb""",
            tools=["checksec", "strings", "file", "objdump", "readelf",
                   "ltrace", "strace", "gdb", "radare2", "binwalk"],
            color="yellow",
            icon="🔬",
            priority=7
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        output_lower = output.lower()
        
        # Binary protections
        protections = {
            "nx enabled": ("NX Enabled", "info"),
            "nx disabled": ("NX Disabled", "high"),
            "canary found": ("Stack Canary", "info"),
            "no canary": ("No Stack Canary", "high"),
            "pie enabled": ("PIE Enabled", "info"),
            "no pie": ("No PIE", "medium"),
            "relro full": ("Full RELRO", "info"),
            "relro partial": ("Partial RELRO", "low"),
            "no relro": ("No RELRO", "medium"),
        }
        
        for keyword, (desc, risk) in protections.items():
            if keyword in output_lower:
                findings.append(Finding(
                    type=FindingType.BINARY_INFO,
                    value=desc,
                    risk=risk
                ))
        
        # Interesting strings
        interesting_patterns = [
            (r'password[=:]\s*(\S+)', "Password in strings"),
            (r'secret[=:]\s*(\S+)', "Secret in strings"),
            (r'api[_-]?key[=:]\s*(\S+)', "API key in strings"),
            (r'flag\{[^}]+\}', "Flag found"),
        ]
        
        for pattern, desc in interesting_patterns:
            if re.search(pattern, output_lower):
                findings.append(Finding(
                    type=FindingType.VULNERABILITY,
                    value=desc,
                    risk="medium" if "flag" not in desc.lower() else "critical"
                ))
        
        return findings


class CTFAgent(BaseAgent):
    """CTF Agent - CTF challenge solving"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.CTF,
            name="CTF",
            description="""You specialize in CTF challenges:
- Steganography with steghide, zsteg, stegsolve
- Forensics with volatility, foremost
- Cryptography challenges
- Flag extraction""",
            tools=["steghide", "zsteg", "stegsolve", "exiftool", "binwalk",
                   "foremost", "volatility", "file", "xxd", "strings"],
            color="magenta",
            icon="🏆",
            priority=8
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        
        # Flag patterns
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'HTB\{[^}]+\}',
            r'THM\{[^}]+\}',
            r'picoCTF\{[^}]+\}',
        ]
        
        for pattern in flag_patterns:
            for match in re.finditer(pattern, output):
                findings.append(Finding(
                    type=FindingType.FLAG,
                    value=match.group(0),
                    risk="critical"
                ))
        
        # Hidden data
        if 'hidden' in output.lower() or 'embedded' in output.lower():
            findings.append(Finding(
                type=FindingType.FILE,
                value="Hidden data detected",
                risk="medium"
            ))
        
        # File carving results
        carved_pattern = r'Extracted:\s*(\S+)'
        for match in re.finditer(carved_pattern, output):
            findings.append(Finding(
                type=FindingType.FILE,
                value=f"Carved: {match.group(1)}"
            ))
        
        return findings


class OSINTAgent(BaseAgent):
    """OSINT Agent - Open Source Intelligence"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.OSINT,
            name="OSINT",
            description="""You specialize in OSINT:
- Subdomain enumeration with amass, subfinder
- Email harvesting with theHarvester
- Username search with sherlock
- DNS reconnaissance""",
            tools=["amass", "subfinder", "theHarvester", "sherlock", "holehe",
                   "dnsrecon", "dnsenum", "fierce", "whois", "dig"],
            color="cyan",
            icon="🔎",
            priority=2
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        findings = []
        
        # Subdomains
        subdomain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
        for match in re.finditer(subdomain_pattern, output):
            domain = match.group(0)
            if self.memory.target in domain or domain.endswith(self.memory.target):
                findings.append(Finding(
                    type=FindingType.SUBDOMAIN,
                    value=domain
                ))
        
        # Emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        for match in re.finditer(email_pattern, output):
            findings.append(Finding(
                type=FindingType.EMAIL,
                value=match.group(0)
            ))
        
        # Social accounts (sherlock)
        if 'sherlock' in command.lower():
            account_pattern = r'\[\+\]\s*(\S+):\s*(\S+)'
            for match in re.finditer(account_pattern, output):
                findings.append(Finding(
                    type=FindingType.USER,
                    value=f"{match.group(1)}: {match.group(2)}",
                    details={"platform": match.group(1)}
                ))
        
        return findings


class ReportingAgent(BaseAgent):
    """Reporting Agent - Generate reports and summaries"""
    
    def __init__(self, ai_service, memory: SharedMemory):
        config = AgentConfig(
            role=AgentRole.REPORTING,
            name="Reporting",
            description="""You specialize in reporting:
- Generate executive summaries
- Create technical reports
- Organize findings by risk
- Provide remediation recommendations""",
            tools=[],  # No external tools - uses AI
            color="white",
            icon="📝",
            priority=10
        )
        super().__init__(config, ai_service, memory)
    
    async def analyze_output(self, command: str, output: str) -> List[Finding]:
        return []  # Reporting agent doesn't execute commands
    
    async def generate_report(self) -> str:
        """Generate a comprehensive report"""
        summary = self.memory.get_summary()
        
        # Get critical and high findings
        critical = await self.memory.get_findings(risk="critical")
        high = await self.memory.get_findings(risk="high")
        
        prompt = f"""Generate a penetration test executive summary based on these findings:

Target: {self.memory.target}
Total Findings: {summary['total_findings']}
Critical: {summary['by_risk']['critical']}
High: {summary['by_risk']['high']}
Medium: {summary['by_risk']['medium']}

Critical Findings:
{chr(10).join(f'- {f.value}' for f in critical[:10])}

High Findings:
{chr(10).join(f'- {f.value}' for f in high[:10])}

Credentials Found: {summary['credentials_found']}
Vulnerabilities: {summary['vulnerabilities_found']}

Provide:
1. Executive Summary (2-3 sentences)
2. Key Risks
3. Immediate Recommendations
"""
        
        try:
            report = self.ai.ask(prompt)
            return report
        except:
            return "Report generation failed"


# =============================================================================
# COORDINATOR AGENT
# =============================================================================

class CoordinatorAgent:
    """
    Coordinator Agent - Orchestrates all agents.
    Decides which agent should work based on findings and phase.
    """
    
    def __init__(self, ai_service, memory: SharedMemory):
        self.ai = ai_service
        self.memory = memory
        self.agents: Dict[str, BaseAgent] = {}
        self.active_agent: Optional[str] = None
        self.round = 0
        self.max_rounds = 20
        self.phase = "recon"  # recon, enum, exploit, post
    
    def add_agent(self, agent: BaseAgent):
        """Add an agent to the team"""
        self.agents[agent.name] = agent
    
    def get_system_prompt(self) -> str:
        return f"""You are the Coordinator of a penetration testing team.

Your team (12 agents):
{self._list_agents()}

Target: {self.memory.target}
Current Phase: {self.phase}

Your job:
1. Analyze current findings
2. Decide which agent should work next
3. Give them a specific task
4. Progress through phases: recon → enum → exploit → post

Rules:
- Start with OSINT/Recon agents
- Use Network agent after finding ports
- Use Web agent for HTTP services
- Only use Exploit agent when vulnerabilities found
- Use Cloud/Container agents if relevant services found

Output format:
NEXT_AGENT: [agent name]
TASK: [specific task]
REASON: [why]

Or if done:
NEXT_AGENT: DONE
REASON: [why]
"""
    
    def _list_agents(self) -> str:
        lines = []
        for name, agent in sorted(self.agents.items(), key=lambda x: x[1].config.priority):
            state = agent.state.value
            tasks = agent.tasks_completed
            findings = agent.findings_count
            lines.append(f"- {agent.config.icon} {name}: {state}, {tasks} tasks, {findings} findings")
        return '\n'.join(lines)
    
    async def decide_next(self) -> tuple:
        """Decide which agent should work next"""
        summary = self.memory.get_summary()
        
        context = f"""Round: {self.round}/{self.max_rounds}
Phase: {self.phase}

Team status:
{self._list_agents()}

Findings summary:
- Total: {summary['total_findings']}
- Ports: {summary['by_type'].get('port', 0)}
- Services: {summary['by_type'].get('service', 0)}
- Subdomains: {summary['by_type'].get('subdomain', 0)}
- Directories: {summary['by_type'].get('directory', 0)}
- Vulnerabilities: {summary['by_type'].get('vulnerability', 0)}
- Credentials: {summary['credentials_found']}

Risk breakdown:
- Critical: {summary['by_risk']['critical']}
- High: {summary['by_risk']['high']}
- Medium: {summary['by_risk']['medium']}

What should we do next?"""
        
        try:
            response = self.ai.ask(context, system_prompt=self.get_system_prompt())
        except:
            response = self.ai.ask(context)
        
        next_agent = None
        task = None
        reason = None
        
        for line in response.split('\n'):
            line = line.strip()
            if line.upper().startswith('NEXT_AGENT:'):
                next_agent = line.split(':', 1)[1].strip()
            elif line.upper().startswith('TASK:'):
                task = line.split(':', 1)[1].strip()
            elif line.upper().startswith('REASON:'):
                reason = line.split(':', 1)[1].strip()
        
        return next_agent, task, reason
    
    async def run(self, max_rounds: int = None) -> Dict:
        """Run the coordinated pentest"""
        if max_rounds:
            self.max_rounds = max_rounds
        
        console.print(Panel(
            f"[bold]🎯 Target:[/bold] {self.memory.target}\n"
            f"[bold]👥 Team:[/bold] {len(self.agents)} agents\n"
            f"[bold]🔄 Max Rounds:[/bold] {self.max_rounds}",
            title="🤖 Multi-Agent Pentest v4.0",
            border_style="cyan"
        ))
        
        while self.round < self.max_rounds:
            self.round += 1
            
            console.print(f"\n[bold cyan]{'═'*20} Round {self.round}/{self.max_rounds} {'═'*20}[/bold cyan]")
            
            # Update phase based on findings
            await self._update_phase()
            
            # Coordinator decides
            next_agent, task, reason = await self.decide_next()
            
            if not next_agent or next_agent.upper() == "DONE":
                console.print(f"\n[green]✓ Coordinator: Assessment complete![/green]")
                console.print(f"[dim]Reason: {reason}[/dim]")
                break
            
            # Find agent
            agent = self._find_agent(next_agent)
            
            if agent:
                console.print(f"\n[bold]📋 Coordinator → {agent.config.icon} {agent.name}:[/bold]")
                console.print(f"[dim]Task: {task}[/dim]")
                console.print(f"[dim]Reason: {reason}[/dim]")
                
                self.active_agent = agent.name
                await agent.run_task(task)
                self.active_agent = None
            else:
                console.print(f"[yellow]⚠ Agent not found: {next_agent}[/yellow]")
            
            await asyncio.sleep(0.3)
        
        # Generate final report
        if "Reporting" in self.agents:
            console.print("\n[bold]📝 Generating report...[/bold]")
            report = await self.agents["Reporting"].generate_report()
            console.print(Panel(report, title="Executive Summary", border_style="green"))
        
        return self.get_results()
    
    async def _update_phase(self):
        """Update phase based on findings"""
        summary = self.memory.get_summary()
        
        if summary['by_risk']['critical'] > 0 or summary['by_risk']['high'] > 2:
            self.phase = "post"
        elif summary['by_type'].get('vulnerability', 0) > 0:
            self.phase = "exploit"
        elif summary['by_type'].get('port', 0) > 0:
            self.phase = "enum"
        else:
            self.phase = "recon"
    
    def _find_agent(self, name: str) -> Optional[BaseAgent]:
        """Find agent by name (fuzzy match)"""
        if name in self.agents:
            return self.agents[name]
        
        name_lower = name.lower()
        for agent_name, agent in self.agents.items():
            if name_lower in agent_name.lower():
                return agent
        
        return None
    
    def get_results(self) -> Dict:
        """Get final results"""
        summary = self.memory.get_summary()
        
        return {
            "target": self.memory.target,
            "rounds": self.round,
            "findings": summary,
            "all_findings": [
                {
                    "type": f.type.value,
                    "value": f.value,
                    "risk": f.risk,
                    "agent": f.source_agent
                }
                for f in self.memory.findings
            ],
            "commands": len(self.memory.commands_executed),
            "credentials": self.memory.credentials,
            "vulnerabilities": self.memory.vulnerabilities,
            "flags": self.memory.flags,
        }


# =============================================================================
# MULTI-AGENT PENTEST CLASS
# =============================================================================

class MultiAgentPentest:
    """
    Main class for multi-agent penetration testing.
    Creates all 12 agents and coordinates them.
    """
    
    def __init__(self, target: str, ai_service, scope: List[str] = None):
        self.target = target
        self.ai = ai_service
        self.memory = SharedMemory()
        self.memory.target = target
        self.memory.scope = scope or [target]
        
        # Create coordinator
        self.coordinator = CoordinatorAgent(ai_service, self.memory)
        
        # Create all 12 specialized agents
        self.agents = {
            "Recon": ReconAgent(ai_service, self.memory),
            "Network": NetworkAgent(ai_service, self.memory),
            "Web": WebAgent(ai_service, self.memory),
            "Exploit": ExploitAgent(ai_service, self.memory),
            "PostExploit": PostExploitAgent(ai_service, self.memory),
            "Cloud": CloudAgent(ai_service, self.memory),
            "Container": ContainerAgent(ai_service, self.memory),
            "Binary": BinaryAgent(ai_service, self.memory),
            "CTF": CTFAgent(ai_service, self.memory),
            "OSINT": OSINTAgent(ai_service, self.memory),
            "Reporting": ReportingAgent(ai_service, self.memory),
        }
        
        # Add agents to coordinator
        for agent in self.agents.values():
            self.coordinator.add_agent(agent)
    
    async def run(self, max_rounds: int = 20) -> Dict:
        """Run the multi-agent pentest"""
        return await self.coordinator.run(max_rounds)
    
    def get_memory(self) -> SharedMemory:
        """Get shared memory"""
        return self.memory
    
    def get_agent_count(self) -> int:
        """Get number of agents"""
        return len(self.agents)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'MultiAgentPentest',
    'SharedMemory',
    'Finding',
    'FindingType',
    'AgentRole',
    'AgentState',
    'BaseAgent',
    'ReconAgent',
    'NetworkAgent',
    'WebAgent',
    'ExploitAgent',
    'PostExploitAgent',
    'CloudAgent',
    'ContainerAgent',
    'BinaryAgent',
    'CTFAgent',
    'OSINTAgent',
    'ReportingAgent',
    'CoordinatorAgent',
]
