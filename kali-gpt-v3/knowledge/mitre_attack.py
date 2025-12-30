"""
MITRE ATT&CK Framework Integration

Maps penetration testing actions to MITRE ATT&CK tactics and techniques.
Provides:
- Technique database
- Tactic progression tracking
- Tool-to-technique mapping
- Attack chain visualization
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import json


class Tactic(str, Enum):
    """MITRE ATT&CK Tactics (Enterprise)"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Technique:
    """MITRE ATT&CK Technique"""
    id: str  # e.g., T1595
    name: str
    tactic: Tactic
    description: str = ""
    sub_techniques: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    detection: str = ""
    platforms: List[str] = field(default_factory=list)
    

@dataclass
class AttackStep:
    """A step in an attack chain"""
    technique: Technique
    tool: str
    command: Optional[str] = None
    status: str = "pending"  # pending, in_progress, success, failed, skipped
    output: Optional[str] = None
    findings: List[Dict] = field(default_factory=list)


@dataclass  
class AttackChain:
    """Chain of attack steps following MITRE ATT&CK"""
    target: str
    steps: List[AttackStep] = field(default_factory=list)
    current_tactic: Tactic = Tactic.RECONNAISSANCE
    tactics_completed: List[Tactic] = field(default_factory=list)
    

class MITREKnowledgeBase:
    """
    MITRE ATT&CK Knowledge Base
    
    Contains technique definitions and tool mappings for penetration testing.
    """
    
    def __init__(self):
        self.techniques: Dict[str, Technique] = {}
        self.tool_mappings: Dict[str, List[str]] = {}  # tool -> technique IDs
        self._load_techniques()
        self._load_tool_mappings()
    
    def _load_techniques(self):
        """Load MITRE ATT&CK techniques relevant to pentesting"""
        
        techniques_data = [
            # ===== RECONNAISSANCE =====
            Technique(
                id="T1595",
                name="Active Scanning",
                tactic=Tactic.RECONNAISSANCE,
                description="Adversaries may execute active reconnaissance scans to gather information.",
                sub_techniques=["T1595.001", "T1595.002", "T1595.003"],
                tools=["nmap", "masscan", "rustscan", "unicornscan", "zmap"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1595.001",
                name="Scanning IP Blocks",
                tactic=Tactic.RECONNAISSANCE,
                description="Scan IP blocks to gather information about hosts.",
                tools=["nmap", "masscan", "zmap"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1595.002", 
                name="Vulnerability Scanning",
                tactic=Tactic.RECONNAISSANCE,
                description="Scan for vulnerabilities in target systems.",
                tools=["nmap", "nessus", "openvas", "nikto", "nuclei"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1592",
                name="Gather Victim Host Information",
                tactic=Tactic.RECONNAISSANCE,
                description="Gather information about victim hosts.",
                sub_techniques=["T1592.001", "T1592.002", "T1592.004"],
                tools=["whatweb", "wappalyzer", "builtwith", "httpx"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1592.002",
                name="Software",
                tactic=Tactic.RECONNAISSANCE,
                description="Identify software running on target systems.",
                tools=["whatweb", "wappalyzer", "nmap", "httpx"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1589",
                name="Gather Victim Identity Information",
                tactic=Tactic.RECONNAISSANCE,
                description="Gather victim identity information like credentials and emails.",
                sub_techniques=["T1589.001", "T1589.002", "T1589.003"],
                tools=["theHarvester", "hunter.io", "phonebook", "linkedin"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1590",
                name="Gather Victim Network Information",
                tactic=Tactic.RECONNAISSANCE,
                description="Gather network information about targets.",
                sub_techniques=["T1590.001", "T1590.002", "T1590.004", "T1590.005"],
                tools=["whois", "dig", "nslookup", "amass", "subfinder"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1590.002",
                name="DNS",
                tactic=Tactic.RECONNAISSANCE,
                description="Gather DNS information about targets.",
                tools=["dig", "nslookup", "dnsenum", "dnsrecon", "fierce"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1590.005",
                name="IP Addresses",
                tactic=Tactic.RECONNAISSANCE,
                description="Gather IP address information.",
                tools=["whois", "amass", "subfinder", "shodan"],
                platforms=["PRE"]
            ),
            Technique(
                id="T1593",
                name="Search Open Websites/Domains",
                tactic=Tactic.RECONNAISSANCE,
                description="Search open websites and domains for information.",
                sub_techniques=["T1593.001", "T1593.002"],
                tools=["google", "shodan", "censys", "securitytrails"],
                platforms=["PRE"]
            ),
            
            # ===== INITIAL ACCESS =====
            Technique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic=Tactic.INITIAL_ACCESS,
                description="Exploit vulnerabilities in public-facing applications.",
                tools=["msfconsole", "sqlmap", "nuclei", "burpsuite"],
                platforms=["Linux", "Windows", "macOS", "Network"]
            ),
            Technique(
                id="T1133",
                name="External Remote Services",
                tactic=Tactic.INITIAL_ACCESS,
                description="Leverage external remote services for access.",
                tools=["hydra", "medusa", "ncrack", "ssh", "rdp"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1078",
                name="Valid Accounts",
                tactic=Tactic.INITIAL_ACCESS,
                description="Use valid accounts to gain access.",
                sub_techniques=["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
                tools=["hydra", "medusa", "crackmapexec", "spray"],
                platforms=["Linux", "Windows", "macOS", "Cloud"]
            ),
            
            # ===== EXECUTION =====
            Technique(
                id="T1059",
                name="Command and Scripting Interpreter",
                tactic=Tactic.EXECUTION,
                description="Execute commands via command-line interface.",
                sub_techniques=["T1059.001", "T1059.003", "T1059.004"],
                tools=["bash", "powershell", "cmd", "python"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1203",
                name="Exploitation for Client Execution",
                tactic=Tactic.EXECUTION,
                description="Exploit client application vulnerabilities.",
                tools=["msfconsole", "beef", "social_engineering_toolkit"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            
            # ===== DISCOVERY =====
            Technique(
                id="T1046",
                name="Network Service Discovery",
                tactic=Tactic.DISCOVERY,
                description="Discover network services.",
                tools=["nmap", "masscan", "netstat", "ss"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1083",
                name="File and Directory Discovery",
                tactic=Tactic.DISCOVERY,
                description="Enumerate files and directories.",
                tools=["gobuster", "ffuf", "dirb", "dirsearch", "feroxbuster"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1087",
                name="Account Discovery",
                tactic=Tactic.DISCOVERY,
                description="Discover accounts on a system.",
                sub_techniques=["T1087.001", "T1087.002"],
                tools=["enum4linux", "crackmapexec", "ldapsearch", "rpcclient"],
                platforms=["Linux", "Windows"]
            ),
            Technique(
                id="T1018",
                name="Remote System Discovery",
                tactic=Tactic.DISCOVERY,
                description="Discover remote systems on a network.",
                tools=["nmap", "ping", "arp-scan", "netdiscover"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1082",
                name="System Information Discovery",
                tactic=Tactic.DISCOVERY,
                description="Gather detailed system information.",
                tools=["uname", "systeminfo", "lsb_release", "hostnamectl"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            
            # ===== CREDENTIAL ACCESS =====
            Technique(
                id="T1110",
                name="Brute Force",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Brute force credentials.",
                sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
                tools=["hydra", "medusa", "ncrack", "john", "hashcat"],
                platforms=["Linux", "Windows", "macOS", "Network"]
            ),
            Technique(
                id="T1110.001",
                name="Password Guessing",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Guess passwords for accounts.",
                tools=["hydra", "medusa", "burpsuite"],
                platforms=["Linux", "Windows", "macOS", "Network"]
            ),
            Technique(
                id="T1110.002",
                name="Password Cracking",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Crack password hashes.",
                tools=["john", "hashcat", "ophcrack"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1003",
                name="OS Credential Dumping",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Dump credentials from the operating system.",
                sub_techniques=["T1003.001", "T1003.002", "T1003.003"],
                tools=["mimikatz", "secretsdump", "lsass", "hashdump"],
                platforms=["Linux", "Windows"]
            ),
            Technique(
                id="T1552",
                name="Unsecured Credentials",
                tactic=Tactic.CREDENTIAL_ACCESS,
                description="Search for unsecured credentials.",
                sub_techniques=["T1552.001", "T1552.004"],
                tools=["grep", "find", "trufflehog", "gitleaks"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            
            # ===== PRIVILEGE ESCALATION =====
            Technique(
                id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic=Tactic.PRIVILEGE_ESCALATION,
                description="Exploit vulnerabilities for privilege escalation.",
                tools=["msfconsole", "linux_exploit_suggester", "windows_exploit_suggester"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1548",
                name="Abuse Elevation Control Mechanism",
                tactic=Tactic.PRIVILEGE_ESCALATION,
                description="Abuse elevation control mechanisms.",
                sub_techniques=["T1548.001", "T1548.002", "T1548.003"],
                tools=["sudo", "gtfobins", "uacbypass"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1055",
                name="Process Injection",
                tactic=Tactic.PRIVILEGE_ESCALATION,
                description="Inject code into processes.",
                tools=["msfconsole", "cobalt_strike", "shellcode"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            
            # ===== LATERAL MOVEMENT =====
            Technique(
                id="T1021",
                name="Remote Services",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Use remote services to move laterally.",
                sub_techniques=["T1021.001", "T1021.002", "T1021.004", "T1021.006"],
                tools=["ssh", "psexec", "wmiexec", "smbexec", "winrm"],
                platforms=["Linux", "Windows"]
            ),
            Technique(
                id="T1021.001",
                name="Remote Desktop Protocol",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Use RDP for lateral movement.",
                tools=["xfreerdp", "rdesktop", "rdp"],
                platforms=["Windows"]
            ),
            Technique(
                id="T1021.002",
                name="SMB/Windows Admin Shares",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Use SMB for lateral movement.",
                tools=["smbclient", "psexec", "smbexec", "crackmapexec"],
                platforms=["Windows"]
            ),
            Technique(
                id="T1570",
                name="Lateral Tool Transfer",
                tactic=Tactic.LATERAL_MOVEMENT,
                description="Transfer tools between systems.",
                tools=["scp", "nc", "curl", "wget", "certutil"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            
            # ===== COLLECTION =====
            Technique(
                id="T1005",
                name="Data from Local System",
                tactic=Tactic.COLLECTION,
                description="Collect data from local system.",
                tools=["find", "grep", "cat", "type"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1039",
                name="Data from Network Shared Drive",
                tactic=Tactic.COLLECTION,
                description="Collect data from network shares.",
                tools=["smbclient", "mount", "net"],
                platforms=["Linux", "Windows"]
            ),
            
            # ===== POST-EXPLOITATION ENUMERATION =====
            Technique(
                id="T1057",
                name="Process Discovery",
                tactic=Tactic.DISCOVERY,
                description="Discover running processes.",
                tools=["ps", "tasklist", "pspy", "procmon"],
                platforms=["Linux", "Windows", "macOS"]
            ),
            Technique(
                id="T1016",
                name="System Network Configuration Discovery",
                tactic=Tactic.DISCOVERY,
                description="Discover network configuration.",
                tools=["ifconfig", "ipconfig", "ip", "netstat", "route"],
                platforms=["Linux", "Windows", "macOS"]
            ),
        ]
        
        for tech in techniques_data:
            self.techniques[tech.id] = tech
    
    def _load_tool_mappings(self):
        """Create reverse mapping from tools to techniques"""
        
        self.tool_mappings = {
            # Reconnaissance tools
            "nmap": ["T1595", "T1595.001", "T1595.002", "T1046", "T1018", "T1592.002"],
            "masscan": ["T1595", "T1595.001", "T1018"],
            "rustscan": ["T1595", "T1595.001"],
            "whois": ["T1590", "T1590.005"],
            "dig": ["T1590", "T1590.002"],
            "nslookup": ["T1590", "T1590.002"],
            "dnsenum": ["T1590.002"],
            "dnsrecon": ["T1590.002"],
            "theHarvester": ["T1589", "T1589.002"],
            "amass": ["T1590", "T1590.002", "T1590.005"],
            "subfinder": ["T1590", "T1590.005"],
            "assetfinder": ["T1590.005"],
            "httpx": ["T1592", "T1592.002"],
            "whatweb": ["T1592", "T1592.002"],
            "wappalyzer": ["T1592", "T1592.002"],
            
            # Scanning tools
            "nikto": ["T1595.002", "T1190"],
            "nuclei": ["T1595.002", "T1190"],
            "nessus": ["T1595.002"],
            "openvas": ["T1595.002"],
            
            # Web enumeration
            "gobuster": ["T1083"],
            "ffuf": ["T1083"],
            "dirb": ["T1083"],
            "dirsearch": ["T1083"],
            "feroxbuster": ["T1083"],
            "wpscan": ["T1595.002", "T1592.002"],
            "burpsuite": ["T1190", "T1110.001"],
            
            # Exploitation
            "msfconsole": ["T1190", "T1068", "T1203"],
            "sqlmap": ["T1190"],
            "searchsploit": ["T1190"],
            
            # Credential attacks
            "hydra": ["T1110", "T1110.001", "T1078", "T1133"],
            "medusa": ["T1110", "T1110.001", "T1078"],
            "ncrack": ["T1110", "T1110.001"],
            "john": ["T1110.002"],
            "hashcat": ["T1110.002"],
            "mimikatz": ["T1003", "T1003.001"],
            "secretsdump": ["T1003"],
            
            # SMB/AD enumeration
            "enum4linux": ["T1087", "T1087.002"],
            "smbmap": ["T1021.002", "T1039"],
            "smbclient": ["T1021.002", "T1039"],
            "crackmapexec": ["T1087", "T1078", "T1021.002"],
            "rpcclient": ["T1087"],
            "ldapsearch": ["T1087.002"],
            
            # Lateral movement
            "psexec": ["T1021.002"],
            "wmiexec": ["T1021.002"],
            "smbexec": ["T1021.002"],
            "evil-winrm": ["T1021.006"],
            "xfreerdp": ["T1021.001"],
            "ssh": ["T1021.004"],
            
            # Post-exploitation
            "linpeas": ["T1082", "T1083", "T1057", "T1016", "T1552"],
            "winpeas": ["T1082", "T1083", "T1057", "T1016", "T1552"],
            "bloodhound": ["T1087.002", "T1069"],
            "pspy": ["T1057"],
        }
    
    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Get technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_for_tactic(self, tactic: Tactic) -> List[Technique]:
        """Get all techniques for a tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def get_techniques_for_tool(self, tool: str) -> List[Technique]:
        """Get techniques that a tool can help with"""
        technique_ids = self.tool_mappings.get(tool.lower(), [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def get_tools_for_technique(self, technique_id: str) -> List[str]:
        """Get tools that can execute a technique"""
        technique = self.techniques.get(technique_id)
        if technique:
            return technique.tools
        return []
    
    def get_recommended_tools(self, tactic: Tactic) -> Dict[str, List[str]]:
        """Get recommended tools for a tactic"""
        techniques = self.get_techniques_for_tactic(tactic)
        
        recommendations = {}
        for tech in techniques:
            if tech.tools:
                recommendations[tech.id] = {
                    "name": tech.name,
                    "tools": tech.tools,
                    "description": tech.description
                }
        
        return recommendations
    
    def map_action_to_technique(self, tool: str, command: str) -> Optional[Technique]:
        """Map an action to the most likely MITRE technique"""
        techniques = self.get_techniques_for_tool(tool)
        
        if not techniques:
            return None
        
        # Simple heuristic: match based on command patterns
        command_lower = command.lower()
        
        for tech in techniques:
            # Check for specific patterns
            if tech.id == "T1595.001" and any(x in command_lower for x in ["-sn", "ping", "-sP"]):
                return tech
            if tech.id == "T1595.002" and any(x in command_lower for x in ["-sV", "--script vuln", "nikto", "nuclei"]):
                return tech
            if tech.id == "T1083" and any(x in command_lower for x in ["dir", "gobuster", "ffuf", "dirsearch"]):
                return tech
            if tech.id == "T1110" and any(x in command_lower for x in ["hydra", "medusa", "-l ", "-L ", "-p ", "-P "]):
                return tech
        
        # Default to first matching technique
        return techniques[0] if techniques else None
    
    def get_next_tactics(self, current_tactic: Tactic) -> List[Tactic]:
        """Get logical next tactics based on current position"""
        
        # Define typical attack flow
        tactic_flow = {
            Tactic.RECONNAISSANCE: [Tactic.INITIAL_ACCESS, Tactic.RESOURCE_DEVELOPMENT],
            Tactic.RESOURCE_DEVELOPMENT: [Tactic.INITIAL_ACCESS],
            Tactic.INITIAL_ACCESS: [Tactic.EXECUTION, Tactic.DISCOVERY],
            Tactic.EXECUTION: [Tactic.PERSISTENCE, Tactic.DISCOVERY, Tactic.PRIVILEGE_ESCALATION],
            Tactic.PERSISTENCE: [Tactic.PRIVILEGE_ESCALATION, Tactic.DISCOVERY],
            Tactic.PRIVILEGE_ESCALATION: [Tactic.DEFENSE_EVASION, Tactic.CREDENTIAL_ACCESS, Tactic.DISCOVERY],
            Tactic.DEFENSE_EVASION: [Tactic.CREDENTIAL_ACCESS, Tactic.DISCOVERY],
            Tactic.CREDENTIAL_ACCESS: [Tactic.LATERAL_MOVEMENT, Tactic.DISCOVERY],
            Tactic.DISCOVERY: [Tactic.LATERAL_MOVEMENT, Tactic.COLLECTION, Tactic.CREDENTIAL_ACCESS],
            Tactic.LATERAL_MOVEMENT: [Tactic.COLLECTION, Tactic.DISCOVERY, Tactic.CREDENTIAL_ACCESS],
            Tactic.COLLECTION: [Tactic.EXFILTRATION, Tactic.COMMAND_AND_CONTROL],
            Tactic.COMMAND_AND_CONTROL: [Tactic.EXFILTRATION, Tactic.IMPACT],
            Tactic.EXFILTRATION: [Tactic.IMPACT],
            Tactic.IMPACT: []
        }
        
        return tactic_flow.get(current_tactic, [])
    
    def to_json(self) -> str:
        """Export knowledge base to JSON"""
        data = {
            "techniques": {
                tid: {
                    "id": t.id,
                    "name": t.name,
                    "tactic": t.tactic.value,
                    "description": t.description,
                    "tools": t.tools,
                    "sub_techniques": t.sub_techniques
                }
                for tid, t in self.techniques.items()
            },
            "tool_mappings": self.tool_mappings
        }
        return json.dumps(data, indent=2)


# Singleton instance
_mitre_kb: Optional[MITREKnowledgeBase] = None


def get_mitre_kb() -> MITREKnowledgeBase:
    """Get or create MITRE knowledge base instance"""
    global _mitre_kb
    if _mitre_kb is None:
        _mitre_kb = MITREKnowledgeBase()
    return _mitre_kb
