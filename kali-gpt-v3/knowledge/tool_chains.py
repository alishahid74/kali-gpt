"""
Intelligent Tool Chaining System

Automatically selects and chains tools based on:
- Discovered services
- Identified technologies
- Previous findings
- MITRE ATT&CK alignment
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import re

from .mitre_attack import get_mitre_kb, Tactic, Technique


class ServiceType(str, Enum):
    """Common service types"""
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    MYSQL = "mysql"
    MSSQL = "mssql"
    POSTGRESQL = "postgresql"
    DNS = "dns"
    SMTP = "smtp"
    LDAP = "ldap"
    SNMP = "snmp"
    TELNET = "telnet"
    VNC = "vnc"
    WINRM = "winrm"
    UNKNOWN = "unknown"


@dataclass
class DiscoveredService:
    """Represents a discovered service"""
    host: str
    port: int
    protocol: str = "tcp"
    service: ServiceType = ServiceType.UNKNOWN
    version: Optional[str] = None
    banner: Optional[str] = None
    extra_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolChainStep:
    """A step in a tool chain"""
    tool: str
    command: str
    description: str
    priority: int = 5  # 1-10, lower = higher priority
    requires: List[str] = field(default_factory=list)  # Required previous findings
    produces: List[str] = field(default_factory=list)  # What this step produces
    technique_id: Optional[str] = None  # MITRE ATT&CK technique


@dataclass
class ToolChain:
    """A complete tool chain"""
    name: str
    description: str
    trigger: str  # What triggers this chain
    steps: List[ToolChainStep] = field(default_factory=list)
    tactic: Tactic = Tactic.RECONNAISSANCE


class ToolChainBuilder:
    """
    Builds intelligent tool chains based on discoveries
    
    Automatically determines what tools to run next based on:
    - Port/service discoveries
    - Technology fingerprints
    - Previously found information
    - Attack methodology
    """
    
    # Service-specific tool chains
    SERVICE_CHAINS: Dict[ServiceType, List[ToolChainStep]] = {
        ServiceType.HTTP: [
            ToolChainStep(
                tool="whatweb",
                command="whatweb -a 3 {target}",
                description="Identify web technologies",
                priority=1,
                produces=["web_technologies", "cms_type", "server_type"]
            ),
            ToolChainStep(
                tool="nikto",
                command="nikto -h {target} -Format txt",
                description="Web vulnerability scan",
                priority=2,
                produces=["web_vulnerabilities"],
                technique_id="T1595.002"
            ),
            ToolChainStep(
                tool="gobuster",
                command="gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 50",
                description="Directory enumeration",
                priority=3,
                produces=["directories", "files"],
                technique_id="T1083"
            ),
            ToolChainStep(
                tool="ffuf",
                command="ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403",
                description="Fast directory fuzzing",
                priority=4,
                produces=["directories", "files"],
                technique_id="T1083"
            ),
        ],
        ServiceType.HTTPS: [
            ToolChainStep(
                tool="sslscan",
                command="sslscan {host}:{port}",
                description="SSL/TLS configuration scan",
                priority=1,
                produces=["ssl_info", "ssl_vulnerabilities"]
            ),
            ToolChainStep(
                tool="testssl",
                command="testssl.sh {target}",
                description="Comprehensive SSL testing",
                priority=2,
                produces=["ssl_vulnerabilities", "cipher_info"]
            ),
            # Then same as HTTP
            ToolChainStep(
                tool="whatweb",
                command="whatweb -a 3 {target}",
                description="Identify web technologies",
                priority=3,
                produces=["web_technologies"]
            ),
            ToolChainStep(
                tool="nikto",
                command="nikto -h {target} -ssl -Format txt",
                description="Web vulnerability scan",
                priority=4,
                produces=["web_vulnerabilities"],
                technique_id="T1595.002"
            ),
        ],
        ServiceType.SSH: [
            ToolChainStep(
                tool="ssh-audit",
                command="ssh-audit {host}:{port}",
                description="SSH configuration audit",
                priority=1,
                produces=["ssh_algorithms", "ssh_vulnerabilities"]
            ),
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script ssh-auth-methods,ssh-hostkey {host}",
                description="SSH enumeration scripts",
                priority=2,
                produces=["ssh_auth_methods", "ssh_hostkey"]
            ),
        ],
        ServiceType.SMB: [
            ToolChainStep(
                tool="enum4linux",
                command="enum4linux -a {host}",
                description="SMB/Samba enumeration",
                priority=1,
                produces=["smb_shares", "smb_users", "smb_groups", "domain_info"],
                technique_id="T1087"
            ),
            ToolChainStep(
                tool="smbmap",
                command="smbmap -H {host}",
                description="SMB share enumeration",
                priority=2,
                produces=["smb_shares", "share_permissions"],
                technique_id="T1021.002"
            ),
            ToolChainStep(
                tool="smbclient",
                command="smbclient -L //{host}/ -N",
                description="List SMB shares",
                priority=3,
                produces=["smb_shares"]
            ),
            ToolChainStep(
                tool="crackmapexec",
                command="crackmapexec smb {host} --shares",
                description="CME share enumeration",
                priority=4,
                produces=["smb_shares", "smb_info"],
                technique_id="T1087"
            ),
            ToolChainStep(
                tool="nmap",
                command="nmap -p 139,445 --script smb-vuln* {host}",
                description="SMB vulnerability scan",
                priority=5,
                produces=["smb_vulnerabilities"],
                technique_id="T1595.002"
            ),
        ],
        ServiceType.FTP: [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script ftp-anon,ftp-bounce,ftp-vuln* {host}",
                description="FTP enumeration and vuln scan",
                priority=1,
                produces=["ftp_anon", "ftp_vulnerabilities"]
            ),
            ToolChainStep(
                tool="hydra",
                command="hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt ftp://{host}",
                description="FTP brute force (if needed)",
                priority=3,
                requires=["ftp_login_required"],
                produces=["ftp_credentials"],
                technique_id="T1110"
            ),
        ],
        ServiceType.MYSQL: [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script mysql-info,mysql-enum,mysql-vuln* {host}",
                description="MySQL enumeration",
                priority=1,
                produces=["mysql_version", "mysql_vulnerabilities"]
            ),
            ToolChainStep(
                tool="hydra",
                command="hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt mysql://{host}",
                description="MySQL brute force",
                priority=3,
                produces=["mysql_credentials"],
                technique_id="T1110"
            ),
        ],
        ServiceType.MSSQL: [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info {host}",
                description="MSSQL enumeration",
                priority=1,
                produces=["mssql_version", "mssql_info"]
            ),
            ToolChainStep(
                tool="crackmapexec",
                command="crackmapexec mssql {host}",
                description="MSSQL enumeration with CME",
                priority=2,
                produces=["mssql_info"]
            ),
        ],
        ServiceType.RDP: [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script rdp-ntlm-info,rdp-enum-encryption {host}",
                description="RDP enumeration",
                priority=1,
                produces=["rdp_info", "rdp_encryption"]
            ),
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script rdp-vuln-ms12-020 {host}",
                description="RDP vulnerability scan",
                priority=2,
                produces=["rdp_vulnerabilities"]
            ),
        ],
        ServiceType.LDAP: [
            ToolChainStep(
                tool="ldapsearch",
                command="ldapsearch -x -H ldap://{host} -s base namingContexts",
                description="LDAP base enumeration",
                priority=1,
                produces=["ldap_base_dn", "ldap_info"]
            ),
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script ldap-rootdse,ldap-search {host}",
                description="LDAP enumeration scripts",
                priority=2,
                produces=["ldap_info"],
                technique_id="T1087.002"
            ),
        ],
        ServiceType.SNMP: [
            ToolChainStep(
                tool="snmpwalk",
                command="snmpwalk -v2c -c public {host}",
                description="SNMP walk with public community",
                priority=1,
                produces=["snmp_info", "system_info"]
            ),
            ToolChainStep(
                tool="onesixtyone",
                command="onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt {host}",
                description="SNMP community string brute force",
                priority=2,
                produces=["snmp_communities"]
            ),
        ],
        ServiceType.DNS: [
            ToolChainStep(
                tool="dig",
                command="dig ANY {host} @{host}",
                description="DNS ANY query",
                priority=1,
                produces=["dns_records"]
            ),
            ToolChainStep(
                tool="dnsrecon",
                command="dnsrecon -d {domain} -t std,brt",
                description="DNS reconnaissance",
                priority=2,
                produces=["dns_records", "subdomains"],
                technique_id="T1590.002"
            ),
            ToolChainStep(
                tool="dig",
                command="dig axfr {domain} @{host}",
                description="DNS zone transfer attempt",
                priority=3,
                produces=["dns_zone"]
            ),
        ],
        ServiceType.SMTP: [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script smtp-commands,smtp-enum-users,smtp-vuln* {host}",
                description="SMTP enumeration",
                priority=1,
                produces=["smtp_commands", "smtp_users", "smtp_vulnerabilities"]
            ),
            ToolChainStep(
                tool="smtp-user-enum",
                command="smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {host}",
                description="SMTP user enumeration",
                priority=2,
                produces=["smtp_users"]
            ),
        ],
    }
    
    # Technology-specific chains (triggered by whatweb/wappalyzer findings)
    TECHNOLOGY_CHAINS: Dict[str, List[ToolChainStep]] = {
        "wordpress": [
            ToolChainStep(
                tool="wpscan",
                command="wpscan --url {target} --enumerate ap,at,u --api-token $WPSCAN_TOKEN",
                description="WordPress comprehensive scan",
                priority=1,
                produces=["wp_plugins", "wp_themes", "wp_users", "wp_vulnerabilities"]
            ),
        ],
        "joomla": [
            ToolChainStep(
                tool="joomscan",
                command="joomscan -u {target}",
                description="Joomla vulnerability scanner",
                priority=1,
                produces=["joomla_vulnerabilities", "joomla_version"]
            ),
        ],
        "drupal": [
            ToolChainStep(
                tool="droopescan",
                command="droopescan scan drupal -u {target}",
                description="Drupal vulnerability scanner",
                priority=1,
                produces=["drupal_vulnerabilities", "drupal_version"]
            ),
        ],
        "tomcat": [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script http-tomcat-manager-bruteforce {host}",
                description="Tomcat manager brute force",
                priority=1,
                produces=["tomcat_credentials"]
            ),
            ToolChainStep(
                tool="nuclei",
                command="nuclei -u {target} -tags tomcat",
                description="Nuclei Tomcat templates",
                priority=2,
                produces=["tomcat_vulnerabilities"]
            ),
        ],
        "iis": [
            ToolChainStep(
                tool="nmap",
                command="nmap -p {port} --script http-iis-webdav-vuln,http-iis-short-name-brute {host}",
                description="IIS vulnerability scan",
                priority=1,
                produces=["iis_vulnerabilities"]
            ),
        ],
        "nginx": [
            ToolChainStep(
                tool="nuclei",
                command="nuclei -u {target} -tags nginx",
                description="Nuclei Nginx templates",
                priority=1,
                produces=["nginx_vulnerabilities"]
            ),
        ],
        "apache": [
            ToolChainStep(
                tool="nuclei",
                command="nuclei -u {target} -tags apache",
                description="Nuclei Apache templates",
                priority=1,
                produces=["apache_vulnerabilities"]
            ),
        ],
        "phpmyadmin": [
            ToolChainStep(
                tool="nuclei",
                command="nuclei -u {target} -tags phpmyadmin",
                description="phpMyAdmin vulnerability scan",
                priority=1,
                produces=["phpmyadmin_vulnerabilities"]
            ),
        ],
    }
    
    # Port to service mapping
    PORT_SERVICE_MAP: Dict[int, ServiceType] = {
        21: ServiceType.FTP,
        22: ServiceType.SSH,
        23: ServiceType.TELNET,
        25: ServiceType.SMTP,
        53: ServiceType.DNS,
        80: ServiceType.HTTP,
        110: ServiceType.UNKNOWN,  # POP3
        139: ServiceType.SMB,
        143: ServiceType.UNKNOWN,  # IMAP
        161: ServiceType.SNMP,
        443: ServiceType.HTTPS,
        445: ServiceType.SMB,
        389: ServiceType.LDAP,
        636: ServiceType.LDAP,
        1433: ServiceType.MSSQL,
        1521: ServiceType.UNKNOWN,  # Oracle
        3306: ServiceType.MYSQL,
        3389: ServiceType.RDP,
        5432: ServiceType.POSTGRESQL,
        5900: ServiceType.VNC,
        5985: ServiceType.WINRM,
        5986: ServiceType.WINRM,
        8080: ServiceType.HTTP,
        8443: ServiceType.HTTPS,
    }
    
    def __init__(self):
        self.mitre_kb = get_mitre_kb()
        self.discovered_services: List[DiscoveredService] = []
        self.findings: Dict[str, Any] = {}
        self.executed_tools: List[str] = []
    
    def identify_service(self, port: int, service_hint: str = None) -> ServiceType:
        """Identify service type from port and optional hint"""
        
        # Check hint first
        if service_hint:
            hint_lower = service_hint.lower()
            for stype in ServiceType:
                if stype.value in hint_lower:
                    return stype
        
        # Fall back to port mapping
        return self.PORT_SERVICE_MAP.get(port, ServiceType.UNKNOWN)
    
    def add_discovered_service(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        service: str = None,
        version: str = None,
        **kwargs
    ) -> DiscoveredService:
        """Add a discovered service"""
        
        svc_type = self.identify_service(port, service)
        
        discovered = DiscoveredService(
            host=host,
            port=port,
            protocol=protocol,
            service=svc_type,
            version=version,
            extra_info=kwargs
        )
        
        self.discovered_services.append(discovered)
        return discovered
    
    def add_finding(self, key: str, value: Any):
        """Add a finding that might trigger additional chains"""
        self.findings[key] = value
    
    def get_chain_for_service(
        self,
        service: DiscoveredService,
        max_steps: int = 5
    ) -> List[ToolChainStep]:
        """Get tool chain for a specific service"""
        
        chain = self.SERVICE_CHAINS.get(service.service, [])
        
        # Format commands with target info
        formatted_chain = []
        for step in chain[:max_steps]:
            # Build target URL for web services
            if service.service in [ServiceType.HTTP, ServiceType.HTTPS]:
                protocol = "https" if service.service == ServiceType.HTTPS else "http"
                target = f"{protocol}://{service.host}:{service.port}"
            else:
                target = f"{service.host}:{service.port}"
            
            # Format command
            formatted_cmd = step.command.format(
                host=service.host,
                port=service.port,
                target=target,
                domain=service.host  # Might be a domain
            )
            
            formatted_step = ToolChainStep(
                tool=step.tool,
                command=formatted_cmd,
                description=step.description,
                priority=step.priority,
                requires=step.requires,
                produces=step.produces,
                technique_id=step.technique_id
            )
            formatted_chain.append(formatted_step)
        
        return formatted_chain
    
    def get_chain_for_technology(
        self,
        technology: str,
        target: str
    ) -> List[ToolChainStep]:
        """Get tool chain for a specific technology"""
        
        tech_lower = technology.lower()
        
        for tech_name, chain in self.TECHNOLOGY_CHAINS.items():
            if tech_name in tech_lower:
                # Format commands
                formatted_chain = []
                for step in chain:
                    # Extract host and port from target
                    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                    port = 443 if "https" in target else 80
                    
                    formatted_cmd = step.command.format(
                        target=target,
                        host=host,
                        port=port
                    )
                    
                    formatted_step = ToolChainStep(
                        tool=step.tool,
                        command=formatted_cmd,
                        description=step.description,
                        priority=step.priority,
                        requires=step.requires,
                        produces=step.produces,
                        technique_id=step.technique_id
                    )
                    formatted_chain.append(formatted_step)
                
                return formatted_chain
        
        return []
    
    def get_next_steps(
        self,
        completed_steps: List[str] = None,
        max_steps: int = 3
    ) -> List[ToolChainStep]:
        """Get next recommended steps based on current state"""
        
        completed = completed_steps or []
        all_steps = []
        
        # Get chains for all discovered services
        for service in self.discovered_services:
            chain = self.get_chain_for_service(service)
            for step in chain:
                # Skip if already executed similar command
                if step.tool not in [s.split()[0] for s in completed]:
                    all_steps.append(step)
        
        # Check for technology-specific chains
        for finding_key, finding_value in self.findings.items():
            if finding_key == "web_technologies" and isinstance(finding_value, list):
                for tech in finding_value:
                    # Find target URL for this finding
                    for svc in self.discovered_services:
                        if svc.service in [ServiceType.HTTP, ServiceType.HTTPS]:
                            protocol = "https" if svc.service == ServiceType.HTTPS else "http"
                            target = f"{protocol}://{svc.host}:{svc.port}"
                            chain = self.get_chain_for_technology(tech, target)
                            all_steps.extend(chain)
        
        # Sort by priority and filter
        all_steps.sort(key=lambda x: x.priority)
        
        # Remove duplicates (same tool)
        seen_tools = set()
        unique_steps = []
        for step in all_steps:
            if step.tool not in seen_tools:
                seen_tools.add(step.tool)
                unique_steps.append(step)
        
        return unique_steps[:max_steps]
    
    def parse_nmap_output(self, output: str, host: str) -> List[DiscoveredService]:
        """Parse nmap output to extract services"""
        
        services = []
        
        # Pattern: 22/tcp   open  ssh     OpenSSH 7.9p1
        port_pattern = r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"
        
        for match in re.finditer(port_pattern, output):
            port = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5).strip() if match.group(5) else None
            
            if state == "open":
                svc = self.add_discovered_service(
                    host=host,
                    port=port,
                    protocol=protocol,
                    service=service,
                    version=version
                )
                services.append(svc)
        
        return services
    
    def get_initial_recon_chain(self, target: str) -> List[ToolChainStep]:
        """Get initial reconnaissance chain for a target"""
        
        # Determine if target is IP or domain
        is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
        
        steps = [
            ToolChainStep(
                tool="nmap",
                command=f"nmap -sV -sC -T4 -Pn {target}",
                description="Service version detection with default scripts",
                priority=1,
                produces=["open_ports", "services", "versions"],
                technique_id="T1595"
            ),
        ]
        
        if not is_ip:
            # Add domain-specific recon
            steps.extend([
                ToolChainStep(
                    tool="whois",
                    command=f"whois {target}",
                    description="WHOIS information",
                    priority=2,
                    produces=["domain_info", "registrar"],
                    technique_id="T1590"
                ),
                ToolChainStep(
                    tool="dig",
                    command=f"dig {target} ANY +short",
                    description="DNS records lookup",
                    priority=2,
                    produces=["dns_records"],
                    technique_id="T1590.002"
                ),
                ToolChainStep(
                    tool="subfinder",
                    command=f"subfinder -d {target} -silent",
                    description="Subdomain enumeration",
                    priority=3,
                    produces=["subdomains"],
                    technique_id="T1590.005"
                ),
            ])
        
        return steps
    
    def get_full_chain(self, target: str) -> ToolChain:
        """Get a complete tool chain for a target"""
        
        return ToolChain(
            name=f"Full scan of {target}",
            description="Comprehensive penetration testing chain",
            trigger="manual",
            steps=self.get_initial_recon_chain(target),
            tactic=Tactic.RECONNAISSANCE
        )
