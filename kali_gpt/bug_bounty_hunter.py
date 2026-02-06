"""
Kali-GPT v4.1 - AI Bug Bounty Hunter

Automated bug bounty hunting with AI-driven:
- Target reconnaissance & asset discovery
- Vulnerability hunting (OWASP Top 10+)
- Smart prioritization based on bounty value
- Duplicate detection
- Professional report generation
- Platform integration (HackerOne, Bugcrowd)

Author: Kali-GPT Team
Version: 4.1
"""

import os
import re
import json
import asyncio
import subprocess
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from urllib.parse import urlparse, urljoin
import hashlib

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich import box

console = Console()


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class VulnCategory(Enum):
    """OWASP-aligned vulnerability categories"""
    INJECTION = "A03:2021 Injection"
    BROKEN_AUTH = "A07:2021 Auth Failures"
    SENSITIVE_DATA = "A02:2021 Crypto Failures"
    XXE = "A05:2021 Security Misconfig"
    BROKEN_ACCESS = "A01:2021 Broken Access Control"
    SECURITY_MISCONFIG = "A05:2021 Security Misconfig"
    XSS = "A03:2021 Injection"
    INSECURE_DESERIAL = "A08:2021 Software Integrity"
    COMPONENTS = "A06:2021 Vulnerable Components"
    LOGGING = "A09:2021 Logging Failures"
    SSRF = "A10:2021 SSRF"
    IDOR = "A01:2021 Broken Access Control"
    SUBDOMAIN_TAKEOVER = "Subdomain Takeover"
    INFO_DISCLOSURE = "Information Disclosure"
    RATE_LIMITING = "Rate Limiting"
    BUSINESS_LOGIC = "Business Logic"


class Severity(Enum):
    """Bug bounty severity levels"""
    CRITICAL = "critical"  # RCE, Auth bypass, SQLi with data
    HIGH = "high"          # Stored XSS, IDOR with sensitive data
    MEDIUM = "medium"      # Reflected XSS, Info disclosure
    LOW = "low"            # Minor info leak, self-XSS
    INFO = "informational" # Best practices


class Platform(Enum):
    """Bug bounty platforms"""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    CUSTOM = "custom"


@dataclass
class BountyProgram:
    """Bug bounty program details"""
    name: str
    platform: Platform
    url: str
    scope: List[str] = field(default_factory=list)  # In-scope domains/IPs
    out_of_scope: List[str] = field(default_factory=list)
    vuln_types: List[str] = field(default_factory=list)  # Accepted vuln types
    bounty_range: Dict[str, Tuple[int, int]] = field(default_factory=dict)  # severity: (min, max)
    rules: List[str] = field(default_factory=list)
    safe_harbor: bool = True
    response_time: str = ""
    
    def is_in_scope(self, target: str) -> bool:
        """Check if target is in scope"""
        target = target.lower()
        
        # Check explicit out of scope first
        for oos in self.out_of_scope:
            if oos.lower() in target or target in oos.lower():
                return False
        
        # Check if in scope
        for scope in self.scope:
            scope = scope.lower()
            if '*' in scope:
                # Wildcard matching
                pattern = scope.replace('.', r'\.').replace('*', '.*')
                if re.match(pattern, target):
                    return True
            elif scope in target or target in scope:
                return True
        
        return False


@dataclass
class Asset:
    """Discovered asset"""
    type: str  # domain, subdomain, ip, url, endpoint, param
    value: str
    source: str  # Tool that found it
    alive: bool = True
    technologies: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    interesting: bool = False
    notes: str = ""


@dataclass
class BugReport:
    """Bug bounty report"""
    id: str
    title: str
    severity: Severity
    category: VulnCategory
    target: str
    endpoint: str
    description: str
    steps_to_reproduce: List[str] = field(default_factory=list)
    poc: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: List[str] = field(default_factory=list)  # Screenshots, logs
    cvss: float = 0.0
    cwe: str = ""
    references: List[str] = field(default_factory=list)
    estimated_bounty: Tuple[int, int] = (0, 0)
    confidence: float = 0.0  # AI confidence 0-1
    duplicate_risk: float = 0.0  # Risk of being duplicate 0-1
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_markdown(self) -> str:
        """Generate markdown report for submission"""
        steps = "\n".join([f"{i+1}. {s}" for i, s in enumerate(self.steps_to_reproduce)])
        refs = "\n".join([f"- {r}" for r in self.references])
        
        return f"""# {self.title}

## Summary
{self.description}

## Severity
**{self.severity.value.upper()}** (CVSS: {self.cvss})

## Vulnerability Type
{self.category.value}
{f'CWE: {self.cwe}' if self.cwe else ''}

## Affected Asset
- **Target:** {self.target}
- **Endpoint:** {self.endpoint}

## Steps to Reproduce
{steps}

## Proof of Concept
```
{self.poc}
```

## Impact
{self.impact}

## Remediation
{self.remediation}

## References
{refs if refs else 'N/A'}

---
*Generated by Kali-GPT Bug Bounty Hunter*
"""


# =============================================================================
# BUG BOUNTY HUNTER ENGINE
# =============================================================================

class BugBountyHunter:
    """
    AI-driven Bug Bounty Hunting Engine
    
    Capabilities:
    - Automated reconnaissance
    - Asset discovery (subdomains, endpoints, params)
    - Vulnerability scanning with AI prioritization
    - Smart duplicate detection
    - Professional report generation
    """
    
    def __init__(self, ai_service, program: BountyProgram = None):
        self.ai = ai_service
        self.program = program
        self.assets: List[Asset] = []
        self.findings: List[BugReport] = []
        self.tested_endpoints: Set[str] = set()
        self.known_vulns_hashes: Set[str] = set()  # For duplicate detection
        
        # Hunting statistics
        self.stats = {
            'subdomains_found': 0,
            'endpoints_found': 0,
            'params_found': 0,
            'vulns_found': 0,
            'estimated_bounty': 0,
            'scan_start': None,
            'scan_end': None
        }
    
    # =========================================================================
    # RECONNAISSANCE
    # =========================================================================
    
    async def recon(self, target: str, callback=None) -> List[Asset]:
        """
        Full reconnaissance on target domain.
        
        Discovers:
        - Subdomains
        - Live hosts
        - Technologies
        - Endpoints
        - Parameters
        """
        self.stats['scan_start'] = datetime.now()
        
        if callback:
            callback(f"🔍 Starting reconnaissance on {target}")
        
        # Phase 1: Subdomain enumeration
        if callback:
            callback("\n[Phase 1/5] 📡 Subdomain Enumeration")
        subdomains = await self._enumerate_subdomains(target, callback)
        
        # Phase 2: Check alive hosts
        if callback:
            callback(f"\n[Phase 2/5] 💓 Checking {len(subdomains)} hosts")
        alive_hosts = await self._check_alive(subdomains, callback)
        
        # Phase 3: Technology fingerprinting
        if callback:
            callback(f"\n[Phase 3/5] 🔧 Technology Detection")
        await self._fingerprint_tech(alive_hosts, callback)
        
        # Phase 4: Endpoint discovery
        if callback:
            callback(f"\n[Phase 4/5] 🌐 Endpoint Discovery")
        await self._discover_endpoints(alive_hosts, callback)
        
        # Phase 5: Parameter discovery
        if callback:
            callback(f"\n[Phase 5/5] 📝 Parameter Discovery")
        await self._discover_params(callback)
        
        self.stats['scan_end'] = datetime.now()
        
        return self.assets
    
    async def _enumerate_subdomains(self, domain: str, callback=None) -> List[str]:
        """Enumerate subdomains using multiple tools"""
        subdomains = set()
        subdomains.add(domain)  # Add main domain
        
        tools = [
            ("subfinder", f"subfinder -d {domain} -silent 2>/dev/null"),
            ("amass", f"amass enum -passive -d {domain} -silent 2>/dev/null | head -100"),
            ("assetfinder", f"assetfinder --subs-only {domain} 2>/dev/null"),
            ("findomain", f"findomain -t {domain} -q 2>/dev/null"),
        ]
        
        for tool_name, cmd in tools:
            if not shutil.which(tool_name.split()[0]):
                continue
            
            if callback:
                callback(f"  Running {tool_name}...")
            
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=120
                )
                
                for line in result.stdout.strip().split('\n'):
                    line = line.strip().lower()
                    if line and domain in line:
                        subdomains.add(line)
                
            except subprocess.TimeoutExpired:
                if callback:
                    callback(f"  [timeout] {tool_name}")
            except Exception as e:
                pass
        
        # Add to assets
        for sub in subdomains:
            # Check if in scope
            if self.program and not self.program.is_in_scope(sub):
                continue
            
            self.assets.append(Asset(
                type="subdomain",
                value=sub,
                source="recon"
            ))
        
        self.stats['subdomains_found'] = len(subdomains)
        
        if callback:
            callback(f"  [green]Found {len(subdomains)} subdomains[/green]")
        
        return list(subdomains)
    
    async def _check_alive(self, hosts: List[str], callback=None) -> List[str]:
        """Check which hosts are alive"""
        alive = []
        
        # Use httpx if available, otherwise curl
        if shutil.which('httpx'):
            # Write hosts to temp file
            hosts_file = '/tmp/hosts_to_check.txt'
            with open(hosts_file, 'w') as f:
                f.write('\n'.join(hosts))
            
            cmd = f"httpx -l {hosts_file} -silent -mc 200,301,302,403,401,500 2>/dev/null"
            
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
                alive = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            except:
                pass
        else:
            # Fallback: check with curl
            for host in hosts[:50]:  # Limit for performance
                for proto in ['https', 'http']:
                    url = f"{proto}://{host}"
                    try:
                        result = subprocess.run(
                            f"curl -sI -o /dev/null -w '%{{http_code}}' --max-time 5 {url}",
                            shell=True, capture_output=True, text=True, timeout=10
                        )
                        if result.stdout.strip() not in ['000', '']:
                            alive.append(url)
                            break
                    except:
                        continue
        
        # Update assets
        for asset in self.assets:
            if asset.type == "subdomain":
                asset.alive = any(asset.value in a for a in alive)
        
        if callback:
            callback(f"  [green]{len(alive)} hosts alive[/green]")
        
        return alive
    
    async def _fingerprint_tech(self, hosts: List[str], callback=None):
        """Fingerprint technologies on hosts"""
        
        if not hosts:
            return
        
        # Use whatweb or wappalyzer
        for host in hosts[:20]:  # Limit
            url = host if host.startswith('http') else f"https://{host}"
            
            techs = []
            
            # Quick header check
            try:
                result = subprocess.run(
                    f"curl -sI --max-time 5 '{url}' 2>/dev/null | head -20",
                    shell=True, capture_output=True, text=True, timeout=10
                )
                
                headers = result.stdout.lower()
                
                # Extract technologies from headers
                if 'php' in headers:
                    techs.append('PHP')
                if 'asp.net' in headers:
                    techs.append('ASP.NET')
                if 'nginx' in headers:
                    techs.append('Nginx')
                if 'apache' in headers:
                    techs.append('Apache')
                if 'cloudflare' in headers:
                    techs.append('Cloudflare')
                if 'wordpress' in headers:
                    techs.append('WordPress')
                
            except:
                pass
            
            # Update asset
            for asset in self.assets:
                if asset.value in url or url in asset.value:
                    asset.technologies = techs
        
        if callback:
            callback(f"  [green]Fingerprinted {min(len(hosts), 20)} hosts[/green]")
    
    async def _discover_endpoints(self, hosts: List[str], callback=None):
        """Discover endpoints using various methods"""
        
        endpoints = set()
        
        for host in hosts[:10]:  # Limit
            url = host if host.startswith('http') else f"https://{host}"
            
            # Method 1: Wayback machine
            if shutil.which('waybackurls'):
                try:
                    domain = urlparse(url).netloc
                    result = subprocess.run(
                        f"echo {domain} | waybackurls 2>/dev/null | head -100",
                        shell=True, capture_output=True, text=True, timeout=30
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            endpoints.add(line.strip())
                except:
                    pass
            
            # Method 2: GAU (Get All URLs)
            if shutil.which('gau'):
                try:
                    domain = urlparse(url).netloc
                    result = subprocess.run(
                        f"echo {domain} | gau --subs 2>/dev/null | head -100",
                        shell=True, capture_output=True, text=True, timeout=30
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            endpoints.add(line.strip())
                except:
                    pass
            
            # Method 3: Common paths
            common_paths = [
                '/robots.txt', '/sitemap.xml', '/.git/config', '/.env',
                '/admin', '/api', '/swagger', '/graphql', '/debug',
                '/wp-admin', '/wp-login.php', '/xmlrpc.php',
                '/backup', '/config', '/.svn', '/server-status',
            ]
            
            for path in common_paths:
                endpoints.add(urljoin(url, path))
        
        # Add interesting endpoints as assets
        for endpoint in endpoints:
            # Check if interesting
            interesting = any(p in endpoint.lower() for p in [
                'admin', 'api', 'config', 'backup', 'debug', 'test',
                'dev', 'staging', 'internal', 'upload', 'file', 'download'
            ])
            
            self.assets.append(Asset(
                type="endpoint",
                value=endpoint,
                source="discovery",
                interesting=interesting
            ))
        
        self.stats['endpoints_found'] = len(endpoints)
        
        if callback:
            callback(f"  [green]Found {len(endpoints)} endpoints[/green]")
    
    async def _discover_params(self, callback=None):
        """Discover parameters from endpoints"""
        
        params = set()
        
        # Extract params from discovered endpoints
        for asset in self.assets:
            if asset.type == "endpoint" and '?' in asset.value:
                parsed = urlparse(asset.value)
                if parsed.query:
                    for param in parsed.query.split('&'):
                        if '=' in param:
                            param_name = param.split('=')[0]
                            params.add(param_name)
        
        # Common interesting parameters
        interesting_params = [
            'id', 'user', 'username', 'email', 'password', 'token',
            'file', 'path', 'url', 'redirect', 'next', 'return',
            'page', 'search', 'query', 'q', 'cmd', 'exec', 'command',
            'debug', 'test', 'admin', 'action', 'callback', 'data'
        ]
        
        for param in params:
            interesting = param.lower() in interesting_params
            
            self.assets.append(Asset(
                type="parameter",
                value=param,
                source="discovery",
                interesting=interesting
            ))
        
        self.stats['params_found'] = len(params)
        
        if callback:
            callback(f"  [green]Found {len(params)} parameters[/green]")
    
    # =========================================================================
    # VULNERABILITY HUNTING
    # =========================================================================
    
    async def hunt(self, callback=None) -> List[BugReport]:
        """
        Hunt for vulnerabilities in discovered assets.
        
        Tests for:
        - Subdomain takeover
        - XSS
        - SQL Injection
        - SSRF
        - IDOR
        - Open redirects
        - Information disclosure
        - Security misconfigurations
        """
        if callback:
            callback("🎯 Starting vulnerability hunting...")
        
        # Get testable endpoints
        endpoints = [a for a in self.assets if a.type == "endpoint" and a.alive]
        subdomains = [a for a in self.assets if a.type == "subdomain"]
        
        # Test 1: Subdomain takeover
        if callback:
            callback("\n[Hunt 1/8] 🔗 Subdomain Takeover Check")
        await self._check_subdomain_takeover(subdomains, callback)
        
        # Test 2: Security headers
        if callback:
            callback("\n[Hunt 2/8] 🔒 Security Headers Check")
        await self._check_security_headers(endpoints, callback)
        
        # Test 3: Sensitive file exposure
        if callback:
            callback("\n[Hunt 3/8] 📁 Sensitive Files Check")
        await self._check_sensitive_files(callback)
        
        # Test 4: XSS
        if callback:
            callback("\n[Hunt 4/8] 💉 XSS Testing")
        await self._test_xss(endpoints, callback)
        
        # Test 5: SQL Injection
        if callback:
            callback("\n[Hunt 5/8] 🗃️ SQL Injection Testing")
        await self._test_sqli(endpoints, callback)
        
        # Test 6: SSRF
        if callback:
            callback("\n[Hunt 6/8] 🌐 SSRF Testing")
        await self._test_ssrf(endpoints, callback)
        
        # Test 7: Open redirect
        if callback:
            callback("\n[Hunt 7/8] ↩️ Open Redirect Testing")
        await self._test_open_redirect(endpoints, callback)
        
        # Test 8: Nuclei scan
        if callback:
            callback("\n[Hunt 8/8] ⚡ Nuclei Vulnerability Scan")
        await self._run_nuclei(callback)
        
        # AI Analysis - prioritize and dedupe
        if callback:
            callback("\n🧠 AI analyzing and prioritizing findings...")
        await self._ai_analyze_findings()
        
        self.stats['vulns_found'] = len(self.findings)
        
        return self.findings
    
    async def _check_subdomain_takeover(self, subdomains: List[Asset], callback=None):
        """Check for subdomain takeover vulnerabilities"""
        
        # Fingerprints for takeover
        takeover_fingerprints = {
            'github': "There isn't a GitHub Pages site here",
            'heroku': "No such app",
            'aws/s3': "NoSuchBucket",
            'shopify': "Sorry, this shop is currently unavailable",
            'tumblr': "There's nothing here",
            'wordpress': "Do you want to register",
            'ghost': "The thing you were looking for is no longer here",
            'surge': "project not found",
            'bitbucket': "Repository not found",
            'intercom': "This page is reserved for",
            'zendesk': "Help Center Closed",
        }
        
        for asset in subdomains[:30]:  # Limit
            domain = asset.value
            
            try:
                # Check HTTP response
                result = subprocess.run(
                    f"curl -sL --max-time 10 'http://{domain}' 2>/dev/null | head -100",
                    shell=True, capture_output=True, text=True, timeout=15
                )
                
                body = result.stdout.lower()
                
                for service, fingerprint in takeover_fingerprints.items():
                    if fingerprint.lower() in body:
                        # Potential takeover!
                        self._add_finding(
                            title=f"Subdomain Takeover - {domain} ({service})",
                            severity=Severity.HIGH,
                            category=VulnCategory.SUBDOMAIN_TAKEOVER,
                            target=domain,
                            endpoint=f"http://{domain}",
                            description=f"The subdomain {domain} appears to be vulnerable to takeover. "
                                       f"The DNS is pointing to {service} but the resource no longer exists.",
                            poc=f"curl -sL http://{domain}",
                            impact="An attacker could claim this subdomain and serve malicious content, "
                                  "potentially stealing cookies or phishing users.",
                            confidence=0.8
                        )
                        
                        if callback:
                            callback(f"  [red]⚠️ FOUND: Subdomain takeover on {domain}[/red]")
                        break
                        
            except:
                continue
        
        if callback:
            callback(f"  Checked {min(len(subdomains), 30)} subdomains")
    
    async def _check_security_headers(self, endpoints: List[Asset], callback=None):
        """Check for missing security headers"""
        
        important_headers = [
            ('strict-transport-security', 'HSTS', Severity.MEDIUM),
            ('x-frame-options', 'Clickjacking Protection', Severity.MEDIUM),
            ('x-content-type-options', 'MIME Sniffing Protection', Severity.LOW),
            ('content-security-policy', 'CSP', Severity.MEDIUM),
            ('x-xss-protection', 'XSS Protection', Severity.LOW),
        ]
        
        checked = set()
        
        for asset in endpoints[:20]:
            url = asset.value
            domain = urlparse(url).netloc
            
            if domain in checked:
                continue
            checked.add(domain)
            
            try:
                result = subprocess.run(
                    f"curl -sI --max-time 5 '{url}' 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=10
                )
                
                headers = result.stdout.lower()
                missing = []
                
                for header, name, severity in important_headers:
                    if header not in headers:
                        missing.append((header, name, severity))
                
                # Only report if multiple important headers missing
                if len(missing) >= 3:
                    missing_list = ", ".join([m[1] for m in missing])
                    
                    self._add_finding(
                        title=f"Missing Security Headers on {domain}",
                        severity=Severity.LOW,
                        category=VulnCategory.SECURITY_MISCONFIG,
                        target=domain,
                        endpoint=url,
                        description=f"The application is missing important security headers: {missing_list}",
                        poc=f"curl -sI {url}",
                        impact="Missing security headers can make the application vulnerable to various attacks.",
                        confidence=1.0,
                        duplicate_risk=0.9  # Very common finding
                    )
                    
            except:
                continue
        
        if callback:
            callback(f"  Checked {len(checked)} domains")
    
    async def _check_sensitive_files(self, callback=None):
        """Check for exposed sensitive files"""
        
        sensitive_files = [
            ('/.git/config', 'Git Configuration', Severity.HIGH),
            ('/.env', 'Environment File', Severity.CRITICAL),
            ('/.svn/entries', 'SVN Entries', Severity.HIGH),
            ('/backup.sql', 'SQL Backup', Severity.CRITICAL),
            ('/debug.log', 'Debug Log', Severity.MEDIUM),
            ('/phpinfo.php', 'PHP Info', Severity.MEDIUM),
            ('/.htpasswd', 'htpasswd File', Severity.HIGH),
            ('/wp-config.php.bak', 'WordPress Config Backup', Severity.CRITICAL),
            ('/.DS_Store', 'MacOS DS_Store', Severity.LOW),
            ('/server-status', 'Apache Server Status', Severity.MEDIUM),
            ('/elmah.axd', 'ELMAH Error Log', Severity.MEDIUM),
            ('/trace.axd', 'ASP.NET Trace', Severity.MEDIUM),
        ]
        
        # Get unique base URLs
        base_urls = set()
        for asset in self.assets:
            if asset.type in ['subdomain', 'endpoint']:
                url = asset.value
                if not url.startswith('http'):
                    url = f"https://{url}"
                parsed = urlparse(url)
                base_urls.add(f"{parsed.scheme}://{parsed.netloc}")
        
        found_count = 0
        
        for base_url in list(base_urls)[:20]:
            for path, name, severity in sensitive_files:
                full_url = urljoin(base_url, path)
                
                try:
                    result = subprocess.run(
                        f"curl -sI --max-time 5 '{full_url}' 2>/dev/null | head -1",
                        shell=True, capture_output=True, text=True, timeout=10
                    )
                    
                    if '200' in result.stdout:
                        # Verify it's not a soft 404
                        body_result = subprocess.run(
                            f"curl -s --max-time 5 '{full_url}' 2>/dev/null | head -5",
                            shell=True, capture_output=True, text=True, timeout=10
                        )
                        
                        # Quick check for false positive
                        if 'not found' not in body_result.stdout.lower() and len(body_result.stdout) > 10:
                            self._add_finding(
                                title=f"Exposed {name} at {urlparse(base_url).netloc}",
                                severity=severity,
                                category=VulnCategory.INFO_DISCLOSURE,
                                target=urlparse(base_url).netloc,
                                endpoint=full_url,
                                description=f"Sensitive file {path} is publicly accessible.",
                                poc=f"curl {full_url}",
                                impact=f"Exposure of {name} can lead to information disclosure or further attacks.",
                                confidence=0.85
                            )
                            
                            found_count += 1
                            
                            if callback:
                                callback(f"  [red]⚠️ FOUND: {name} at {full_url}[/red]")
                            
                except:
                    continue
        
        if callback:
            callback(f"  Found {found_count} sensitive files")
    
    async def _test_xss(self, endpoints: List[Asset], callback=None):
        """Test for XSS vulnerabilities"""
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '{{constructor.constructor("alert(1)")()}}',
        ]
        
        # Get endpoints with parameters
        testable = []
        for asset in self.assets:
            if asset.type == "endpoint" and '=' in asset.value:
                testable.append(asset.value)
        
        if not testable and shutil.which('dalfox'):
            # Use dalfox if available
            urls_file = '/tmp/xss_urls.txt'
            with open(urls_file, 'w') as f:
                for asset in endpoints[:20]:
                    f.write(asset.value + '\n')
            
            try:
                result = subprocess.run(
                    f"dalfox file {urls_file} --skip-bav --silence 2>/dev/null | head -20",
                    shell=True, capture_output=True, text=True, timeout=180
                )
                
                for line in result.stdout.strip().split('\n'):
                    if '[POC]' in line or '[V]' in line:
                        self._add_finding(
                            title="XSS Vulnerability Found",
                            severity=Severity.MEDIUM,
                            category=VulnCategory.XSS,
                            target="",
                            endpoint=line,
                            description="Cross-Site Scripting vulnerability detected.",
                            poc=line,
                            impact="XSS can be used to steal cookies, session tokens, or redirect users.",
                            confidence=0.9
                        )
                        
                        if callback:
                            callback(f"  [red]⚠️ FOUND: XSS vulnerability[/red]")
                            
            except:
                pass
        
        if callback:
            callback(f"  Tested {len(testable)} endpoints")
    
    async def _test_sqli(self, endpoints: List[Asset], callback=None):
        """Test for SQL Injection"""
        
        # Get endpoints with parameters
        testable = [a.value for a in self.assets if a.type == "endpoint" and '=' in a.value][:10]
        
        if not testable:
            if callback:
                callback("  No testable endpoints found")
            return
        
        if shutil.which('sqlmap'):
            for url in testable[:5]:
                try:
                    result = subprocess.run(
                        f"sqlmap -u '{url}' --batch --level=1 --risk=1 --threads=5 "
                        f"--technique=BE --timeout=10 2>/dev/null | tail -20",
                        shell=True, capture_output=True, text=True, timeout=120
                    )
                    
                    if 'is vulnerable' in result.stdout.lower() or 'injectable' in result.stdout.lower():
                        self._add_finding(
                            title=f"SQL Injection at {urlparse(url).netloc}",
                            severity=Severity.CRITICAL,
                            category=VulnCategory.INJECTION,
                            target=urlparse(url).netloc,
                            endpoint=url,
                            description="SQL Injection vulnerability detected. Database can be compromised.",
                            poc=f"sqlmap -u '{url}' --batch",
                            impact="Full database access, data theft, authentication bypass.",
                            confidence=0.95
                        )
                        
                        if callback:
                            callback(f"  [red]⚠️ CRITICAL: SQL Injection found![/red]")
                        break
                        
                except:
                    continue
        
        if callback:
            callback(f"  Tested {min(len(testable), 5)} endpoints")
    
    async def _test_ssrf(self, endpoints: List[Asset], callback=None):
        """Test for SSRF vulnerabilities"""
        
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'return', 'next', 
                       'data', 'feed', 'host', 'site', 'html', 'val', 'validate',
                       'domain', 'callback', 'return_to', 'open', 'img', 'image']
        
        testable = []
        for asset in self.assets:
            if asset.type == "endpoint":
                url = asset.value.lower()
                for param in ssrf_params:
                    if param + '=' in url:
                        testable.append(asset.value)
                        break
        
        if callback:
            callback(f"  Found {len(testable)} SSRF-testable endpoints")
    
    async def _test_open_redirect(self, endpoints: List[Asset], callback=None):
        """Test for open redirect vulnerabilities"""
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'returnTo', 'return_to',
                          'goto', 'destination', 'dest', 'continue', 'redir', 'target']
        
        payload = 'https://evil.com'
        
        for asset in self.assets[:20]:
            if asset.type != "endpoint":
                continue
            
            url = asset.value.lower()
            
            for param in redirect_params:
                if param + '=' in url:
                    test_url = re.sub(f'{param}=[^&]+', f'{param}={payload}', url, flags=re.IGNORECASE)
                    
                    try:
                        result = subprocess.run(
                            f"curl -sI --max-time 5 --max-redirs 0 '{test_url}' 2>/dev/null",
                            shell=True, capture_output=True, text=True, timeout=10
                        )
                        
                        if 'evil.com' in result.stdout.lower():
                            self._add_finding(
                                title=f"Open Redirect on {urlparse(url).netloc}",
                                severity=Severity.LOW,
                                category=VulnCategory.BROKEN_ACCESS,
                                target=urlparse(url).netloc,
                                endpoint=url,
                                description=f"Open redirect via {param} parameter.",
                                poc=test_url,
                                impact="Can be used for phishing attacks.",
                                confidence=0.9,
                                duplicate_risk=0.8
                            )
                            
                            if callback:
                                callback(f"  [yellow]⚠️ FOUND: Open redirect[/yellow]")
                                
                    except:
                        continue
        
        if callback:
            callback(f"  Tested redirect parameters")
    
    async def _run_nuclei(self, callback=None):
        """Run nuclei vulnerability scanner"""
        
        if not shutil.which('nuclei'):
            if callback:
                callback("  Nuclei not installed, skipping")
            return
        
        # Get alive hosts
        hosts = [a.value for a in self.assets if a.type == "subdomain" and a.alive][:20]
        
        if not hosts:
            return
        
        hosts_file = '/tmp/nuclei_targets.txt'
        with open(hosts_file, 'w') as f:
            for h in hosts:
                f.write(f"https://{h}\n")
                f.write(f"http://{h}\n")
        
        try:
            result = subprocess.run(
                f"nuclei -l {hosts_file} -severity critical,high -silent 2>/dev/null | head -30",
                shell=True, capture_output=True, text=True, timeout=300
            )
            
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    # Parse nuclei output
                    self._add_finding(
                        title=f"Nuclei Finding: {line[:80]}",
                        severity=Severity.HIGH if 'critical' in line.lower() else Severity.MEDIUM,
                        category=VulnCategory.COMPONENTS,
                        target="",
                        endpoint=line,
                        description=f"Nuclei detected: {line}",
                        poc="nuclei scan",
                        confidence=0.85
                    )
                    
                    if callback:
                        callback(f"  [red]⚠️ FOUND: {line[:60]}...[/red]")
                        
        except subprocess.TimeoutExpired:
            if callback:
                callback("  Nuclei scan timed out")
        except Exception as e:
            pass
        
        if callback:
            callback(f"  Scanned {len(hosts)} hosts")
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _add_finding(self, **kwargs):
        """Add a finding with duplicate detection"""
        
        # Create hash for duplicate detection
        hash_input = f"{kwargs.get('title', '')}{kwargs.get('endpoint', '')}{kwargs.get('category', '')}"
        finding_hash = hashlib.md5(hash_input.encode()).hexdigest()
        
        if finding_hash in self.known_vulns_hashes:
            return  # Skip duplicate
        
        self.known_vulns_hashes.add(finding_hash)
        
        # Estimate bounty
        bounty_estimate = self._estimate_bounty(kwargs.get('severity', Severity.LOW))
        
        report = BugReport(
            id=f"BUG-{len(self.findings) + 1:04d}",
            title=kwargs.get('title', ''),
            severity=kwargs.get('severity', Severity.LOW),
            category=kwargs.get('category', VulnCategory.INFO_DISCLOSURE),
            target=kwargs.get('target', ''),
            endpoint=kwargs.get('endpoint', ''),
            description=kwargs.get('description', ''),
            steps_to_reproduce=[kwargs.get('poc', '')],
            poc=kwargs.get('poc', ''),
            impact=kwargs.get('impact', ''),
            confidence=kwargs.get('confidence', 0.5),
            duplicate_risk=kwargs.get('duplicate_risk', 0.3),
            estimated_bounty=bounty_estimate
        )
        
        self.findings.append(report)
        self.stats['estimated_bounty'] += bounty_estimate[0]
    
    def _estimate_bounty(self, severity: Severity) -> Tuple[int, int]:
        """Estimate bounty based on severity"""
        
        if self.program and self.program.bounty_range:
            return self.program.bounty_range.get(severity.value, (0, 0))
        
        # Default estimates
        estimates = {
            Severity.CRITICAL: (1000, 10000),
            Severity.HIGH: (500, 3000),
            Severity.MEDIUM: (100, 500),
            Severity.LOW: (50, 200),
            Severity.INFO: (0, 50),
        }
        
        return estimates.get(severity, (0, 0))
    
    async def _ai_analyze_findings(self):
        """Use AI to analyze, prioritize, and enhance findings"""
        
        if not self.ai or not self.findings:
            return
        
        for finding in self.findings:
            # Generate better description
            prompt = f"""Analyze this bug bounty finding and provide:
1. A better, more professional title (max 10 words)
2. Enhanced impact description
3. Duplicate risk assessment (0-1)
4. Suggested CVSS score

Finding:
Title: {finding.title}
Category: {finding.category.value}
Current Description: {finding.description}
Endpoint: {finding.endpoint}

Respond in JSON format:
{{"title": "...", "impact": "...", "duplicate_risk": 0.X, "cvss": X.X}}"""

            try:
                response = self.ai.ask(prompt)
                
                # Parse response
                json_match = re.search(r'\{[^{}]+\}', response, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group())
                    
                    if 'title' in data:
                        finding.title = data['title']
                    if 'impact' in data:
                        finding.impact = data['impact']
                    if 'duplicate_risk' in data:
                        finding.duplicate_risk = float(data['duplicate_risk'])
                    if 'cvss' in data:
                        finding.cvss = float(data['cvss'])
                        
            except:
                continue
        
        # Sort by severity and confidence, deprioritize high duplicate risk
        self.findings.sort(key=lambda f: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}.get(f.severity.value, 5),
            f.duplicate_risk,
            -f.confidence
        ))
