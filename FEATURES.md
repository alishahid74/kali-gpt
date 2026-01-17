# Kali GPT Enhanced - Features Documentation

## Version 2.0 - Future Enhancements Implementation

This document details all the enhanced features implemented in Kali GPT Version 2.0.

---

## 🚀 New Features Overview

### 1. Metasploit Framework Integration

Full integration with Metasploit Framework for automated exploitation and payload generation.

#### Features:
- **Exploit Search**: Search the Metasploit database for exploits by CVE, platform, or keyword
- **Payload Generation**: Generate payloads using msfvenom with multiple formats
- **Auxiliary Modules**: Search and utilize Metasploit auxiliary modules
- **Handler Commands**: Automatically generate listener commands for reverse shells
- **Exploit Suggestions**: Get exploit recommendations based on target information

#### Usage:
```python
# Access via main menu option 13
# Or programmatically:
from kali_gpt.integrations.metasploit import MetasploitIntegration

msf = MetasploitIntegration(config_manager)

# Search for exploits
exploits = msf.search_exploits("SMB")

# Generate payload
payload = msf.generate_payload(
    "windows/meterpreter/reverse_tcp",
    lhost="192.168.1.10",
    lport="4444",
    format="exe"
)

# List available payloads
payloads = msf.list_payloads(platform="windows")
```

#### Example Workflow:
1. Select option 13 from main menu
2. Choose "Search Exploits"
3. Enter CVE or keyword (e.g., "eternal blue")
4. View matching exploits
5. Generate payload for selected exploit
6. Get listener command to catch connections

---

### 2. Custom Tool Profiles

Create and manage custom security testing profiles tailored to your specific needs.

#### Built-in Profiles:
- **General Pentesting**: All-purpose testing
- **Reconnaissance**: Information gathering focused
- **Exploitation**: Vulnerability exploitation
- **Web Application**: Web app security testing
- **Wireless Security**: Wireless network testing
- **Post-Exploitation**: Privilege escalation and persistence
- **Digital Forensics**: Evidence collection and analysis

#### Creating Custom Profiles:
```python
from kali_gpt.modules.profile_manager import ProfileManager

profiles = ProfileManager(config_manager)

# Add custom profile
profiles.add_profile(
    profile_id="custom_api_testing",
    name="API Security Testing",
    description="Specialized API penetration testing",
    prompt="You are an API security expert...",
    tools=["burp", "postman", "sqlmap", "jwt_tool"],
    color="magenta"
)

# Update existing profile
profiles.update_profile(
    "custom_api_testing",
    description="Advanced API security testing with OAuth focus"
)
```

#### Profile Storage:
- Default profiles: Built into the application
- Custom profiles: `~/.kali-gpt/profiles/custom_profiles.json`
- Config-based profiles: Stored in main config

---

### 3. Report Generation

Generate professional penetration testing reports in multiple formats.

#### Supported Formats:
- **HTML**: Rich, styled reports with interactive elements
- **Markdown**: Plain text reports compatible with documentation systems
- **JSON**: Structured data for integration with other tools

#### Features:
- Automatic statistics (total interactions, commands executed, etc.)
- Interaction timeline with timestamps
- Command execution history
- AI analysis inclusion
- Customizable report sections
- Date range filtering

#### Usage:
```python
from kali_gpt.modules.report_generator import ReportGenerator

reports = ReportGenerator(config_manager, history_manager)

# Generate HTML report
html_file = reports.generate_html_report(
    title="Q4 2024 Penetration Test",
    start_date="2024-10-01",
    end_date="2024-12-31",
    include_commands=True
)

# Generate Markdown report
md_file = reports.generate_markdown_report(
    title="Security Assessment Report"
)

# Generate JSON report
json_file = reports.generate_json_report()
```

#### Report Sections:
- Executive Summary
- Statistics Dashboard
- Detailed Interactions
- Command Execution Log
- AI Analysis Results
- Findings Summary

Reports are saved to: `~/.kali-gpt/reports/`

---

### 4. Multi-Target Management

Manage multiple targets with findings, notes, and metadata.

#### Features:
- **Target Tracking**: Store host, ports, description, tags
- **Findings Management**: Add security findings to targets
- **Notes**: Attach notes to targets
- **Status Tracking**: Track target testing status
- **Search & Filter**: Find targets by host, tag, or status
- **Import/Export**: Share target lists

#### Usage:
```python
from kali_gpt.modules.target_manager import TargetManager

targets = TargetManager(config_manager)

# Add target
target_id = targets.add_target(
    host="192.168.1.100",
    ports="80,443,8080",
    description="Production web server",
    tags=["web", "production", "high-priority"]
)

# Set active target
targets.set_active_target(target_id)

# Add finding
targets.add_finding(
    target_id,
    title="SQL Injection in login form",
    description="Union-based SQL injection vulnerability",
    severity="high",
    cvss="8.2"
)

# Add note
targets.add_note(target_id, "Scheduled for retest on 2024-12-15")

# Search targets
results = targets.search_targets("production")
```

#### Target Data Structure:
```json
{
  "id": "abc123",
  "host": "192.168.1.100",
  "ports": "80,443",
  "description": "Web server",
  "tags": ["web"],
  "status": "in_progress",
  "created": "2024-01-01T12:00:00",
  "findings": [],
  "notes": []
}
```

---

### 5. Plugin System

Extensible plugin architecture for custom functionality.

#### Plugin Capabilities:
- **Command Hooks**: Intercept and modify commands before execution
- **Output Analysis**: Add custom analysis to command outputs
- **Menu Items**: Add custom menu options
- **Custom Commands**: Register new commands
- **Event Handlers**: React to scans, findings, reports
- **Configuration**: Plugin-specific settings

#### Creating a Plugin:
```python
from kali_gpt.plugins.plugin_base import KaliGPTPlugin

class CustomPlugin(KaliGPTPlugin):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"
        self.version = "1.0.0"
        self.description = "Does amazing things"
        self.author = "Your Name"

    def on_init(self, app):
        print(f"{self.name} initialized!")
        return True

    def on_command_execute(self, command, context):
        # Log all nmap commands
        if "nmap" in command:
            print(f"Nmap scan detected: {command}")
        return command

    def on_output_analysis(self, command, output, context):
        # Custom analysis
        if "nmap" in command and "80/tcp" in output:
            return {
                "finding": "HTTP server detected",
                "recommendation": "Run web vulnerability scan"
            }
        return None

    def get_menu_items(self):
        return [
            {
                "label": "Run Custom Scan",
                "callback": self.custom_scan
            }
        ]

    def custom_scan(self):
        print("Running custom scan...")
```

#### Plugin Management:
```bash
# Via menu (option 15)
# Or programmatically:

plugins.load_plugin_from_file("custom_plugin", "path/to/plugin.py")
plugins.enable_plugin("custom_plugin")
plugins.disable_plugin("custom_plugin")
plugins.reload_plugin("custom_plugin")
```

#### Plugin Hooks:
- `on_init(app)`: Plugin initialization
- `on_command_execute(command, context)`: Before command execution
- `on_output_analysis(command, output, context)`: After command execution
- `on_scan_complete(scan_results)`: After scans complete
- `on_finding_added(target_id, finding)`: When findings are added
- `on_report_generate(report_type, data)`: During report generation

---

### 6. Team Collaboration Features

Share sessions, findings, and coordinate with team members.

#### Features:
- **Session Sharing**: Create shareable penetration testing sessions
- **Session Export/Import**: Share sessions via JSON files
- **Team Members**: Manage team member access and roles
- **Shared Findings**: Collaborate on vulnerability findings
- **Activity Tracking**: Monitor team activity
- **Remote Sync**: Sync with collaboration server (optional)

#### Usage:
```python
from kali_gpt.integrations.collaboration import CollaborationManager

collab = CollaborationManager(config_manager, history_manager)

# Create shareable session
result = collab.create_session_share(
    session_name="Q4 Web App Test",
    description="Testing production web application",
    include_logs=True
)

# Export session
exported_file = collab.export_session(
    session_id="abc123",
    output_file="session_export.json"
)

# Import shared session
session_id = collab.import_session("session_export.json")

# Add team member
collab.add_team_member(
    name="John Doe",
    role="pentester",
    email="john@example.com",
    permissions=["view_logs", "execute_commands", "add_findings"]
)

# Get team activity
activity = collab.get_team_activity()
```

#### Collaboration Server (Optional):
Configure in settings to sync with a central server:
```json
{
  "collaboration": {
    "enabled": true,
    "server_url": "https://collab.example.com",
    "api_key": "your-api-key",
    "share_logs": true
  }
}
```

---

### 7. Automated Vulnerability Scanning

Integrated vulnerability scanning with multiple tools.

#### Supported Scanners:
- **Nmap**: Network and service scanning
- **Nikto**: Web server vulnerability scanning
- **Custom Tools**: Extensible for any scanner

#### Scan Profiles:
- **Quick**: Fast service detection (`-sV -T4`)
- **Full**: Comprehensive scan (`-sV -sC -A -T4 -p-`)
- **Stealth**: Slow, stealthy scan (`-sS -sV -T2`)
- **Vuln**: Vulnerability scripts (`-sV --script vuln`)
- **Aggressive**: Maximum information (`-A -T4`)
- **Comprehensive**: Everything (`-sS -sV -sC -A -O -p-`)

#### Usage:
```python
from kali_gpt.integrations.scanner import ScannerManager

scanner = ScannerManager(config_manager, command_executor)

# Nmap scan
results = scanner.nmap_scan(
    target="192.168.1.0/24",
    scan_type="quick",
    ports="1-1000"
)

# Nikto web scan
web_results = scanner.nikto_scan(
    target="example.com",
    port=443,
    ssl=True
)

# Custom scanner
custom_results = scanner.run_custom_scan(
    tool="sqlmap",
    target="http://example.com",
    options="-u http://example.com/login --forms --batch"
)

# Scan a managed target
target_results = scanner.scan_target(
    target_id="abc123",
    target_manager=target_manager,
    scan_profile="vuln"
)

# Get available scanners
scanners = scanner.get_available_scanners()

# Get scan history
history = scanner.get_scan_history()
```

#### Scan Results:
Results are automatically parsed and can be:
- Analyzed by AI
- Added to target findings
- Included in reports
- Cross-referenced with vulnerability databases

Scans are stored in: `~/.kali-gpt/scans/`

---

### 8. Vulnerability Database Integration

Real-time vulnerability information from multiple sources.

#### Data Sources:
- **NVD** (National Vulnerability Database): Comprehensive CVE database
- **CVE API**: Direct CVE lookups
- **ExploitDB**: Public exploit database

#### Features:
- **CVE Lookup**: Detailed vulnerability information
- **Vulnerability Search**: Find vulnerabilities by keyword
- **Recent Vulnerabilities**: Track newly disclosed vulnerabilities
- **Service Vulnerabilities**: Check known vulnerabilities for services
- **Exploit Availability**: Check if public exploits exist
- **CVSS Scoring**: Get severity ratings
- **Caching**: Local cache for faster lookups

#### Usage:
```python
from kali_gpt.integrations.vulnerability_db import VulnerabilityDatabase

vuln_db = VulnerabilityDatabase(config_manager)

# CVE lookup
cve_data = vuln_db.lookup_cve("CVE-2021-44228")
# Returns: {
#   "id": "CVE-2021-44228",
#   "description": "...",
#   "cvss_v3": {"score": 10.0, "severity": "CRITICAL"},
#   "references": [...],
#   "cwe": [...]
# }

# Search vulnerabilities
results = vuln_db.search_vulnerabilities("Apache", limit=10)

# Recent vulnerabilities
recent = vuln_db.get_recent_vulnerabilities(days=7, limit=20)

# Check service vulnerabilities
vulns = vuln_db.check_service_vulnerabilities("Apache", "2.4.49")

# Check exploit availability
exploit_info = vuln_db.get_exploit_availability("CVE-2021-44228")
# Returns: {
#   "exploits_available": true,
#   "public_exploits": ["https://exploit-db.com/..."],
#   "metasploit_modules": [...]
# }

# Analyze scan results
analysis = vuln_db.analyze_scan_results(scan_results)
# Returns statistics and vulnerability mappings

# Clear cache
vuln_db.clear_cache()
```

#### Rate Limiting:
Built-in rate limiting to respect API quotas:
- Minimum 1 second between requests
- Configurable limits
- Automatic retry logic

#### Caching:
Local cache to reduce API calls:
- Cache location: `~/.kali-gpt/vuln_cache/`
- Default TTL: 24 hours (configurable)
- Automatic cache expiration

---

## 📁 File Structure

```
kali-gpt/
├── kali_gpt/                      # Modular codebase
│   ├── __init__.py
│   ├── core/                      # Core application
│   │   ├── __init__.py
│   │   ├── config.py              # Configuration management
│   │   └── app.py                 # Main application (if refactored)
│   │
│   ├── modules/                   # Feature modules
│   │   ├── __init__.py
│   │   ├── ai_service.py          # AI interactions
│   │   ├── command_executor.py    # Command execution
│   │   ├── profile_manager.py     # Security profiles
│   │   ├── history_manager.py     # History & logging
│   │   ├── report_generator.py    # Report generation
│   │   └── target_manager.py      # Target management
│   │
│   ├── integrations/              # External tool integrations
│   │   ├── __init__.py
│   │   ├── metasploit.py          # Metasploit Framework
│   │   ├── vulnerability_db.py    # Vulnerability databases
│   │   ├── scanner.py             # Vulnerability scanners
│   │   └── collaboration.py       # Team collaboration
│   │
│   ├── plugins/                   # Plugin system
│   │   ├── __init__.py
│   │   ├── plugin_base.py         # Plugin base class
│   │   └── plugin_manager.py      # Plugin manager
│   │
│   ├── utils/                     # Utility functions
│   │   ├── __init__.py
│   │   ├── logger.py              # Logging utilities
│   │   ├── validators.py          # Input validation
│   │   └── formatters.py          # Output formatting
│   │
│   └── ui/                        # User interface
│       ├── __init__.py
│       ├── menu.py                # Menu displays
│       └── colors.py              # Color schemes
│
├── kali-gpt.py                    # Original simple version
├── kali-gpt-advanced.py           # Original advanced version
├── kali-gpt-enhanced.py           # Enhanced version 2.0
├── requirements.txt               # Python dependencies
├── setup.sh                       # Installation script
├── .env                           # Environment variables
├── README.md                      # Main documentation
├── README_ADVANCED.md             # Advanced features guide
├── QUICK_START.md                 # Quick reference
└── FEATURES.md                    # This file

~/.kali-gpt/                       # User data directory
├── config.json                    # User configuration
├── conversation_history.json      # Chat history
├── interaction_logs.json          # Detailed logs
├── targets.json                   # Target database
├── profiles/                      # Custom profiles
│   └── custom_profiles.json
├── plugins/                       # User plugins
├── reports/                       # Generated reports
├── scans/                         # Scan results
├── vuln_cache/                    # Vulnerability cache
│   └── vuln_cache.json
└── collaboration/                 # Collaboration data
    ├── shared_sessions.json
    ├── team_members.json
    └── sessions/
```

---

## ⚙️ Configuration

### Main Configuration File: `~/.kali-gpt/config.json`

```json
{
  "model": "gpt-4o",
  "temperature": 0.7,
  "max_tokens": 2000,
  "require_confirmation": true,
  "auto_copy": true,
  "save_history": true,
  "max_history": 10,
  "default_timeout": 30,
  "custom_profiles": [],

  "metasploit": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 55553,
    "username": "msf",
    "password": ""
  },

  "vulnerability_db": {
    "enabled": true,
    "auto_update": true,
    "update_interval": 86400,
    "sources": ["nvd", "cve", "exploitdb"]
  },

  "scanner": {
    "enabled": true,
    "default_scanner": "nmap",
    "concurrent_scans": 1
  },

  "collaboration": {
    "enabled": false,
    "server_url": "",
    "api_key": "",
    "share_logs": false
  },

  "plugins": {
    "enabled": true,
    "auto_load": true,
    "plugin_directory": "~/.kali-gpt/plugins"
  },

  "reports": {
    "default_format": "html",
    "output_directory": "~/.kali-gpt/reports",
    "include_screenshots": false,
    "auto_generate": false
  },

  "targets": {
    "save_targets": true,
    "max_targets": 50
  }
}
```

---

## 🔧 Installation

### 1. Install Requirements
```bash
pip install -r requirements.txt
```

### 2. Set Up Environment
```bash
cp config.example.json ~/.kali-gpt/config.json
echo "OPENAI_API_KEY=your-key-here" > .env
```

### 3. Run Enhanced Version
```bash
python3 kali-gpt-enhanced.py
```

Or use the setup script:
```bash
./setup.sh
```

---

## 📚 API Reference

### ConfigManager
```python
config = ConfigManager()
value = config.get("key.nested_key", default_value)
config.set("key.nested_key", new_value)
config.reset_to_defaults()
```

### AIService
```python
ai = AIService(config_manager)
response = ai.ask(prompt, system_prompt=None, include_history=True)
analysis = ai.analyze_output(command, output, context="")
cmd_info = ai.generate_command(task, target_info="")
```

### TargetManager
```python
targets = TargetManager(config_manager)
target_id = targets.add_target(host, ports, description)
targets.set_active_target(target_id)
targets.add_finding(target_id, title, description, severity)
targets.add_note(target_id, note)
```

### MetasploitIntegration
```python
msf = MetasploitIntegration(config_manager)
exploits = msf.search_exploits(query)
payload = msf.generate_payload(type, lhost, lport, format)
payloads = msf.list_payloads(platform)
```

### VulnerabilityDatabase
```python
vuln_db = VulnerabilityDatabase(config_manager)
cve = vuln_db.lookup_cve(cve_id)
results = vuln_db.search_vulnerabilities(keyword, limit)
recent = vuln_db.get_recent_vulnerabilities(days, limit)
```

### ScannerManager
```python
scanner = ScannerManager(config_manager, executor)
results = scanner.nmap_scan(target, scan_type, ports)
web_results = scanner.nikto_scan(target, port, ssl)
custom = scanner.run_custom_scan(tool, target, options)
```

### PluginManager
```python
plugins = PluginManager(config_manager)
plugins.load_plugin_from_file(name, file_path)
plugins.register_plugin(id, instance)
plugins.execute_hook(hook_name, *args, **kwargs)
```

---

## 🎯 Usage Examples

### Complete Penetration Testing Workflow

```python
# 1. Add target
target_id = targets.add_target(
    host="192.168.1.100",
    ports="1-65535",
    description="Production web server"
)

# 2. Run vulnerability scan
scan_results = scanner.nmap_scan("192.168.1.100", "comprehensive")

# 3. Check for vulnerabilities
for host in scan_results['hosts']:
    for port in host['ports']:
        service = port['service']
        version = port['version']

        # Check vulnerability database
        vulns = vuln_db.check_service_vulnerabilities(service, version)

        # Add findings
        for vuln in vulns:
            targets.add_finding(
                target_id,
                title=vuln['id'],
                description=vuln['description'],
                severity=vuln_db.get_severity_rating(vuln['cvss_score'])
            )

# 4. Search for exploits
for finding in target['findings']:
    cve_id = finding['title']
    exploit_info = vuln_db.get_exploit_availability(cve_id)

    if exploit_info['exploits_available']:
        # Search Metasploit
        exploits = msf.search_exploits(cve_id)

# 5. Generate report
report_file = reports.generate_html_report(
    title="Penetration Test Report - 192.168.1.100"
)

# 6. Share with team
session_id = collaboration.create_session_share(
    "Web Server Pentest",
    "Complete assessment of production web server"
)
```

---

## 🔒 Security Considerations

### Command Validation
All commands are validated before execution:
- Dangerous command detection
- User confirmation for risky operations
- Timeout protection
- Command injection prevention

### API Key Security
- Store API keys in `.env` file (not in config)
- Never commit `.env` to version control
- Use environment variables for production

### Plugin Security
- Only load plugins from trusted sources
- Review plugin code before installation
- Plugins run with same privileges as main app
- Disable unused plugins

### Collaboration Security
- Use HTTPS for collaboration server
- Encrypt shared sessions
- Implement role-based access control
- Audit all team actions

---

## 🐛 Troubleshooting

### Metasploit Not Available
```bash
# Check if installed
which msfconsole

# Initialize database
sudo msfdb init

# Test connection
msfconsole -q -x "version; exit"
```

### Vulnerability Database API Errors
```python
# Clear cache
vuln_db.clear_cache()

# Check rate limiting
# Wait 60 seconds between large queries
```

### Plugin Loading Errors
```bash
# Check plugin directory
ls ~/.kali-gpt/plugins/

# Verify plugin syntax
python3 -m py_compile ~/.kali-gpt/plugins/your_plugin.py

# Check plugin manager logs
# Errors are printed to console during load
```

---

## 📈 Performance Optimization

### Caching
- Vulnerability database results are cached (24 hours)
- AI responses can be cached with custom plugins
- Scan results are stored locally

### Parallel Operations
- Multiple scans can run concurrently (configure in settings)
- Plugin hooks execute in parallel when possible

### Resource Management
- Configure timeouts for long-running commands
- Limit conversation history size
- Clean old scan results periodically

---

## 🤝 Contributing

### Creating Custom Plugins
1. Use plugin template generator
2. Implement required hooks
3. Test thoroughly
4. Share with community

### Adding Integrations
1. Create new integration in `kali_gpt/integrations/`
2. Follow existing integration patterns
3. Add configuration options
4. Update documentation

---

## 📄 License

Same license as Kali GPT project.

---
**End of Documentation**
