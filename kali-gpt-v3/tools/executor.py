"""
Tool Executor

Safely executes penetration testing tools and commands.
Includes:
- Command validation and sanitization
- Timeout handling
- Output parsing
- Tool availability checking
"""

import asyncio
import subprocess
import shlex
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import os


class RiskLevel(str, Enum):
    """Risk levels for commands"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKED = "blocked"


@dataclass
class ToolConfig:
    """Configuration for a specific tool"""
    name: str
    path: Optional[str] = None
    default_timeout: int = 60
    risk_level: RiskLevel = RiskLevel.LOW
    requires_root: bool = False
    output_parser: Optional[str] = None  # Parser function name
    allowed_flags: List[str] = field(default_factory=list)
    blocked_flags: List[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    """Result of command execution"""
    success: bool
    output: str
    error: Optional[str] = None
    return_code: int = 0
    execution_time: float = 0.0
    tool: str = ""
    command: str = ""
    findings: List[Dict] = field(default_factory=list)


class CommandValidator:
    """Validates commands for safety"""
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        r"rm\s+-rf\s+/",
        r"rm\s+-rf\s+\*",
        r"mkfs\.",
        r"dd\s+if=.+of=/dev/",
        r">\s*/dev/sd[a-z]",
        r"chmod\s+-R\s+777\s+/",
        r"wget.+\|\s*sh",
        r"curl.+\|\s*sh",
        r":\(\)\{.*\}",  # Fork bomb
        r"/dev/null\s*>\s*/",
    ]
    
    # Commands that require extra confirmation
    HIGH_RISK_COMMANDS = [
        "msfconsole", "msfvenom",
        "sqlmap", "sqlninja",
        "hydra", "medusa", "ncrack",
        "john", "hashcat",
        "mimikatz", "secretsdump",
        "responder", "impacket",
    ]
    
    # Safe read-only commands
    SAFE_COMMANDS = [
        "nmap", "whois", "dig", "host", "nslookup",
        "ping", "traceroute", "curl", "wget",
        "cat", "head", "tail", "grep", "find",
        "ls", "pwd", "whoami", "id", "uname",
        "whatweb", "wafw00f", "httpx",
        "subfinder", "amass", "assetfinder",
        "gobuster", "ffuf", "dirb", "dirsearch",
        "nikto", "nuclei", "wpscan",
    ]
    
    def __init__(self):
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_PATTERNS
        ]
    
    def validate(self, command: str) -> Tuple[bool, RiskLevel, str]:
        """
        Validate a command for safety
        
        Returns:
            Tuple of (is_valid, risk_level, reason)
        """
        if not command or not command.strip():
            return False, RiskLevel.BLOCKED, "Empty command"
        
        # Check for dangerous patterns
        for pattern in self.compiled_patterns:
            if pattern.search(command):
                return False, RiskLevel.BLOCKED, f"Dangerous pattern detected"
        
        # Get the base command
        parts = shlex.split(command)
        if not parts:
            return False, RiskLevel.BLOCKED, "Invalid command syntax"
        
        base_cmd = parts[0].split("/")[-1]  # Handle full paths
        
        # Check risk level
        if base_cmd in self.SAFE_COMMANDS:
            return True, RiskLevel.LOW, "Safe command"
        
        if base_cmd in self.HIGH_RISK_COMMANDS:
            return True, RiskLevel.HIGH, "High-risk exploitation tool"
        
        # Unknown command - medium risk
        return True, RiskLevel.MEDIUM, "Unknown command"
    
    def sanitize(self, command: str) -> str:
        """Basic command sanitization"""
        # Remove any shell injection attempts
        dangerous_chars = [";", "&&", "||", "`", "$(",  "$(", "|"]
        
        sanitized = command
        for char in dangerous_chars:
            if char in sanitized:
                # Only block if not in quotes
                # Simple check - may need improvement
                sanitized = sanitized.replace(char, " ")
        
        return sanitized.strip()


class ToolExecutor:
    """Executes penetration testing tools safely"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.validator = CommandValidator()
        self.default_timeout = self.config.get("default_timeout", 300)
        self.require_confirmation = self.config.get("require_confirmation", True)
        self.tool_configs: Dict[str, ToolConfig] = {}
        
        # Initialize tool configurations
        self._init_tool_configs()
    
    def _init_tool_configs(self):
        """Initialize configurations for common tools"""
        tools = [
            ToolConfig("nmap", default_timeout=600, risk_level=RiskLevel.LOW),
            ToolConfig("masscan", default_timeout=300, risk_level=RiskLevel.MEDIUM, requires_root=True),
            ToolConfig("nikto", default_timeout=600, risk_level=RiskLevel.LOW),
            ToolConfig("gobuster", default_timeout=300, risk_level=RiskLevel.LOW),
            ToolConfig("ffuf", default_timeout=300, risk_level=RiskLevel.LOW),
            ToolConfig("sqlmap", default_timeout=600, risk_level=RiskLevel.HIGH),
            ToolConfig("hydra", default_timeout=600, risk_level=RiskLevel.HIGH),
            ToolConfig("nuclei", default_timeout=300, risk_level=RiskLevel.MEDIUM),
            ToolConfig("wpscan", default_timeout=300, risk_level=RiskLevel.LOW),
            ToolConfig("whatweb", default_timeout=60, risk_level=RiskLevel.SAFE),
            ToolConfig("whois", default_timeout=30, risk_level=RiskLevel.SAFE),
            ToolConfig("dig", default_timeout=30, risk_level=RiskLevel.SAFE),
            ToolConfig("theHarvester", default_timeout=300, risk_level=RiskLevel.LOW),
            ToolConfig("amass", default_timeout=600, risk_level=RiskLevel.LOW),
            ToolConfig("subfinder", default_timeout=300, risk_level=RiskLevel.LOW),
        ]
        
        for tool in tools:
            self.tool_configs[tool.name] = tool
    
    async def execute(
        self,
        tool: str,
        command: Optional[str] = None,
        parameters: Optional[Dict] = None,
        timeout: Optional[int] = None,
        skip_validation: bool = False
    ) -> Dict[str, Any]:
        """
        Execute a tool/command
        
        Args:
            tool: Tool name or full command
            command: Full command (if tool is just a name)
            parameters: Additional parameters
            timeout: Execution timeout
            skip_validation: Skip safety validation
            
        Returns:
            ExecutionResult as dict
        """
        # Determine the full command
        full_command = command if command else tool
        
        # Validate command
        if not skip_validation:
            is_valid, risk_level, reason = self.validator.validate(full_command)
            
            if not is_valid:
                return {
                    "success": False,
                    "output": "",
                    "error": f"Command blocked: {reason}",
                    "return_code": -1,
                    "risk_level": risk_level.value
                }
            
            if risk_level == RiskLevel.BLOCKED:
                return {
                    "success": False,
                    "output": "",
                    "error": "Command blocked for safety",
                    "return_code": -1,
                    "risk_level": risk_level.value
                }
        
        # Get tool config for timeout
        base_tool = full_command.split()[0].split("/")[-1]
        tool_config = self.tool_configs.get(base_tool)
        
        exec_timeout = timeout or (
            tool_config.default_timeout if tool_config 
            else self.default_timeout
        )
        
        # Check if tool is available
        if not await self.is_tool_available(base_tool):
            return {
                "success": False,
                "output": "",
                "error": f"Tool not found: {base_tool}",
                "return_code": -1
            }
        
        # Execute the command
        try:
            result = await self._run_command(full_command, exec_timeout)
            
            # Parse output if parser available
            if tool_config and tool_config.output_parser:
                result["findings"] = self._parse_output(
                    result["output"], 
                    tool_config.output_parser
                )
            
            return result
            
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "return_code": -1
            }
    
    async def _run_command(self, command: str, timeout: int) -> Dict[str, Any]:
        """Execute command asynchronously"""
        import time
        start_time = time.time()
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode("utf-8", errors="replace"),
                "error": stderr.decode("utf-8", errors="replace") if stderr else None,
                "return_code": process.returncode,
                "execution_time": execution_time,
                "command": command
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "error": f"Command timed out after {timeout} seconds",
                "return_code": -1,
                "command": command
            }
    
    async def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available on the system"""
        try:
            process = await asyncio.create_subprocess_shell(
                f"which {tool}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False
    
    async def get_available_tools(self) -> List[str]:
        """Get list of available tools"""
        available = []
        for tool_name in self.tool_configs.keys():
            if await self.is_tool_available(tool_name):
                available.append(tool_name)
        return available
    
    def _parse_output(self, output: str, parser_type: str) -> List[Dict]:
        """Parse tool output to extract findings"""
        findings = []
        
        if parser_type == "nmap":
            findings = self._parse_nmap_output(output)
        elif parser_type == "nikto":
            findings = self._parse_nikto_output(output)
        # Add more parsers as needed
        
        return findings
    
    def _parse_nmap_output(self, output: str) -> List[Dict]:
        """Parse nmap output for findings"""
        findings = []
        
        # Simple regex-based parsing
        # Port pattern: 22/tcp   open  ssh
        port_pattern = r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)"
        
        for match in re.finditer(port_pattern, output):
            findings.append({
                "type": "open_port",
                "port": match.group(1),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4)
            })
        
        return findings
    
    def _parse_nikto_output(self, output: str) -> List[Dict]:
        """Parse nikto output for findings"""
        findings = []
        
        # Look for OSVDB and vulnerability patterns
        vuln_pattern = r"\+\s+(OSVDB-\d+|CVE-\d+-\d+)?\s*:?\s*(.+)"
        
        for line in output.split('\n'):
            if line.startswith('+') and 'Server:' not in line:
                findings.append({
                    "type": "web_finding",
                    "raw": line.strip('+').strip()
                })
        
        return findings


class AsyncToolExecutor(ToolExecutor):
    """Tool executor with async streaming support"""
    
    async def execute_stream(
        self,
        command: str,
        timeout: Optional[int] = None
    ):
        """Execute command and yield output in real-time"""
        
        # Validate first
        is_valid, risk_level, reason = self.validator.validate(command)
        if not is_valid:
            yield f"[ERROR] Command blocked: {reason}"
            return
        
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        try:
            while True:
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=timeout or self.default_timeout
                )
                
                if not line:
                    break
                
                yield line.decode("utf-8", errors="replace")
                
        except asyncio.TimeoutError:
            process.kill()
            yield f"\n[ERROR] Command timed out"
        
        await process.wait()
