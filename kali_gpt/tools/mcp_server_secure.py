#!/usr/bin/env python3
"""
Kali-GPT MCP Server v4.1 - SECURE VERSION
SECURITY FIX: Addresses CWE-78 command injection vulnerability

This version uses:
- List-form subprocess (no shell=True)
- Input validation for all parameters
- Defense-in-depth security controls

CVE: Pending
CVSS: 9.8 Critical (FIXED)
Fix Date: 2026-11-05
"""

import asyncio
import json
import subprocess
import shutil
import sys
import os
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import secure validator
try:
    from kali_gpt.utils.input_validator import validator, InputValidationError
except ImportError:
    print("ERROR: Could not import input validator. Run from project root.", file=sys.stderr)
    sys.exit(1)

# MCP Protocol imports
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

# Flask for HTTP mode
try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


# =============================================================================
# SECURE COMMAND EXECUTION
# =============================================================================

def execute_secure(command_list: List[str], timeout: int = 300) -> Dict:
    """
    Execute command securely using list-form subprocess (NO shell=True)

    Args:
        command_list: Command as list of strings (argv style)
        timeout: Command timeout in seconds

    Returns:
        Dict with execution results

    Security:
        - Uses list-form subprocess (prevents shell injection)
        - No shell interpretation
        - Validates tool exists before execution
        - Has timeout protection
    """
    if not command_list:
        return {"error": "Empty command"}

    tool_bin = command_list[0]

    # Check if tool exists
    if not shutil.which(tool_bin):
        return {"error": f"Tool not installed: {tool_bin}"}

    try:
        result = subprocess.run(
            command_list,  # List form - NO SHELL INJECTION POSSIBLE
            capture_output=True,
            text=True,
            timeout=timeout,
            # SECURITY: shell=False is the default, but explicitly set for clarity
            shell=False
        )

        return {
            "command": ' '.join(command_list),  # For logging only
            "output": result.stdout + result.stderr,
            "return_code": result.returncode,
            "success": result.returncode == 0 or len(result.stdout) > 0,
            "timestamp": datetime.now().isoformat()
        }

    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "command": ' '.join(command_list)}
    except Exception as e:
        return {"error": str(e), "command": ' '.join(command_list)}


# =============================================================================
# TOOL DEFINITIONS (Same as before)
# =============================================================================

KALI_TOOLS = {
    # Reconnaissance
    "nmap_scan": {
        "name": "nmap_scan",
        "description": "Network port scanning and service detection with Nmap",
        "parameters": {
            "target": {"type": "string", "description": "Target IP or hostname", "required": True},
            "ports": {"type": "string", "description": "Ports to scan (e.g., '22,80,443' or '1-1000')", "required": False},
            "scan_type": {"type": "string", "description": "Scan type: quick, full, vuln, stealth", "required": False},
        }
    },
    "masscan_scan": {
        "name": "masscan_scan",
        "description": "Fast port scanning with Masscan",
        "parameters": {
            "target": {"type": "string", "description": "Target IP/CIDR", "required": True},
            "ports": {"type": "string", "description": "Ports to scan", "required": False},
            "rate": {"type": "integer", "description": "Packets per second", "required": False},
        }
    },
    "gobuster_scan": {
        "name": "gobuster_scan",
        "description": "Directory and file enumeration with Gobuster",
        "parameters": {
            "url": {"type": "string", "description": "Target URL", "required": True},
            "wordlist": {"type": "string", "description": "Wordlist path", "required": False},
            "extensions": {"type": "string", "description": "File extensions (e.g., 'php,html,txt')", "required": False},
        }
    },
    "nuclei_scan": {
        "name": "nuclei_scan",
        "description": "Vulnerability scanning with Nuclei templates",
        "parameters": {
            "target": {"type": "string", "description": "Target URL", "required": True},
            "severity": {"type": "string", "description": "Severity filter (critical,high,medium)", "required": False},
        }
    },
    "hydra_attack": {
        "name": "hydra_attack",
        "description": "Network login brute-force",
        "parameters": {
            "target": {"type": "string", "description": "Target IP", "required": True},
            "service": {"type": "string", "description": "Service (ssh, ftp, http-post-form)", "required": True},
            "username": {"type": "string", "description": "Username", "required": True},
            "password_list": {"type": "string", "description": "Password wordlist", "required": True},
        }
    },
    "subfinder_enum": {
        "name": "subfinder_enum",
        "description": "Passive subdomain enumeration",
        "parameters": {
            "domain": {"type": "string", "description": "Target domain", "required": True},
        }
    },
    "whatweb_scan": {
        "name": "whatweb_scan",
        "description": "Web technology fingerprinting",
        "parameters": {
            "target": {"type": "string", "description": "Target URL", "required": True},
        }
    },
}


# =============================================================================
# SECURE TOOL EXECUTION
# =============================================================================

def execute_tool_secure(tool_name: str, params: Dict) -> Dict:
    """
    Execute a security tool SECURELY

    SECURITY IMPROVEMENTS:
    1. Input validation for ALL parameters
    2. List-form subprocess (no shell=True)
    3. No f-string interpolation into commands
    4. Defense-in-depth validation

    Args:
        tool_name: Name of tool to execute
        params: Tool parameters (ALL will be validated)

    Returns:
        Execution results or error
    """

    if tool_name not in KALI_TOOLS:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        # =================================================================
        # NMAP SCAN
        # =================================================================
        if tool_name == "nmap_scan":
            target = validator.validate_target(params.get("target", ""))
            ports = params.get("ports", "")
            scan_type = validator.validate_scan_type(params.get("scan_type", "quick"))

            # Build command as LIST (not f-string!)
            cmd = ["nmap"]

            if scan_type == "quick":
                cmd.extend(["-T4", "--top-ports", "100", target])
            elif scan_type == "full":
                cmd.extend(["-sV", "-sC", "-T4"])
                if ports:
                    validated_ports = validator.validate_port_range(ports)
                    cmd.extend(["-p", validated_ports])
                cmd.append(target)
            elif scan_type == "vuln":
                cmd.extend(["--script=vuln", target])
            elif scan_type == "stealth":
                cmd.extend(["-sS", "-T2", target])
            else:
                cmd.extend(["-sV", "-sC", "-T4", target])

            result = execute_secure(cmd)
            result["tool"] = tool_name
            return result

        # =================================================================
        # MASSCAN SCAN
        # =================================================================
        elif tool_name == "masscan_scan":
            target = validator.validate_target(params.get("target", ""))
            ports = validator.validate_port_range(params.get("ports", "1-1000"))
            rate = int(params.get("rate", 1000))

            if rate < 1 or rate > 100000:
                raise InputValidationError(f"Invalid rate: {rate}. Must be 1-100000")

            cmd = ["masscan", target, f"-p{ports}", f"--rate={rate}"]

            result = execute_secure(cmd)
            result["tool"] = tool_name
            return result

        # =================================================================
        # GOBUSTER SCAN
        # =================================================================
        elif tool_name == "gobuster_scan":
            url = validator.validate_url(params.get("url", ""))
            wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

            # Validate wordlist path
            try:
                wordlist = validator.validate_wordlist_path(wordlist)
            except InputValidationError:
                # Fallback to default if invalid
                wordlist = "/usr/share/wordlists/dirb/common.txt"

            cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "30", "-q"]

            # Optional extensions
            extensions = params.get("extensions", "")
            if extensions:
                # Validate extensions (alphanumeric + comma only)
                if not all(c.isalnum() or c == ',' for c in extensions):
                    raise InputValidationError(f"Invalid extensions: {extensions}")
                cmd.extend(["-x", extensions])

            result = execute_secure(cmd)
            result["tool"] = tool_name
            return result

        # =================================================================
        # NUCLEI SCAN
        # =================================================================
        elif tool_name == "nuclei_scan":
            target = validator.validate_url(params.get("target", ""))

            cmd = ["nuclei", "-u", target]

            # Optional severity filter
            severity = params.get("severity", "")
            if severity:
                severity = validator.validate_severity(severity)
                cmd.extend(["-severity", severity])

            result = execute_secure(cmd)
            result["tool"] = tool_name
            return result

        # =================================================================
        # HYDRA ATTACK
        # =================================================================
        elif tool_name == "hydra_attack":
            target = validator.validate_target(params.get("target", ""))
            service = validator.validate_service_name(params.get("service", "ssh"))
            username = validator.validate_username(params.get("username", "admin"))
            password_list = params.get("password_list", "/usr/share/wordlists/rockyou.txt")

            # Validate wordlist
            try:
                password_list = validator.validate_wordlist_path(password_list)
            except InputValidationError:
                password_list = "/usr/share/wordlists/rockyou.txt"

            cmd = ["hydra", "-l", username, "-P", password_list, target, service]

            result = execute_secure(cmd, timeout=600)  # Longer timeout for brute force
            result["tool"] = tool_name
            return result

        # =================================================================
        # SUBFINDER
        # =================================================================
        elif tool_name == "subfinder_enum":
            domain = validator.validate_domain(params.get("domain", ""))

            cmd = ["subfinder", "-d", domain, "-silent"]

            result = execute_secure(cmd)
            result["tool"] = tool_name
            return result

        # =================================================================
        # WHATWEB
        # =================================================================
        elif tool_name == "whatweb_scan":
            target = validator.validate_url(params.get("target", ""), require_http=False)

            cmd = ["whatweb", target, "-a", "3"]

            result = execute_secure(cmd)
            result["tool"] = tool_name
            return result

        # =================================================================
        # UNKNOWN TOOL
        # =================================================================
        else:
            return {"error": f"Tool '{tool_name}' not yet implemented in secure version"}

    except InputValidationError as e:
        return {"error": f"Input validation failed: {e}"}
    except Exception as e:
        return {"error": f"Execution error: {e}"}


# =============================================================================
# MCP SERVER
# =============================================================================

if MCP_AVAILABLE:
    mcp_server = Server("kali-gpt-secure")

    @mcp_server.list_tools()
    async def list_tools() -> List[Tool]:
        """List available tools"""
        tools = []
        for name, info in KALI_TOOLS.items():
            tools.append(Tool(
                name=name,
                description=info["description"] + " [SECURE]",
                inputSchema={
                    "type": "object",
                    "properties": info["parameters"],
                    "required": [k for k, v in info["parameters"].items() if v.get("required")]
                }
            ))
        return tools

    @mcp_server.call_tool()
    async def call_tool(name: str, arguments: Dict) -> List[TextContent]:
        """Execute a tool securely"""
        result = execute_tool_secure(name, arguments)

        if "error" in result:
            return [TextContent(
                type="text",
                text=f"Error: {result['error']}\nCommand: {result.get('command', 'N/A')}"
            )]

        return [TextContent(
            type="text",
            text=f"Tool: {result['tool']}\nCommand: {result['command']}\n\nOutput:\n{result['output']}"
        )]

    async def run_mcp_server():
        """Run MCP server via stdio"""
        async with stdio_server() as (read_stream, write_stream):
            await mcp_server.run(read_stream, write_stream)


# =============================================================================
# HTTP SERVER (Flask) - SECURE VERSION
# =============================================================================

if FLASK_AVAILABLE:
    app = Flask(__name__)
    CORS(app)

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "version": "4.1-secure",
            "security": "CWE-78 FIXED",
            "tools_available": len(KALI_TOOLS),
            "timestamp": datetime.now().isoformat()
        })

    @app.route("/tools", methods=["GET"])
    def list_http_tools():
        """List available tools"""
        return jsonify({"tools": list(KALI_TOOLS.keys())})

    @app.route("/execute", methods=["POST"])
    def execute():
        """Execute a tool securely"""
        data = request.json
        tool_name = data.get("tool")
        params = data.get("params", {})

        if not tool_name:
            return jsonify({"error": "Missing tool name"}), 400

        result = execute_tool_secure(tool_name, params)
        return jsonify(result)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def cli_mode():
    """Interactive CLI mode"""
    print("Kali-GPT MCP Server v4.1 - SECURE")
    print("✓ CWE-78 Command Injection FIXED")
    print(f"Tools available: {len(KALI_TOOLS)}")
    print("\nCommands: list, run <tool>, quit\n")

    while True:
        try:
            cmd = input("kali-gpt-secure> ").strip()

            if not cmd:
                continue

            if cmd in ("quit", "exit"):
                break

            if cmd == "list":
                print("\nAvailable tools:")
                for name in sorted(KALI_TOOLS.keys()):
                    print(f"  - {name}: {KALI_TOOLS[name]['description'][:60]}")
                print()

            elif cmd.startswith("run "):
                tool_name = cmd[4:].strip()

                if tool_name not in KALI_TOOLS:
                    print(f"Unknown tool: {tool_name}")
                    continue

                # Collect params
                params = {}
                tool_info = KALI_TOOLS[tool_name]

                for param_name, param_info in tool_info['parameters'].items():
                    if param_info.get('required'):
                        value = input(f"  {param_name}: ")
                        params[param_name] = value
                    else:
                        value = input(f"  {param_name} (optional): ")
                        if value:
                            params[param_name] = value

                print(f"\nExecuting {tool_name} [SECURE MODE]...")
                result = execute_tool_secure(tool_name, params)

                if "error" in result:
                    print(f"Error: {result['error']}")
                else:
                    print(f"Command: {result['command']}")
                    print(f"Output:\n{result['output']}")

            else:
                print("Unknown command. Use: list, run <tool>, quit")

        except KeyboardInterrupt:
            print("\n")
            break
        except EOFError:
            break


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Kali-GPT MCP Server v4.1 SECURE")
    parser.add_argument("--mode", choices=["mcp", "http", "cli"], default="cli",
                       help="Server mode")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    print("="*60, file=sys.stderr)
    print("SECURITY: Using SECURE version (CWE-78 FIXED)", file=sys.stderr)
    print("="*60, file=sys.stderr)

    if args.mode == "mcp":
        if not MCP_AVAILABLE:
            print("MCP not available. Install: pip install mcp")
            sys.exit(1)
        print("Starting SECURE MCP server...", file=sys.stderr)
        asyncio.run(run_mcp_server())

    elif args.mode == "http":
        if not FLASK_AVAILABLE:
            print("Flask not available. Install: pip install flask flask-cors")
            sys.exit(1)
        print(f"Starting SECURE HTTP server on {args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=False)

    else:
        cli_mode()


if __name__ == "__main__":
    main()
