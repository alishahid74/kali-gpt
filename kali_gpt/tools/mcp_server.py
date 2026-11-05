#!/usr/bin/env python3
"""
Kali-GPT MCP Server v4.0

Model Context Protocol server for IDE integration.
Works with: Claude Desktop, VS Code Copilot, Cursor, Roo Code

This allows AI agents to use Kali-GPT tools directly from your IDE.

Usage:
    python3 mcp_server.py --port 8888
    
Configure in Claude Desktop (claude_desktop_config.json):
    {
        "mcpServers": {
            "kali-gpt": {
                "command": "python3",
                "args": ["/path/to/mcp_server.py"],
                "timeout": 300
            }
        }
    }
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

# SECURITY: Input validation to prevent command injection (CWE-78)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
try:
    from kali_gpt.utils.input_validator import validator, InputValidationError
except ImportError:
    # Fallback: refuse to run tools rather than execute unvalidated input
    validator = None

    class InputValidationError(Exception):
        pass

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
# TOOL DEFINITIONS
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
    
    # Web
    "gobuster_scan": {
        "name": "gobuster_scan",
        "description": "Directory and file enumeration with Gobuster",
        "parameters": {
            "url": {"type": "string", "description": "Target URL", "required": True},
            "wordlist": {"type": "string", "description": "Wordlist path", "required": False},
            "extensions": {"type": "string", "description": "File extensions (e.g., 'php,html,txt')", "required": False},
        }
    },
    "ffuf_scan": {
        "name": "ffuf_scan",
        "description": "Fast web fuzzer",
        "parameters": {
            "url": {"type": "string", "description": "Target URL with FUZZ keyword", "required": True},
            "wordlist": {"type": "string", "description": "Wordlist path", "required": False},
            "filter_code": {"type": "string", "description": "Filter status codes", "required": False},
        }
    },
    "nuclei_scan": {
        "name": "nuclei_scan",
        "description": "Vulnerability scanning with Nuclei templates",
        "parameters": {
            "target": {"type": "string", "description": "Target URL", "required": True},
            "templates": {"type": "string", "description": "Template category (cves, vulnerabilities, etc.)", "required": False},
            "severity": {"type": "string", "description": "Severity filter (critical,high,medium)", "required": False},
        }
    },
    "nikto_scan": {
        "name": "nikto_scan",
        "description": "Web server vulnerability scanner",
        "parameters": {
            "target": {"type": "string", "description": "Target URL", "required": True},
            "tuning": {"type": "string", "description": "Test types to include", "required": False},
        }
    },
    "wpscan_scan": {
        "name": "wpscan_scan",
        "description": "WordPress vulnerability scanner",
        "parameters": {
            "url": {"type": "string", "description": "WordPress URL", "required": True},
            "enumerate": {"type": "string", "description": "Enumerate: ap (plugins), at (themes), u (users)", "required": False},
        }
    },
    "sqlmap_scan": {
        "name": "sqlmap_scan",
        "description": "Automatic SQL injection testing",
        "parameters": {
            "url": {"type": "string", "description": "Target URL with parameter", "required": True},
            "dbs": {"type": "boolean", "description": "Enumerate databases", "required": False},
            "level": {"type": "integer", "description": "Test level (1-5)", "required": False},
        }
    },
    
    # Network
    "enum4linux_scan": {
        "name": "enum4linux_scan",
        "description": "SMB enumeration",
        "parameters": {
            "target": {"type": "string", "description": "Target IP", "required": True},
            "options": {"type": "string", "description": "Options (-a for all)", "required": False},
        }
    },
    "smbclient_list": {
        "name": "smbclient_list",
        "description": "List SMB shares",
        "parameters": {
            "target": {"type": "string", "description": "Target IP", "required": True},
            "username": {"type": "string", "description": "Username", "required": False},
            "password": {"type": "string", "description": "Password", "required": False},
        }
    },
    
    # Password
    "hydra_attack": {
        "name": "hydra_attack",
        "description": "Network login brute-force",
        "parameters": {
            "target": {"type": "string", "description": "Target IP", "required": True},
            "service": {"type": "string", "description": "Service (ssh, ftp, http-post-form)", "required": True},
            "username": {"type": "string", "description": "Username or user list", "required": True},
            "password_list": {"type": "string", "description": "Password wordlist", "required": True},
        }
    },
    
    # Cloud
    "prowler_scan": {
        "name": "prowler_scan",
        "description": "AWS/Azure/GCP security assessment",
        "parameters": {
            "provider": {"type": "string", "description": "Cloud provider: aws, azure, gcp", "required": True},
            "checks": {"type": "string", "description": "Specific checks to run", "required": False},
        }
    },
    "trivy_scan": {
        "name": "trivy_scan",
        "description": "Container/IaC vulnerability scanner",
        "parameters": {
            "target": {"type": "string", "description": "Image name or path", "required": True},
            "scan_type": {"type": "string", "description": "Type: image, fs, repo, config", "required": False},
        }
    },
    
    # OSINT
    "subfinder_enum": {
        "name": "subfinder_enum",
        "description": "Passive subdomain enumeration",
        "parameters": {
            "domain": {"type": "string", "description": "Target domain", "required": True},
        }
    },
    "theharvester_scan": {
        "name": "theharvester_scan",
        "description": "Email and subdomain harvesting",
        "parameters": {
            "domain": {"type": "string", "description": "Target domain", "required": True},
            "sources": {"type": "string", "description": "Data sources (google,bing,linkedin)", "required": False},
        }
    },
    
    # Utility
    "whatweb_scan": {
        "name": "whatweb_scan",
        "description": "Web technology fingerprinting",
        "parameters": {
            "target": {"type": "string", "description": "Target URL", "required": True},
        }
    },
    "searchsploit_search": {
        "name": "searchsploit_search",
        "description": "Search exploit database",
        "parameters": {
            "query": {"type": "string", "description": "Search query", "required": True},
        }
    },
}


# =============================================================================
# TOOL EXECUTION
# =============================================================================

def _run_argv(cmd: List[str], timeout: int = 300, tool_name: str = "") -> Dict:
    """
    SECURITY: Execute a command as an argv list with shell=False.

    Passing a list with shell=False hands arguments straight to execve(), so
    shell metacharacters (; | & ` $() etc.) in any argument are treated as
    literal data and can never start a new command (CWE-78 mitigation).
    """
    if not cmd:
        return {"error": "Could not build command"}

    tool_bin = cmd[0]
    if not shutil.which(tool_bin):
        return {"error": f"Tool not installed: {tool_bin}"}

    try:
        result = subprocess.run(
            cmd,
            shell=False,  # SECURITY: never use shell=True with external input
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "tool": tool_name,
            "command": " ".join(cmd),  # display/logging only, never re-executed
            "output": result.stdout + result.stderr,
            "return_code": result.returncode,
            "success": result.returncode == 0 or len(result.stdout) > 0,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "command": " ".join(cmd)}
    except Exception as e:
        return {"error": str(e), "command": " ".join(cmd)}


def _build_command(tool_name: str, params: Dict) -> List[str]:
    """
    Build a validated argv list for a tool.

    SECURITY: Every user-controllable value is validated through the allowlist
    validators before it is placed into the argv list. Validation failures raise
    InputValidationError, which the caller turns into an error response.
    """
    if validator is None:
        raise InputValidationError(
            "Input validator unavailable; refusing to execute to avoid command injection"
        )

    if tool_name == "nmap_scan":
        target = validator.validate_target(params.get("target", ""))
        scan_type = validator.validate_scan_type(params.get("scan_type", "quick"))
        cmd = ["nmap"]
        if scan_type == "quick":
            cmd += ["-T4", "--top-ports", "100", target]
        elif scan_type == "full":
            cmd += ["-sV", "-sC", "-T4"]
            if params.get("ports"):
                cmd += ["-p", validator.validate_port_range(params["ports"])]
            cmd.append(target)
        elif scan_type == "vuln":
            cmd += ["--script=vuln", target]
        elif scan_type == "stealth":
            cmd += ["-sS", "-T2", target]
        else:
            cmd += ["-sV", "-sC", "-T4", target]
        return cmd

    if tool_name == "masscan_scan":
        target = validator.validate_target(params.get("target", ""))
        ports = validator.validate_port_range(params.get("ports", "1-1000"))
        rate = int(params.get("rate", 1000))
        if not (1 <= rate <= 100000):
            raise InputValidationError(f"Invalid rate: {rate} (must be 1-100000)")
        return ["masscan", target, f"-p{ports}", f"--rate={rate}"]

    if tool_name == "gobuster_scan":
        url = validator.validate_url(params.get("url", ""))
        wordlist = _safe_wordlist(params.get("wordlist"))
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "30", "-q"]
        ext = params.get("extensions", "")
        if ext:
            if not all(c.isalnum() or c == "," for c in ext):
                raise InputValidationError(f"Invalid extensions: {ext}")
            cmd += ["-x", ext]
        return cmd

    if tool_name == "ffuf_scan":
        url = validator.validate_url(params.get("url", ""))
        wordlist = _safe_wordlist(params.get("wordlist"))
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-t", "50"]
        fc = params.get("filter_code", "")
        if fc:
            if not all(c.isdigit() or c == "," for c in fc):
                raise InputValidationError(f"Invalid filter_code: {fc}")
            cmd += ["-fc", fc]
        return cmd

    if tool_name == "nuclei_scan":
        target = validator.validate_url(params.get("target", ""))
        cmd = ["nuclei", "-u", target]
        templates = params.get("templates", "")
        if templates:
            cmd += ["-t", validator.validate_alphanumeric(templates, "templates") + "/"]
        severity = params.get("severity", "")
        if severity:
            cmd += ["-severity", validator.validate_severity(severity)]
        return cmd

    if tool_name == "nikto_scan":
        target = validator.validate_url(params.get("target", ""), require_http=False)
        cmd = ["nikto", "-h", target]
        tuning = params.get("tuning", "")
        if tuning:
            cmd += ["-Tuning", validator.validate_alphanumeric(tuning, "tuning")]
        return cmd

    if tool_name == "wpscan_scan":
        url = validator.validate_url(params.get("url", ""))
        enumerate = params.get("enumerate", "ap,at,u")
        if not all(c.isalnum() or c == "," for c in enumerate):
            raise InputValidationError(f"Invalid enumerate value: {enumerate}")
        return ["wpscan", "--url", url, "--enumerate", enumerate]

    if tool_name == "sqlmap_scan":
        url = validator.validate_url(params.get("url", ""))
        level = int(params.get("level", 1))
        if not (1 <= level <= 5):
            raise InputValidationError(f"Invalid level: {level} (must be 1-5)")
        cmd = ["sqlmap", "-u", url, "--level", str(level), "--batch"]
        if params.get("dbs", False):
            cmd.append("--dbs")
        return cmd

    if tool_name == "enum4linux_scan":
        target = validator.validate_target(params.get("target", ""))
        options = params.get("options", "-a")
        # Allowlist of safe enum4linux flags only
        if options not in ("-a", "-U", "-S", "-G", "-P", "-o"):
            raise InputValidationError(f"Invalid options: {options}")
        return ["enum4linux", options, target]

    if tool_name == "smbclient_list":
        target = validator.validate_target(params.get("target", ""))
        username = params.get("username", "")
        password = params.get("password", "")
        if username and password:
            username = validator.validate_username(username)
            # Password passed as a separate argv element: not shell-interpreted.
            return ["smbclient", "-L", f"//{target}", "-U", f"{username}%{password}"]
        return ["smbclient", "-L", f"//{target}", "-N"]

    if tool_name == "hydra_attack":
        target = validator.validate_target(params.get("target", ""))
        service = validator.validate_service_name(params.get("service", "ssh"))
        username = validator.validate_username(params.get("username", "admin"))
        password_list = _safe_wordlist(params.get("password_list"), "/usr/share/wordlists/rockyou.txt")
        return ["hydra", "-l", username, "-P", password_list, target, service]

    if tool_name == "prowler_scan":
        provider = params.get("provider", "aws")
        if provider not in ("aws", "azure", "gcp"):
            raise InputValidationError(f"Invalid provider: {provider}")
        cmd = ["prowler", provider]
        checks = params.get("checks", "")
        if checks:
            cmd += ["-c", validator.validate_alphanumeric(checks, "checks")]
        return cmd

    if tool_name == "trivy_scan":
        target = params.get("target", "")
        scan_type = params.get("scan_type", "image")
        if scan_type not in ("image", "fs", "repo", "config"):
            raise InputValidationError(f"Invalid scan_type: {scan_type}")
        # Image names / paths: allow a conservative character set, no shell metachars.
        if not re_target_ok(target):
            raise InputValidationError(f"Invalid trivy target: {target}")
        return ["trivy", scan_type, target]

    if tool_name == "subfinder_enum":
        domain = validator.validate_domain(params.get("domain", ""))
        return ["subfinder", "-d", domain, "-silent"]

    if tool_name == "theharvester_scan":
        domain = validator.validate_domain(params.get("domain", ""))
        sources = params.get("sources", "all")
        if not all(c.isalnum() or c in ",_-" for c in sources):
            raise InputValidationError(f"Invalid sources: {sources}")
        return ["theHarvester", "-d", domain, "-b", sources]

    if tool_name == "whatweb_scan":
        target = validator.validate_url(params.get("target", ""), require_http=False)
        return ["whatweb", target, "-a", "3"]

    if tool_name == "searchsploit_search":
        query = params.get("query", "")
        # searchsploit takes free-text terms; allow words/numbers/dots/hyphens only.
        if not query or not all(c.isalnum() or c in " ._-" for c in query):
            raise InputValidationError(f"Invalid search query: {query}")
        return ["searchsploit"] + query.split()

    raise InputValidationError(f"Tool not supported: {tool_name}")


def _safe_wordlist(path: Optional[str], default: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Validate a wordlist path, falling back to a safe default on failure."""
    if not path:
        return default
    try:
        return validator.validate_wordlist_path(path)
    except InputValidationError:
        return default


def re_target_ok(target: str) -> bool:
    """Conservative check for image names / filesystem paths (no shell metachars)."""
    import re
    return bool(re.match(r'^[A-Za-z0-9][A-Za-z0-9_./:@\-]{0,254}$', target or ""))


def execute_tool(tool_name: str, params: Dict) -> Dict:
    """
    Execute a security tool and return results.

    SECURITY (CWE-78 fix): all parameters are validated by allowlist and the
    command is executed as an argv list with shell=False. No user input is ever
    interpolated into a shell string.
    """
    if tool_name not in KALI_TOOLS:
        return {"error": f"Unknown tool: {tool_name}"}

    try:
        cmd = _build_command(tool_name, params)
    except InputValidationError as e:
        return {"error": f"Input validation failed: {e}", "tool": tool_name}
    except (ValueError, TypeError) as e:
        return {"error": f"Invalid parameter: {e}", "tool": tool_name}

    # hydra brute force gets a longer timeout
    timeout = 600 if tool_name == "hydra_attack" else 300
    return _run_argv(cmd, timeout=timeout, tool_name=tool_name)


# =============================================================================
# MCP SERVER (for Claude Desktop / VS Code)
# =============================================================================

# Guard registration so an incompatible installed `mcp` version cannot crash
# module import (which would also break the HTTP and CLI modes below).
try:
    if MCP_AVAILABLE:
        mcp_server = Server("kali-gpt")

        @mcp_server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available tools"""
            tools = []
            for name, info in KALI_TOOLS.items():
                tools.append(Tool(
                    name=name,
                    description=info["description"],
                    inputSchema={
                        "type": "object",
                        "properties": info["parameters"],
                        "required": [k for k, v in info["parameters"].items() if v.get("required")]
                    }
                ))
            return tools

        @mcp_server.call_tool()
        async def call_tool(name: str, arguments: Dict) -> List[TextContent]:
            """Execute a tool"""
            result = execute_tool(name, arguments)

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
except Exception as _mcp_reg_err:  # pragma: no cover - depends on installed mcp version
    MCP_AVAILABLE = False
    print(f"MCP registration skipped (incompatible mcp version): {_mcp_reg_err}", file=sys.stderr)


# =============================================================================
# HTTP SERVER (Flask)
# =============================================================================

if FLASK_AVAILABLE:
    app = Flask(__name__)
    CORS(app)
    
    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "version": "4.1",
            "security": "CWE-78 command injection fixed (validated argv, shell=False)",
            "tools_available": len(KALI_TOOLS),
            "timestamp": datetime.now().isoformat()
        })
    
    @app.route("/tools", methods=["GET"])
    def list_http_tools():
        """List available tools"""
        return jsonify({"tools": list(KALI_TOOLS.keys())})
    
    @app.route("/tool/<name>", methods=["GET"])
    def get_tool_info(name: str):
        """Get tool information"""
        if name not in KALI_TOOLS:
            return jsonify({"error": f"Unknown tool: {name}"}), 404
        return jsonify(KALI_TOOLS[name])
    
    @app.route("/execute", methods=["POST"])
    def execute():
        """Execute a tool"""
        data = request.json
        tool_name = data.get("tool")
        params = data.get("params", {})
        
        if not tool_name:
            return jsonify({"error": "Missing tool name"}), 400
        
        result = execute_tool(tool_name, params)
        return jsonify(result)
    
    @app.route("/api/command", methods=["POST"])
    def raw_command():
        """
        Execute a raw command.

        SECURITY: A network endpoint that runs arbitrary commands is dangerous
        by design and a blocklist does not make it safe. It is therefore DISABLED
        unless the operator explicitly opts in by setting the environment variable
        KALI_GPT_ALLOW_RAW_COMMAND=1. When enabled, the command is split with
        shlex and executed with shell=False so shell metacharacters are not
        interpreted. Prefer the validated /execute endpoint instead.
        """
        if os.environ.get("KALI_GPT_ALLOW_RAW_COMMAND") != "1":
            return jsonify({
                "error": "Raw command endpoint disabled. Use /execute, or set "
                         "KALI_GPT_ALLOW_RAW_COMMAND=1 to explicitly enable (not recommended)."
            }), 403

        data = request.json
        command = data.get("command")

        if not command:
            return jsonify({"error": "Missing command"}), 400

        import shlex
        try:
            argv = shlex.split(command)
        except ValueError as e:
            return jsonify({"error": f"Could not parse command: {e}"}), 400

        if not argv:
            return jsonify({"error": "Empty command"}), 400

        if not shutil.which(argv[0]):
            return jsonify({"error": f"Tool not installed: {argv[0]}"}), 400

        try:
            result = subprocess.run(
                argv,
                shell=False,  # SECURITY: no shell interpretation of metacharacters
                capture_output=True,
                text=True,
                timeout=120
            )

            return jsonify({
                "command": " ".join(argv),
                "output": result.stdout + result.stderr,
                "return_code": result.returncode,
                "success": result.returncode == 0
            })
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Command timed out"}), 408
        except Exception as e:
            return jsonify({"error": str(e)}), 500


# =============================================================================
# CLI INTERFACE
# =============================================================================

def cli_mode():
    """Interactive CLI mode"""
    print("Kali-GPT MCP Server v4.0")
    print(f"Tools available: {len(KALI_TOOLS)}")
    print("\nCommands: list, run <tool>, help <tool>, quit\n")
    
    while True:
        try:
            cmd = input("kali-gpt> ").strip()
            
            if not cmd:
                continue
            
            if cmd == "quit" or cmd == "exit":
                break
            
            if cmd == "list":
                print("\nAvailable tools:")
                for name in sorted(KALI_TOOLS.keys()):
                    print(f"  - {name}: {KALI_TOOLS[name]['description'][:60]}")
                print()
            
            elif cmd.startswith("help "):
                tool_name = cmd[5:].strip()
                if tool_name in KALI_TOOLS:
                    tool = KALI_TOOLS[tool_name]
                    print(f"\n{tool_name}: {tool['description']}")
                    print("Parameters:")
                    for param, info in tool['parameters'].items():
                        req = "(required)" if info.get("required") else "(optional)"
                        print(f"  - {param}: {info['description']} {req}")
                    print()
                else:
                    print(f"Unknown tool: {tool_name}")
            
            elif cmd.startswith("run "):
                parts = cmd[4:].strip().split()
                tool_name = parts[0]
                
                if tool_name not in KALI_TOOLS:
                    print(f"Unknown tool: {tool_name}")
                    continue
                
                # Parse params
                params = {}
                tool_info = KALI_TOOLS[tool_name]
                
                for param_name, param_info in tool_info['parameters'].items():
                    if param_info.get('required'):
                        value = input(f"  {param_name}: ")
                        params[param_name] = value
                    else:
                        value = input(f"  {param_name} (optional, press Enter to skip): ")
                        if value:
                            params[param_name] = value
                
                print(f"\nExecuting {tool_name}...")
                result = execute_tool(tool_name, params)
                
                if "error" in result:
                    print(f"Error: {result['error']}")
                else:
                    print(f"Command: {result['command']}")
                    print(f"Output:\n{result['output']}")
            
            else:
                print("Unknown command. Use: list, run <tool>, help <tool>, quit")
        
        except KeyboardInterrupt:
            print("\n")
            break
        except EOFError:
            break


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Kali-GPT MCP Server")
    parser.add_argument("--mode", choices=["mcp", "http", "cli"], default="cli",
                       help="Server mode: mcp (stdio), http (REST API), cli (interactive)")
    parser.add_argument("--port", type=int, default=8888, help="HTTP server port")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP server host")
    args = parser.parse_args()
    
    if args.mode == "mcp":
        if not MCP_AVAILABLE:
            print("MCP not available. Install: pip install mcp")
            sys.exit(1)
        print("Starting MCP server (stdio mode)...", file=sys.stderr)
        asyncio.run(run_mcp_server())
    
    elif args.mode == "http":
        if not FLASK_AVAILABLE:
            print("Flask not available. Install: pip install flask flask-cors")
            sys.exit(1)
        print(f"Starting HTTP server on {args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=False)
    
    else:
        cli_mode()


if __name__ == "__main__":
    main()
