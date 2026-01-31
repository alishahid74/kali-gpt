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

def execute_tool(tool_name: str, params: Dict) -> Dict:
    """Execute a security tool and return results"""
    
    if tool_name not in KALI_TOOLS:
        return {"error": f"Unknown tool: {tool_name}"}
    
    # Build command based on tool
    command = None
    
    if tool_name == "nmap_scan":
        target = params.get("target", "")
        ports = params.get("ports", "")
        scan_type = params.get("scan_type", "quick")
        
        if scan_type == "quick":
            command = f"nmap -T4 --top-ports 100 {target}"
        elif scan_type == "full":
            command = f"nmap -sV -sC -T4 {'-p ' + ports if ports else ''} {target}"
        elif scan_type == "vuln":
            command = f"nmap --script=vuln {target}"
        elif scan_type == "stealth":
            command = f"nmap -sS -T2 {target}"
        else:
            command = f"nmap -sV -sC -T4 {target}"
    
    elif tool_name == "masscan_scan":
        target = params.get("target", "")
        ports = params.get("ports", "1-1000")
        rate = params.get("rate", 1000)
        command = f"masscan {target} -p{ports} --rate={rate}"
    
    elif tool_name == "gobuster_scan":
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = params.get("extensions", "")
        ext_flag = f"-x {extensions}" if extensions else ""
        command = f"gobuster dir -u {url} -w {wordlist} {ext_flag} -t 30 -q"
    
    elif tool_name == "ffuf_scan":
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        filter_code = params.get("filter_code", "")
        fc_flag = f"-fc {filter_code}" if filter_code else ""
        command = f"ffuf -u {url} -w {wordlist} {fc_flag} -t 50"
    
    elif tool_name == "nuclei_scan":
        target = params.get("target", "")
        templates = params.get("templates", "")
        severity = params.get("severity", "")
        t_flag = f"-t {templates}/" if templates else ""
        s_flag = f"-severity {severity}" if severity else ""
        command = f"nuclei -u {target} {t_flag} {s_flag}"
    
    elif tool_name == "nikto_scan":
        target = params.get("target", "")
        tuning = params.get("tuning", "")
        t_flag = f"-Tuning {tuning}" if tuning else ""
        command = f"nikto -h {target} {t_flag}"
    
    elif tool_name == "wpscan_scan":
        url = params.get("url", "")
        enumerate = params.get("enumerate", "ap,at,u")
        command = f"wpscan --url {url} --enumerate {enumerate}"
    
    elif tool_name == "sqlmap_scan":
        url = params.get("url", "")
        dbs = params.get("dbs", False)
        level = params.get("level", 1)
        dbs_flag = "--dbs" if dbs else ""
        command = f"sqlmap -u \"{url}\" {dbs_flag} --level={level} --batch"
    
    elif tool_name == "enum4linux_scan":
        target = params.get("target", "")
        options = params.get("options", "-a")
        command = f"enum4linux {options} {target}"
    
    elif tool_name == "smbclient_list":
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        if username and password:
            command = f"smbclient -L //{target} -U {username}%{password}"
        else:
            command = f"smbclient -L //{target} -N"
    
    elif tool_name == "hydra_attack":
        target = params.get("target", "")
        service = params.get("service", "ssh")
        username = params.get("username", "admin")
        password_list = params.get("password_list", "/usr/share/wordlists/rockyou.txt")
        command = f"hydra -l {username} -P {password_list} {target} {service}"
    
    elif tool_name == "prowler_scan":
        provider = params.get("provider", "aws")
        checks = params.get("checks", "")
        c_flag = f"-c {checks}" if checks else ""
        command = f"prowler {provider} {c_flag}"
    
    elif tool_name == "trivy_scan":
        target = params.get("target", "")
        scan_type = params.get("scan_type", "image")
        command = f"trivy {scan_type} {target}"
    
    elif tool_name == "subfinder_enum":
        domain = params.get("domain", "")
        command = f"subfinder -d {domain} -silent"
    
    elif tool_name == "theharvester_scan":
        domain = params.get("domain", "")
        sources = params.get("sources", "all")
        command = f"theHarvester -d {domain} -b {sources}"
    
    elif tool_name == "whatweb_scan":
        target = params.get("target", "")
        command = f"whatweb {target} -a 3"
    
    elif tool_name == "searchsploit_search":
        query = params.get("query", "")
        command = f"searchsploit {query}"
    
    if not command:
        return {"error": "Could not build command"}
    
    # Check if tool exists
    tool_bin = command.split()[0]
    if not shutil.which(tool_bin):
        return {"error": f"Tool not installed: {tool_bin}"}
    
    # Execute
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        return {
            "tool": tool_name,
            "command": command,
            "output": result.stdout + result.stderr,
            "return_code": result.returncode,
            "success": result.returncode == 0 or len(result.stdout) > 0,
            "timestamp": datetime.now().isoformat()
        }
    
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out", "command": command}
    except Exception as e:
        return {"error": str(e), "command": command}


# =============================================================================
# MCP SERVER (for Claude Desktop / VS Code)
# =============================================================================

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
            "version": "4.0",
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
        """Execute a raw command (with caution)"""
        data = request.json
        command = data.get("command")
        
        if not command:
            return jsonify({"error": "Missing command"}), 400
        
        # Basic safety check
        dangerous = ["rm -rf", "mkfs", "dd if=", "> /dev/"]
        if any(d in command for d in dangerous):
            return jsonify({"error": "Dangerous command blocked"}), 403
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return jsonify({
                "command": command,
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
