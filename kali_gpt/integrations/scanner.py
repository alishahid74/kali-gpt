"""Vulnerability Scanner Integration Module"""

import subprocess
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from pathlib import Path
import re

class ScannerManager:
    """Manages automated vulnerability scanning"""

    def __init__(self, config_manager, command_executor):
        """Initialize scanner manager"""
        self.config = config_manager
        self.executor = command_executor
        self.scanner_config = config_manager.get("scanner", {})
        self.enabled = self.scanner_config.get("enabled", False)
        self.default_scanner = self.scanner_config.get("default_scanner", "nmap")

        # Scan results directory
        self.scans_dir = Path(config_manager.config_dir) / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a scanning tool is available"""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def nmap_scan(self, target: str, scan_type: str = "quick",
                  ports: str = None, options: str = "") -> Dict:
        """
        Run Nmap scan

        Args:
            target: Target IP or hostname
            scan_type: Type of scan (quick, full, stealth, vuln)
            ports: Port specification
            options: Additional nmap options

        Returns:
            Scan results
        """
        if not self.is_tool_available("nmap"):
            return {"success": False, "error": "Nmap not available"}

        # Build nmap command based on scan type
        # -Pn treats all hosts as online (skips ping discovery) - crucial for domains/firewalls
        scan_profiles = {
            "quick": "-Pn -sV -T4",
            "full": "-Pn -sV -sC -A -T4 -p-",
            "stealth": "-Pn -sS -sV -T2",
            "vuln": "-Pn -sV --script vuln",
            "aggressive": "-Pn -A -T4",
            "comprehensive": "-Pn -sS -sV -sC -A -O -p-"
        }

        base_cmd = "nmap"
        nmap_options = scan_profiles.get(scan_type, "-Pn -sV")

        if ports:
            nmap_options += f" -p {ports}"

        if options:
            nmap_options += f" {options}"

        # Output to XML for parsing
        # Replace dots and colons for safe filenames
        safe_target = target.replace('.', '_').replace(':', '_')
        output_file = self.scans_dir / f"nmap_{safe_target}_{scan_type}.xml"
        command = f"{base_cmd} {nmap_options} -oX {output_file} {target}"

        # Execute scan
        result = self.executor.execute(command, timeout=600)  # 10 minute timeout

        if result["success"]:
            # Parse XML results
            scan_results = self._parse_nmap_xml(str(output_file))
            scan_results["raw_output"] = result["output"]
            scan_results["command"] = command
            return scan_results
        else:
            return {
                "success": False,
                "error": result["error"],
                "command": command
            }

    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse Nmap XML output"""
        import os

        # Check if XML file exists
        if not os.path.exists(xml_file):
            return {
                "success": False,
                "error": f"Nmap XML file not found: {xml_file}. Scan may have failed."
            }

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            results = {
                "success": True,
                "hosts": [],
                "summary": {}
            }

            for host in root.findall('.//host'):
                # Get host status
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    host_info = {
                        "ip": "",
                        "hostname": "",
                        "state": "up",
                        "os": "",
                        "ports": []
                    }

                    # Get IP address
                    address = host.find('.//address[@addrtype="ipv4"]')
                    if address is not None:
                        host_info["ip"] = address.get('addr', '')

                    # Get hostname
                    hostname = host.find('.//hostname')
                    if hostname is not None:
                        host_info["hostname"] = hostname.get('name', '')

                    # Get OS
                    os_match = host.find('.//osmatch')
                    if os_match is not None:
                        host_info["os"] = os_match.get('name', '')

                    # Get ports
                    for port in host.findall('.//port'):
                        port_id = port.get('portid', '')
                        protocol = port.get('protocol', '')

                        state = port.find('state')
                        service = port.find('service')

                        if state is not None:
                            port_info = {
                                "port": port_id,
                                "protocol": protocol,
                                "state": state.get('state', ''),
                                "service": service.get('name', '') if service is not None else '',
                                "version": service.get('version', '') if service is not None else '',
                                "product": service.get('product', '') if service is not None else ''
                            }

                            host_info["ports"].append(port_info)

                    results["hosts"].append(host_info)

            # Summary
            results["summary"] = {
                "total_hosts": len(results["hosts"]),
                "total_open_ports": sum(len(h["ports"]) for h in results["hosts"])
            }

            return results

        except Exception as e:
            return {
                "success": False,
                "error": f"Error parsing Nmap XML: {str(e)}"
            }

    def nikto_scan(self, target: str, port: int = 80, ssl: bool = False) -> Dict:
        """
        Run Nikto web server scan

        Args:
            target: Target host
            port: Target port
            ssl: Use SSL/TLS

        Returns:
            Scan results
        """
        if not self.is_tool_available("nikto"):
            return {"success": False, "error": "Nikto not available"}

        protocol = "https" if ssl else "http"
        output_file = self.scans_dir / f"nikto_{target.replace('.', '_')}_{port}.txt"

        command = f"nikto -h {protocol}://{target}:{port} -o {output_file}"

        result = self.executor.execute(command, timeout=600)

        return {
            "success": result["success"],
            "output": result["output"],
            "error": result.get("error", ""),
            "output_file": str(output_file),
            "command": command
        }

    def run_custom_scan(self, tool: str, target: str, options: str = "") -> Dict:
        """
        Run a custom scan with any tool

        Args:
            tool: Tool name (nmap, nikto, sqlmap, etc.)
            target: Target
            options: Tool options

        Returns:
            Scan results
        """
        if not self.is_tool_available(tool):
            return {"success": False, "error": f"{tool} not available"}

        command = f"{tool} {options} {target}"
        result = self.executor.execute(command, timeout=600)

        return {
            "success": result["success"],
            "output": result["output"],
            "error": result.get("error", ""),
            "command": command
        }

    def scan_target(self, target_id: str, target_manager, scan_profile: str = "quick") -> Dict:
        """
        Scan a target from target manager

        Args:
            target_id: Target ID
            target_manager: TargetManager instance
            scan_profile: Scan profile to use

        Returns:
            Scan results
        """
        target = target_manager.get_target(target_id)
        if not target:
            return {"success": False, "error": "Target not found"}

        host = target.get("host", "")
        ports = target.get("ports", "")

        # Run scan
        results = self.nmap_scan(host, scan_type=scan_profile, ports=ports)

        # Update target with findings
        if results.get("success"):
            for host_result in results.get("hosts", []):
                for port in host_result.get("ports", []):
                    if port.get("state") == "open":
                        service = port.get("service", "")
                        version = port.get("version", "")

                        finding_title = f"Open Port: {port.get('port')}/{port.get('protocol')}"
                        finding_desc = f"Service: {service}"
                        if version:
                            finding_desc += f" Version: {version}"

                        target_manager.add_finding(
                            target_id,
                            title=finding_title,
                            description=finding_desc,
                            severity="info"
                        )

        return results

    def schedule_scan(self, target: str, scan_type: str, interval_hours: int = 24):
        """
        Schedule periodic scanning (placeholder for future cron integration)

        Args:
            target: Target to scan
            scan_type: Type of scan
            interval_hours: Hours between scans
        """
        # This would integrate with cron or a task scheduler
        # For now, return a command to add to cron
        cron_command = f"0 */{interval_hours} * * * kali-gpt-scan {target} {scan_type}"

        return {
            "message": "To schedule this scan, add the following to crontab:",
            "command": cron_command,
            "note": "Automatic scheduling not yet implemented"
        }

    def get_available_scanners(self) -> List[str]:
        """Get list of available scanning tools"""
        common_scanners = [
            "nmap", "nikto", "sqlmap", "wpscan", "dirb",
            "gobuster", "ffuf", "wfuzz", "nuclei", "masscan"
        ]

        available = []
        for scanner in common_scanners:
            if self.is_tool_available(scanner):
                available.append(scanner)

        return available

    def get_scan_history(self) -> List[Dict]:
        """Get history of scans performed"""
        scans = []

        for scan_file in self.scans_dir.glob("*"):
            scans.append({
                "filename": scan_file.name,
                "path": str(scan_file),
                "modified": scan_file.stat().st_mtime,
                "size": scan_file.stat().st_size
            })

        # Sort by modification time (newest first)
        scans.sort(key=lambda x: x["modified"], reverse=True)

        return scans
