#!/usr/bin/env python3
"""
Secure Input Validation Module
Prevents command injection and validates all user inputs

SECURITY: This module provides defense-in-depth validation for all user-controllable
parameters passed to security tools. It implements allowlist-based validation to
prevent command injection attacks (CWE-78).

Version: 1.0.0
Last Updated: 2026-11-05
"""

import re
import ipaddress
from typing import Optional, List
from pathlib import Path
from urllib.parse import urlparse


class InputValidationError(Exception):
    """Raised when input validation fails"""
    pass


class SecureInputValidator:
    """
    Validates and sanitizes all user inputs before they're used in commands.
    Uses allowlist-based validation - only explicitly permitted characters/patterns.
    """

    # Allowlist patterns
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}\.[a-zA-Z]{2,}$')
    PORT_PATTERN = re.compile(r'^[0-9]{1,5}$')
    PORT_RANGE_PATTERN = re.compile(r'^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$')
    CIDR_PATTERN = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$')
    SAFE_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9/_\-\.]+$')
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')

    # Known safe wordlist paths
    ALLOWED_WORDLIST_DIRS = [
        '/usr/share/wordlists/',
        '/usr/share/seclists/',
        '/usr/share/dirb/',
        '/usr/share/dirbuster/',
        '/opt/SecLists/',
    ]

    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """
        Validate IP address (IPv4 or IPv6)

        Args:
            ip: IP address string

        Returns:
            Validated IP address

        Raises:
            InputValidationError: If IP is invalid
        """
        if not ip or not isinstance(ip, str):
            raise InputValidationError("IP address cannot be empty")

        try:
            # This will raise ValueError if invalid
            ipaddress.ip_address(ip.strip())
            return ip.strip()
        except ValueError as e:
            raise InputValidationError(f"Invalid IP address '{ip}': {e}")

    @staticmethod
    def validate_cidr(cidr: str) -> str:
        """
        Validate CIDR notation (e.g., 192.168.1.0/24)

        Args:
            cidr: CIDR string

        Returns:
            Validated CIDR

        Raises:
            InputValidationError: If CIDR is invalid
        """
        if not cidr or not isinstance(cidr, str):
            raise InputValidationError("CIDR cannot be empty")

        try:
            ipaddress.ip_network(cidr.strip(), strict=False)
            return cidr.strip()
        except ValueError as e:
            raise InputValidationError(f"Invalid CIDR '{cidr}': {e}")

    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """
        Validate hostname (RFC 1123)

        Args:
            hostname: Hostname string

        Returns:
            Validated hostname

        Raises:
            InputValidationError: If hostname is invalid
        """
        if not hostname or not isinstance(hostname, str):
            raise InputValidationError("Hostname cannot be empty")

        hostname = hostname.strip()

        if len(hostname) > 255:
            raise InputValidationError(f"Hostname too long (max 255 chars): {hostname}")

        if not SecureInputValidator.HOSTNAME_PATTERN.match(hostname):
            raise InputValidationError(f"Invalid hostname '{hostname}': must contain only letters, numbers, dots, and hyphens")

        return hostname

    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Validate domain name

        Args:
            domain: Domain string

        Returns:
            Validated domain

        Raises:
            InputValidationError: If domain is invalid
        """
        if not domain or not isinstance(domain, str):
            raise InputValidationError("Domain cannot be empty")

        domain = domain.strip().lower()

        if not SecureInputValidator.DOMAIN_PATTERN.match(domain):
            raise InputValidationError(f"Invalid domain '{domain}': must be a valid domain name")

        return domain

    @staticmethod
    def validate_target(target: str) -> str:
        """
        Validate target (IP, hostname, or CIDR)

        Args:
            target: Target string

        Returns:
            Validated target

        Raises:
            InputValidationError: If target is invalid
        """
        if not target or not isinstance(target, str):
            raise InputValidationError("Target cannot be empty")

        target = target.strip()

        # Try IP
        try:
            return SecureInputValidator.validate_ip_address(target)
        except InputValidationError:
            pass

        # Try CIDR
        try:
            return SecureInputValidator.validate_cidr(target)
        except InputValidationError:
            pass

        # Try hostname
        try:
            return SecureInputValidator.validate_hostname(target)
        except InputValidationError:
            pass

        raise InputValidationError(f"Invalid target '{target}': must be IP, CIDR, or hostname")

    @staticmethod
    def validate_port(port: str) -> str:
        """
        Validate single port number

        Args:
            port: Port string

        Returns:
            Validated port

        Raises:
            InputValidationError: If port is invalid
        """
        if not port or not isinstance(port, str):
            raise InputValidationError("Port cannot be empty")

        port = port.strip()

        if not SecureInputValidator.PORT_PATTERN.match(port):
            raise InputValidationError(f"Invalid port '{port}': must be 1-5 digits")

        port_int = int(port)
        if port_int < 1 or port_int > 65535:
            raise InputValidationError(f"Invalid port '{port}': must be 1-65535")

        return port

    @staticmethod
    def validate_port_range(ports: str) -> str:
        """
        Validate port range (e.g., "80,443" or "1-1000" or "22,80-100,443")

        Args:
            ports: Port range string

        Returns:
            Validated port range

        Raises:
            InputValidationError: If port range is invalid
        """
        if not ports or not isinstance(ports, str):
            raise InputValidationError("Port range cannot be empty")

        ports = ports.strip()

        if not SecureInputValidator.PORT_RANGE_PATTERN.match(ports):
            raise InputValidationError(f"Invalid port range '{ports}': must be numbers, commas, and hyphens only")

        # Validate each port/range
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-', 1)
                SecureInputValidator.validate_port(start)
                SecureInputValidator.validate_port(end)
            else:
                SecureInputValidator.validate_port(part)

        return ports

    @staticmethod
    def validate_url(url: str, require_http: bool = True) -> str:
        """
        Validate URL

        Args:
            url: URL string
            require_http: If True, require http:// or https://

        Returns:
            Validated URL

        Raises:
            InputValidationError: If URL is invalid
        """
        if not url or not isinstance(url, str):
            raise InputValidationError("URL cannot be empty")

        url = url.strip()

        try:
            parsed = urlparse(url)

            if require_http and parsed.scheme not in ('http', 'https'):
                raise InputValidationError(f"Invalid URL '{url}': must start with http:// or https://")

            if not parsed.netloc:
                raise InputValidationError(f"Invalid URL '{url}': missing hostname")

            # Validate hostname part
            hostname = parsed.hostname
            if hostname:
                try:
                    # Try as IP
                    ipaddress.ip_address(hostname)
                except ValueError:
                    # Must be hostname
                    if not SecureInputValidator.HOSTNAME_PATTERN.match(hostname):
                        raise InputValidationError(f"Invalid hostname in URL: {hostname}")

            return url
        except Exception as e:
            raise InputValidationError(f"Invalid URL '{url}': {e}")

    @staticmethod
    def validate_file_path(path: str, must_exist: bool = False, allowed_dirs: Optional[List[str]] = None) -> str:
        """
        Validate file path

        Args:
            path: File path string
            must_exist: If True, file must exist
            allowed_dirs: List of allowed directory prefixes

        Returns:
            Validated path

        Raises:
            InputValidationError: If path is invalid
        """
        if not path or not isinstance(path, str):
            raise InputValidationError("File path cannot be empty")

        path = path.strip()

        # Block path traversal
        if '..' in path:
            raise InputValidationError(f"Path traversal detected in '{path}'")

        # Must use safe characters
        if not SecureInputValidator.SAFE_PATH_PATTERN.match(path):
            raise InputValidationError(f"Invalid path '{path}': contains unsafe characters")

        p = Path(path)

        # Check if in allowed directories
        if allowed_dirs:
            allowed = False
            for allowed_dir in allowed_dirs:
                if str(p).startswith(allowed_dir):
                    allowed = True
                    break
            if not allowed:
                raise InputValidationError(f"Path '{path}' not in allowed directories: {allowed_dirs}")

        # Check existence
        if must_exist and not p.exists():
            raise InputValidationError(f"File not found: {path}")

        return path

    @staticmethod
    def validate_wordlist_path(path: str) -> str:
        """
        Validate wordlist file path

        Args:
            path: Wordlist path

        Returns:
            Validated path

        Raises:
            InputValidationError: If path is invalid
        """
        return SecureInputValidator.validate_file_path(
            path,
            must_exist=True,
            allowed_dirs=SecureInputValidator.ALLOWED_WORDLIST_DIRS
        )

    @staticmethod
    def validate_alphanumeric(value: str, name: str = "value") -> str:
        """
        Validate alphanumeric string (letters, numbers, underscore, hyphen only)

        Args:
            value: String to validate
            name: Name for error messages

        Returns:
            Validated string

        Raises:
            InputValidationError: If string is invalid
        """
        if not value or not isinstance(value, str):
            raise InputValidationError(f"{name} cannot be empty")

        value = value.strip()

        if not SecureInputValidator.ALPHANUMERIC_PATTERN.match(value):
            raise InputValidationError(f"Invalid {name} '{value}': must contain only letters, numbers, underscore, and hyphen")

        return value

    @staticmethod
    def validate_username(username: str) -> str:
        """Validate username (alphanumeric + underscore + hyphen)"""
        return SecureInputValidator.validate_alphanumeric(username, "username")

    @staticmethod
    def validate_service_name(service: str) -> str:
        """Validate service name"""
        # Allowlist of known services
        ALLOWED_SERVICES = {
            'ssh', 'ftp', 'telnet', 'smtp', 'http', 'https', 'mysql', 'postgresql',
            'rdp', 'vnc', 'smb', 'snmp', 'ldap', 'pop3', 'imap', 'http-post-form',
            'http-get', 'http-head'
        }

        service = service.strip().lower()

        if service not in ALLOWED_SERVICES:
            raise InputValidationError(f"Unknown service '{service}'. Allowed: {', '.join(sorted(ALLOWED_SERVICES))}")

        return service

    @staticmethod
    def validate_severity(severity: str) -> str:
        """Validate severity level"""
        ALLOWED_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}

        severity = severity.strip().lower()

        if severity not in ALLOWED_SEVERITIES:
            raise InputValidationError(f"Invalid severity '{severity}'. Allowed: {', '.join(sorted(ALLOWED_SEVERITIES))}")

        return severity

    @staticmethod
    def validate_scan_type(scan_type: str) -> str:
        """Validate scan type"""
        ALLOWED_SCAN_TYPES = {'quick', 'full', 'vuln', 'stealth', 'image', 'fs', 'repo', 'config'}

        scan_type = scan_type.strip().lower()

        if scan_type not in ALLOWED_SCAN_TYPES:
            raise InputValidationError(f"Invalid scan type '{scan_type}'. Allowed: {', '.join(sorted(ALLOWED_SCAN_TYPES))}")

        return scan_type


# Convenience validator instance
validator = SecureInputValidator()
