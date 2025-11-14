"""Input validation utilities"""

import re
from typing import Tuple, List

class CommandValidator:
    """Validates and sanitizes shell commands"""

    DANGEROUS_KEYWORDS = [
        'rm -rf',
        'dd if=',
        'mkfs',
        ':(){:|:&};:',
        'fork bomb',
        '> /dev/sda',
        '> /dev/sd',
        'mkfs.ext',
        ':(){ :|:& };:',
        'shutdown',
        'reboot',
        'init 0',
        'init 6'
    ]

    INJECTION_PATTERNS = [
        r';\s*rm\s+-rf',
        r'&&\s*rm\s+-rf',
        r'\|\s*rm\s+-rf',
        r'`.*rm\s+-rf.*`',
        r'\$\(.*rm\s+-rf.*\)',
    ]

    @classmethod
    def is_dangerous(cls, command: str) -> Tuple[bool, str]:
        """
        Check if command contains dangerous keywords
        Returns: (is_dangerous, reason)
        """
        command_lower = command.lower()

        # Check dangerous keywords
        for keyword in cls.DANGEROUS_KEYWORDS:
            if keyword in command_lower:
                return True, f"Contains dangerous keyword: {keyword}"

        # Check injection patterns
        for pattern in cls.INJECTION_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"Potential command injection detected"

        return False, ""

    @classmethod
    def sanitize_input(cls, user_input: str) -> str:
        """Sanitize user input to prevent basic injection attacks"""
        # Remove null bytes
        sanitized = user_input.replace('\x00', '')

        # Remove control characters except newlines and tabs
        sanitized = ''.join(char for char in sanitized
                          if char.isprintable() or char in '\n\t')

        return sanitized.strip()

    @classmethod
    def validate_ip(cls, ip_address: str) -> bool:
        """Validate IP address format"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip_address))

    @classmethod
    def validate_port(cls, port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False

    @classmethod
    def validate_domain(cls, domain: str) -> bool:
        """Validate domain name format"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
