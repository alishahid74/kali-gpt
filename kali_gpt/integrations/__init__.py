"""External tool integrations"""

from .metasploit import MetasploitIntegration
from .vulnerability_db import VulnerabilityDatabase
from .scanner import ScannerManager
from .collaboration import CollaborationManager

__all__ = [
    'MetasploitIntegration',
    'VulnerabilityDatabase',
    'ScannerManager',
    'CollaborationManager'
]
