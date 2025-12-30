"""
Memory Module - Persistent Storage

SQLite-based persistent memory for:
- Engagement history
- Vulnerability records
- Successful patterns for learning
- Target fingerprinting
"""

from .store import (
    MemoryStore,
    EngagementRecord,
    VulnerabilityRecord,
    ActionPattern
)

__all__ = [
    "MemoryStore",
    "EngagementRecord",
    "VulnerabilityRecord",
    "ActionPattern"
]
