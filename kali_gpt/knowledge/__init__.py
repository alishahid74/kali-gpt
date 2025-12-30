"""
Knowledge Module

Contains:
- MITRE ATT&CK framework integration
- Intelligent tool chaining
- Attack playbooks
"""

from .mitre_attack import (
    MITREKnowledgeBase,
    get_mitre_kb,
    Tactic,
    Technique,
    AttackStep,
    AttackChain
)

from .tool_chains import (
    ToolChainBuilder,
    ToolChain,
    ToolChainStep,
    DiscoveredService,
    ServiceType
)

__all__ = [
    # MITRE ATT&CK
    "MITREKnowledgeBase",
    "get_mitre_kb",
    "Tactic",
    "Technique",
    "AttackStep",
    "AttackChain",
    
    # Tool Chaining
    "ToolChainBuilder",
    "ToolChain",
    "ToolChainStep",
    "DiscoveredService",
    "ServiceType"
]
