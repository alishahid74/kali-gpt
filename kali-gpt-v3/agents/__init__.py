"""
Agents Module - Autonomous Penetration Testing Agents

Contains:
- AutonomousAgent: Main ReAct-based agent
- EnhancedAutonomousAgent: MITRE ATT&CK integrated agent
- Specialized agents for different phases
"""

from .autonomous_agent import (
    AutonomousAgent,
    AgentState,
    AgentAction,
    AgentObservation,
    AgentThought,
    EngagementContext,
    PentestPhase
)

from .enhanced_agent import (
    EnhancedAutonomousAgent,
    EnhancedEngagementContext
)

__all__ = [
    # Base agent
    "AutonomousAgent",
    "AgentState",
    "AgentAction",
    "AgentObservation",
    "AgentThought",
    "EngagementContext",
    "PentestPhase",
    
    # Enhanced agent
    "EnhancedAutonomousAgent",
    "EnhancedEngagementContext"
]
