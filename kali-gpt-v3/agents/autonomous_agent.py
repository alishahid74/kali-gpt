"""
Autonomous Pentesting Agent

Implements the ReAct (Reasoning + Acting) pattern for autonomous penetration testing.
The agent can:
- Observe the current state
- Think about what to do next
- Take actions (run tools)
- Learn from results
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Awaitable
from enum import Enum
from datetime import datetime
import json


class AgentState(str, Enum):
    """States of the autonomous agent"""
    IDLE = "idle"
    THINKING = "thinking"
    PLANNING = "planning"
    EXECUTING = "executing"
    OBSERVING = "observing"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class PentestPhase(str, Enum):
    """Penetration testing phases (based on PTES)"""
    PRE_ENGAGEMENT = "pre_engagement"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class AgentAction:
    """Represents an action the agent can take"""
    name: str
    tool: str
    command: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    expected_outcome: str = ""
    risk_level: str = "low"  # low, medium, high, critical
    requires_confirmation: bool = False


@dataclass
class AgentObservation:
    """Observation/result from an action"""
    action: AgentAction
    success: bool
    output: str
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    findings: List[Dict] = field(default_factory=list)
    next_actions_suggested: List[str] = field(default_factory=list)


@dataclass
class EngagementContext:
    """Context for the current penetration test engagement"""
    target: str
    scope: List[str] = field(default_factory=list)  # In-scope targets
    out_of_scope: List[str] = field(default_factory=list)
    engagement_type: str = "black_box"  # black_box, grey_box, white_box
    rules_of_engagement: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    
    # Discovered information
    discovered_hosts: List[Dict] = field(default_factory=list)
    discovered_services: List[Dict] = field(default_factory=list)
    discovered_vulnerabilities: List[Dict] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    
    # Current state
    current_phase: PentestPhase = PentestPhase.RECONNAISSANCE
    actions_taken: List[AgentAction] = field(default_factory=list)
    observations: List[AgentObservation] = field(default_factory=list)
    
    def to_summary(self) -> str:
        """Generate a summary of current engagement state"""
        return f"""
=== Engagement Summary ===
Target: {self.target}
Phase: {self.current_phase.value}
Duration: {datetime.now() - self.start_time}

Discovered:
- Hosts: {len(self.discovered_hosts)}
- Services: {len(self.discovered_services)}  
- Vulnerabilities: {len(self.discovered_vulnerabilities)}
- Credentials: {len(self.credentials_found)}

Actions taken: {len(self.actions_taken)}
"""


@dataclass
class AgentThought:
    """Represents the agent's reasoning process"""
    situation_analysis: str
    available_options: List[str]
    chosen_action: str
    reasoning: str
    confidence: float = 0.8
    alternative_actions: List[str] = field(default_factory=list)


class AutonomousAgent:
    """
    Core autonomous penetration testing agent
    
    Implements ReAct (Reasoning + Acting) pattern:
    1. OBSERVE: Gather information about current state
    2. THINK: Analyze situation and plan next steps
    3. ACT: Execute the chosen action
    4. LEARN: Update knowledge based on results
    """
    
    def __init__(
        self,
        llm,  # LLMFactory instance
        tool_executor,  # ToolExecutor instance
        context: Optional[EngagementContext] = None
    ):
        self.llm = llm
        self.tool_executor = tool_executor
        self.context = context or EngagementContext(target="")
        self.state = AgentState.IDLE
        self.max_iterations = 100
        self.current_iteration = 0
        
        # Callbacks for UI integration
        self.on_state_change: Optional[Callable[[AgentState], Awaitable[None]]] = None
        self.on_thought: Optional[Callable[[AgentThought], Awaitable[None]]] = None
        self.on_action: Optional[Callable[[AgentAction], Awaitable[bool]]] = None  # Returns True to proceed
        self.on_observation: Optional[Callable[[AgentObservation], Awaitable[None]]] = None
        
        # Control flags
        self._paused = False
        self._stopped = False
    
    async def initialize(self, target: str, scope: List[str] = None, **kwargs):
        """Initialize the agent for a new engagement"""
        self.context = EngagementContext(
            target=target,
            scope=scope or [target],
            engagement_type=kwargs.get("engagement_type", "black_box"),
            rules_of_engagement=kwargs.get("rules", {})
        )
        self.state = AgentState.IDLE
        self.current_iteration = 0
        self._paused = False
        self._stopped = False
        
        # Set up LLM with security system prompt
        self.llm.set_system_prompt("autonomous_pentester")
    
    async def run(self, autonomous: bool = True) -> EngagementContext:
        """
        Main agent loop
        
        Args:
            autonomous: If True, runs autonomously. If False, requires confirmation for each action.
        """
        if not self.context.target:
            raise ValueError("No target specified. Call initialize() first.")
        
        await self._set_state(AgentState.THINKING)
        
        while not self._should_stop():
            self.current_iteration += 1
            
            if self._paused:
                await self._set_state(AgentState.PAUSED)
                await asyncio.sleep(1)
                continue
            
            try:
                # 1. OBSERVE: Understand current state
                await self._set_state(AgentState.OBSERVING)
                situation = await self._observe()
                
                # 2. THINK: Decide what to do
                await self._set_state(AgentState.THINKING)
                thought = await self._think(situation)
                
                if self.on_thought:
                    await self.on_thought(thought)
                
                # 3. PLAN: Convert thought to action
                await self._set_state(AgentState.PLANNING)
                action = await self._plan(thought)
                
                if action is None:
                    # No more actions needed
                    break
                
                # Check if confirmation needed
                if not autonomous or action.requires_confirmation:
                    if self.on_action:
                        proceed = await self.on_action(action)
                        if not proceed:
                            continue
                
                # 4. ACT: Execute the action
                await self._set_state(AgentState.EXECUTING)
                observation = await self._act(action)
                
                if self.on_observation:
                    await self.on_observation(observation)
                
                # 5. LEARN: Update context based on results
                await self._learn(observation)
                
            except Exception as e:
                await self._set_state(AgentState.ERROR)
                print(f"[!] Agent error: {e}")
                # Try to recover
                await asyncio.sleep(2)
        
        await self._set_state(AgentState.COMPLETED)
        return self.context
    
    async def _set_state(self, state: AgentState):
        """Update agent state and notify callbacks"""
        self.state = state
        if self.on_state_change:
            await self.on_state_change(state)
    
    def _should_stop(self) -> bool:
        """Check if agent should stop"""
        if self._stopped:
            return True
        if self.current_iteration >= self.max_iterations:
            print(f"[!] Max iterations ({self.max_iterations}) reached")
            return True
        if self.context.current_phase == PentestPhase.REPORTING:
            return True
        return False
    
    async def _observe(self) -> str:
        """Gather information about current state"""
        observation = f"""
Current Engagement State:
- Target: {self.context.target}
- Phase: {self.context.current_phase.value}
- Iteration: {self.current_iteration}

Discovered Information:
- Hosts: {json.dumps(self.context.discovered_hosts[-5:], indent=2) if self.context.discovered_hosts else "None yet"}
- Services: {json.dumps(self.context.discovered_services[-10:], indent=2) if self.context.discovered_services else "None yet"}
- Vulnerabilities: {json.dumps(self.context.discovered_vulnerabilities[-5:], indent=2) if self.context.discovered_vulnerabilities else "None yet"}

Recent Actions:
{self._format_recent_actions()}

Recent Observations:
{self._format_recent_observations()}
"""
        return observation
    
    def _format_recent_actions(self) -> str:
        """Format recent actions for context"""
        if not self.context.actions_taken:
            return "No actions taken yet"
        
        recent = self.context.actions_taken[-5:]
        return "\n".join([
            f"- {a.tool}: {a.command or a.name} (Risk: {a.risk_level})"
            for a in recent
        ])
    
    def _format_recent_observations(self) -> str:
        """Format recent observations for context"""
        if not self.context.observations:
            return "No observations yet"
        
        recent = self.context.observations[-3:]
        formatted = []
        for obs in recent:
            status = "✓" if obs.success else "✗"
            output_preview = obs.output[:200] + "..." if len(obs.output) > 200 else obs.output
            formatted.append(f"- [{status}] {obs.action.tool}: {output_preview}")
        
        return "\n".join(formatted)
    
    async def _think(self, situation: str) -> AgentThought:
        """Use LLM to reason about the situation"""
        
        prompt = f"""
Based on the current penetration testing engagement state, decide the next action.

{situation}

Current Phase: {self.context.current_phase.value}

Consider:
1. What information do we still need?
2. What is the logical next step in the methodology?
3. Are there any quick wins based on what we've discovered?
4. What tools would be most effective?

Provide your response in this format:
THOUGHT: [Your analysis of the current situation]
PLAN: [Your plan for the next 2-3 steps]
ACTION: [The specific tool to use next]
ACTION_INPUT: [The exact command to run]
OBSERVATION: [What you expect to find]
"""
        
        response = await self.llm.generate(prompt)
        
        # Parse the response
        thought = AgentThought(
            situation_analysis=response.thought or "Analyzing situation...",
            available_options=self._get_available_tools(),
            chosen_action=response.action or "",
            reasoning=response.content,
            confidence=0.8
        )
        
        return thought
    
    async def _plan(self, thought: AgentThought) -> Optional[AgentAction]:
        """Convert thought into concrete action"""
        
        if not thought.chosen_action:
            # Ask LLM to be more specific
            prompt = f"""
Based on your analysis: {thought.reasoning}

Please specify the EXACT command to run. Format:
ACTION: [tool name]
ACTION_INPUT: [complete command with all parameters]
"""
            response = await self.llm.generate(prompt)
            thought.chosen_action = response.action or ""
        
        if not thought.chosen_action:
            return None
        
        # Determine risk level
        risk_level = self._assess_risk(thought.chosen_action)
        
        action = AgentAction(
            name=f"Step {self.current_iteration}",
            tool=thought.chosen_action,
            command=self._extract_command(thought.reasoning),
            reasoning=thought.situation_analysis,
            expected_outcome=thought.reasoning,
            risk_level=risk_level,
            requires_confirmation=risk_level in ["high", "critical"]
        )
        
        return action
    
    async def _act(self, action: AgentAction) -> AgentObservation:
        """Execute the action"""
        
        # Record the action
        self.context.actions_taken.append(action)
        
        # Execute via tool executor
        result = await self.tool_executor.execute(
            tool=action.tool,
            command=action.command,
            parameters=action.parameters
        )
        
        observation = AgentObservation(
            action=action,
            success=result.get("success", False),
            output=result.get("output", ""),
            error=result.get("error"),
            findings=result.get("findings", [])
        )
        
        self.context.observations.append(observation)
        
        return observation
    
    async def _learn(self, observation: AgentObservation):
        """Update knowledge based on observation"""
        
        # Ask LLM to extract findings
        if observation.success and observation.output:
            prompt = f"""
Analyze this penetration testing output and extract key findings:

Tool: {observation.action.tool}
Command: {observation.action.command}
Output:
```
{observation.output[:3000]}
```

Extract:
1. Discovered hosts (IP addresses)
2. Discovered services (port, service name, version)
3. Potential vulnerabilities
4. Credentials or sensitive information
5. Recommended next steps

Format as JSON:
{{
    "hosts": [...],
    "services": [...],
    "vulnerabilities": [...],
    "credentials": [...],
    "next_steps": [...]
}}
"""
            
            response = await self.llm.generate(prompt, include_history=False)
            
            # Try to parse findings
            try:
                # Extract JSON from response
                content = response.content
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                
                findings = json.loads(content)
                
                # Update context with findings
                if findings.get("hosts"):
                    self.context.discovered_hosts.extend(findings["hosts"])
                if findings.get("services"):
                    self.context.discovered_services.extend(findings["services"])
                if findings.get("vulnerabilities"):
                    self.context.discovered_vulnerabilities.extend(findings["vulnerabilities"])
                if findings.get("credentials"):
                    self.context.credentials_found.extend(findings["credentials"])
                
                observation.findings = findings
                observation.next_actions_suggested = findings.get("next_steps", [])
                
            except json.JSONDecodeError:
                # LLM didn't return valid JSON, continue anyway
                pass
        
        # Check if we should advance to next phase
        await self._check_phase_transition()
    
    async def _check_phase_transition(self):
        """Check if we should move to the next phase"""
        current = self.context.current_phase
        
        # Simple phase transition logic
        if current == PentestPhase.RECONNAISSANCE:
            if len(self.context.discovered_hosts) > 0:
                self.context.current_phase = PentestPhase.SCANNING
                
        elif current == PentestPhase.SCANNING:
            if len(self.context.discovered_services) > 5:
                self.context.current_phase = PentestPhase.ENUMERATION
                
        elif current == PentestPhase.ENUMERATION:
            if len(self.context.discovered_services) > 10:
                self.context.current_phase = PentestPhase.VULNERABILITY_ANALYSIS
                
        elif current == PentestPhase.VULNERABILITY_ANALYSIS:
            if len(self.context.discovered_vulnerabilities) > 0:
                self.context.current_phase = PentestPhase.EXPLOITATION
    
    def _get_available_tools(self) -> List[str]:
        """Get list of available tools for current phase"""
        phase_tools = {
            PentestPhase.RECONNAISSANCE: [
                "nmap", "whois", "dig", "theHarvester", "amass", 
                "subfinder", "assetfinder", "httpx"
            ],
            PentestPhase.SCANNING: [
                "nmap", "masscan", "rustscan", "unicornscan"
            ],
            PentestPhase.ENUMERATION: [
                "nmap", "enum4linux", "smbmap", "gobuster", "ffuf",
                "nikto", "whatweb", "wpscan"
            ],
            PentestPhase.VULNERABILITY_ANALYSIS: [
                "nmap", "nikto", "nuclei", "searchsploit", "vulners"
            ],
            PentestPhase.EXPLOITATION: [
                "msfconsole", "sqlmap", "hydra", "john", "hashcat"
            ],
            PentestPhase.POST_EXPLOITATION: [
                "linpeas", "winpeas", "mimikatz", "bloodhound"
            ]
        }
        
        return phase_tools.get(self.context.current_phase, [])
    
    def _assess_risk(self, tool: str) -> str:
        """Assess risk level of a tool/action"""
        high_risk_tools = ["msfconsole", "sqlmap", "hydra", "mimikatz"]
        medium_risk_tools = ["nmap", "nikto", "nuclei", "gobuster"]
        
        tool_lower = tool.lower()
        
        if any(t in tool_lower for t in high_risk_tools):
            return "high"
        elif any(t in tool_lower for t in medium_risk_tools):
            return "medium"
        return "low"
    
    def _extract_command(self, reasoning: str) -> Optional[str]:
        """Extract command from reasoning text"""
        # Look for common command patterns
        lines = reasoning.split('\n')
        for line in lines:
            line = line.strip()
            # Look for ACTION_INPUT or command-like patterns
            if line.startswith("ACTION_INPUT:"):
                return line.replace("ACTION_INPUT:", "").strip()
            if line.startswith("ACTION INPUT:"):
                return line.replace("ACTION INPUT:", "").strip()
            # Look for backticks
            if line.startswith("`") and line.endswith("`"):
                return line.strip("`")
            # Look for common tool prefixes
            common_tools = ["nmap", "whois", "dig", "gobuster", "nikto", "sqlmap"]
            for tool in common_tools:
                if line.lower().startswith(tool):
                    return line
        
        return None
    
    # Control methods
    def pause(self):
        """Pause the agent"""
        self._paused = True
    
    def resume(self):
        """Resume the agent"""
        self._paused = False
    
    def stop(self):
        """Stop the agent"""
        self._stopped = True
    
    async def step(self) -> Optional[AgentObservation]:
        """Execute a single step (for manual mode)"""
        if self._should_stop():
            return None
        
        self.current_iteration += 1
        
        situation = await self._observe()
        thought = await self._think(situation)
        action = await self._plan(thought)
        
        if action is None:
            return None
        
        observation = await self._act(action)
        await self._learn(observation)
        
        return observation
