"""
Enhanced Autonomous Agent

Integrates:
- MITRE ATT&CK framework for methodology
- Intelligent tool chaining
- Learning from past engagements
- Adaptive decision making
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable, Awaitable
from datetime import datetime

from ..knowledge import (
    MITREKnowledgeBase,
    get_mitre_kb,
    Tactic,
    Technique,
    ToolChainBuilder,
    ToolChainStep,
    DiscoveredService
)
from ..memory import MemoryStore
from ..llm import LLMFactory, LLMResponse


@dataclass
class EnhancedEngagementContext:
    """Enhanced context with MITRE ATT&CK tracking"""
    target: str
    scope: List[str] = field(default_factory=list)
    engagement_type: str = "black_box"
    rules_of_engagement: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    
    # Discovery tracking
    discovered_hosts: List[Dict] = field(default_factory=list)
    discovered_services: List[DiscoveredService] = field(default_factory=list)
    discovered_vulnerabilities: List[Dict] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    
    # MITRE ATT&CK tracking
    current_tactic: Tactic = Tactic.RECONNAISSANCE
    tactics_completed: List[Tactic] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)  # Technique IDs
    attack_path: List[Dict] = field(default_factory=list)  # Ordered list of actions
    
    # Execution tracking
    actions_taken: List[Dict] = field(default_factory=list)
    tool_chain_queue: List[ToolChainStep] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)


class EnhancedAutonomousAgent:
    """
    Enhanced autonomous pentesting agent with MITRE ATT&CK integration
    
    Features:
    - MITRE ATT&CK-aligned methodology
    - Intelligent tool chaining
    - Learning from past engagements
    - Adaptive strategy based on findings
    """
    
    def __init__(
        self,
        llm: LLMFactory,
        tool_executor,
        memory: Optional[MemoryStore] = None
    ):
        self.llm = llm
        self.tool_executor = tool_executor
        self.memory = memory
        
        # Knowledge systems
        self.mitre_kb = get_mitre_kb()
        self.chain_builder = ToolChainBuilder()
        
        # State
        self.context: Optional[EnhancedEngagementContext] = None
        self.running = False
        self.paused = False
        self.current_iteration = 0
        self.max_iterations = 100
        
        # Callbacks
        self.on_status: Optional[Callable[[str], Awaitable[None]]] = None
        self.on_finding: Optional[Callable[[Dict], Awaitable[None]]] = None
        self.on_technique_used: Optional[Callable[[Technique], Awaitable[None]]] = None
        self.on_action_proposed: Optional[Callable[[ToolChainStep], Awaitable[bool]]] = None
    
    async def initialize(
        self,
        target: str,
        scope: List[str] = None,
        engagement_type: str = "black_box",
        **kwargs
    ):
        """Initialize for a new engagement"""
        
        self.context = EnhancedEngagementContext(
            target=target,
            scope=scope or [target],
            engagement_type=engagement_type,
            rules_of_engagement=kwargs.get("rules", {})
        )
        
        self.chain_builder = ToolChainBuilder()
        self.current_iteration = 0
        self.running = False
        self.paused = False
        
        # Load recommendations from past engagements
        if self.memory:
            recommendations = await self._get_past_recommendations()
            if recommendations:
                await self._notify_status(f"Found {len(recommendations)} recommendations from similar targets")
    
    async def _notify_status(self, message: str):
        """Send status update"""
        if self.on_status:
            await self.on_status(message)
    
    async def _get_past_recommendations(self) -> List[Dict]:
        """Get recommendations from past engagements"""
        if not self.memory:
            return []
        
        similar = await self.memory.get_similar_engagements(self.context.target)
        
        if not similar:
            return []
        
        # Get successful patterns
        fingerprint = self.memory._generate_fingerprint(self.context.target)
        patterns = await self.memory.get_successful_patterns(fingerprint)
        
        return [
            {
                "tool": p.tool,
                "command": p.command_pattern,
                "success_rate": p.success_rate,
                "times_used": p.times_used
            }
            for p in patterns
        ]
    
    async def run(self, autonomous: bool = True) -> EnhancedEngagementContext:
        """
        Run the autonomous engagement
        
        Args:
            autonomous: If True, runs without confirmation. If False, asks for each action.
        """
        if not self.context:
            raise ValueError("Not initialized. Call initialize() first.")
        
        self.running = True
        
        await self._notify_status(f"Starting engagement against {self.context.target}")
        await self._notify_status(f"Current tactic: {self.context.current_tactic.value}")
        
        # Phase 1: Initial reconnaissance
        await self._run_initial_recon(autonomous)
        
        # Phase 2: Service-specific enumeration
        await self._run_service_enumeration(autonomous)
        
        # Phase 3: Vulnerability analysis
        await self._run_vulnerability_analysis(autonomous)
        
        # Continue until stopped or completed
        while self.running and self.current_iteration < self.max_iterations:
            if self.paused:
                await asyncio.sleep(1)
                continue
            
            self.current_iteration += 1
            
            # Get next actions from tool chain
            next_steps = self._get_next_actions()
            
            if not next_steps:
                # Ask LLM for guidance
                next_steps = await self._ask_llm_for_next_steps()
            
            if not next_steps:
                await self._notify_status("No more actions available. Engagement complete.")
                break
            
            for step in next_steps:
                if not self.running:
                    break
                
                # Confirm action if not autonomous
                if not autonomous:
                    if self.on_action_proposed:
                        proceed = await self.on_action_proposed(step)
                        if not proceed:
                            continue
                
                # Execute the action
                result = await self._execute_step(step)
                
                # Process results
                await self._process_results(step, result)
                
                # Record technique usage
                if step.technique_id:
                    await self._record_technique(step.technique_id)
        
        self.running = False
        return self.context
    
    async def _run_initial_recon(self, autonomous: bool):
        """Run initial reconnaissance phase"""
        await self._notify_status("Phase 1: Initial Reconnaissance")
        self.context.current_tactic = Tactic.RECONNAISSANCE
        
        # Get initial recon chain
        recon_chain = self.chain_builder.get_initial_recon_chain(self.context.target)
        
        for step in recon_chain:
            if not self.running:
                break
            
            # Confirm if not autonomous
            if not autonomous and self.on_action_proposed:
                proceed = await self.on_action_proposed(step)
                if not proceed:
                    continue
            
            await self._notify_status(f"Running: {step.description}")
            
            result = await self._execute_step(step)
            await self._process_results(step, result)
            
            # Special handling for nmap results
            if step.tool == "nmap" and result.get("success"):
                services = self.chain_builder.parse_nmap_output(
                    result.get("output", ""),
                    self.context.target
                )
                self.context.discovered_services.extend(services)
                
                await self._notify_status(f"Discovered {len(services)} services")
                
                # Add services to context
                for svc in services:
                    self.context.discovered_hosts.append({
                        "host": svc.host,
                        "port": svc.port,
                        "service": svc.service.value,
                        "version": svc.version
                    })
    
    async def _run_service_enumeration(self, autonomous: bool):
        """Run service-specific enumeration"""
        await self._notify_status("Phase 2: Service Enumeration")
        self.context.current_tactic = Tactic.DISCOVERY
        
        # Get chains for each discovered service
        for service in self.context.discovered_services:
            if not self.running:
                break
            
            await self._notify_status(f"Enumerating {service.service.value} on port {service.port}")
            
            chain = self.chain_builder.get_chain_for_service(service, max_steps=3)
            
            for step in chain:
                if not self.running:
                    break
                
                if not autonomous and self.on_action_proposed:
                    proceed = await self.on_action_proposed(step)
                    if not proceed:
                        continue
                
                result = await self._execute_step(step)
                await self._process_results(step, result)
    
    async def _run_vulnerability_analysis(self, autonomous: bool):
        """Run vulnerability analysis"""
        await self._notify_status("Phase 3: Vulnerability Analysis")
        self.context.current_tactic = Tactic.RECONNAISSANCE  # T1595.002
        
        # Run nuclei for comprehensive vuln scanning
        if self.context.discovered_services:
            web_services = [
                s for s in self.context.discovered_services
                if s.service.value in ["http", "https"]
            ]
            
            for service in web_services:
                if not self.running:
                    break
                
                protocol = "https" if service.service.value == "https" else "http"
                target = f"{protocol}://{service.host}:{service.port}"
                
                step = ToolChainStep(
                    tool="nuclei",
                    command=f"nuclei -u {target} -severity medium,high,critical",
                    description=f"Vulnerability scan of {target}",
                    priority=1,
                    produces=["vulnerabilities"],
                    technique_id="T1595.002"
                )
                
                if not autonomous and self.on_action_proposed:
                    proceed = await self.on_action_proposed(step)
                    if not proceed:
                        continue
                
                result = await self._execute_step(step)
                await self._process_results(step, result)
    
    def _get_next_actions(self) -> List[ToolChainStep]:
        """Get next actions based on current state"""
        
        # Check tool chain queue first
        if self.context.tool_chain_queue:
            next_steps = self.context.tool_chain_queue[:3]
            self.context.tool_chain_queue = self.context.tool_chain_queue[3:]
            return next_steps
        
        # Get from chain builder based on findings
        completed = [a.get("tool", "") for a in self.context.actions_taken]
        return self.chain_builder.get_next_steps(completed, max_steps=3)
    
    async def _ask_llm_for_next_steps(self) -> List[ToolChainStep]:
        """Ask LLM for guidance on next steps"""
        
        # Build context for LLM
        context_summary = self._build_context_summary()
        
        prompt = f"""Based on the current penetration testing engagement state, suggest the next 2-3 actions.

{context_summary}

Available tools: nmap, nikto, gobuster, nuclei, sqlmap, hydra, enum4linux, smbmap, wpscan, ffuf

For each suggestion, provide:
1. Tool name
2. Complete command
3. What you expect to find
4. MITRE ATT&CK technique ID (if known)

Format your response as:
TOOL: [tool name]
COMMAND: [full command]
REASON: [why this action]
TECHNIQUE: [MITRE ID or "none"]
---
"""
        
        response = await self.llm.generate(prompt)
        
        # Parse LLM response into steps
        steps = self._parse_llm_suggestions(response.content)
        return steps
    
    def _build_context_summary(self) -> str:
        """Build a summary of current engagement state for LLM"""
        
        services_summary = "\n".join([
            f"  - {s.host}:{s.port} ({s.service.value}) {s.version or ''}"
            for s in self.context.discovered_services[:10]
        ]) or "  None discovered yet"
        
        vulns_summary = "\n".join([
            f"  - {v.get('type', 'Unknown')}: {v.get('description', '')[:50]}"
            for v in self.context.discovered_vulnerabilities[:5]
        ]) or "  None found yet"
        
        recent_actions = "\n".join([
            f"  - {a.get('tool', 'Unknown')}: {a.get('status', 'Unknown')}"
            for a in self.context.actions_taken[-5:]
        ]) or "  None yet"
        
        return f"""
Target: {self.context.target}
Current MITRE Tactic: {self.context.current_tactic.value}
Techniques Used: {', '.join(self.context.techniques_used[-5:]) or 'None'}

Discovered Services:
{services_summary}

Vulnerabilities Found:
{vulns_summary}

Recent Actions:
{recent_actions}

Iteration: {self.current_iteration}/{self.max_iterations}
"""
    
    def _parse_llm_suggestions(self, content: str) -> List[ToolChainStep]:
        """Parse LLM response into tool chain steps"""
        
        steps = []
        current_step = {}
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith("TOOL:"):
                if current_step.get("tool"):
                    steps.append(self._create_step_from_dict(current_step))
                current_step = {"tool": line.replace("TOOL:", "").strip()}
            elif line.startswith("COMMAND:"):
                current_step["command"] = line.replace("COMMAND:", "").strip()
            elif line.startswith("REASON:"):
                current_step["reason"] = line.replace("REASON:", "").strip()
            elif line.startswith("TECHNIQUE:"):
                tech = line.replace("TECHNIQUE:", "").strip()
                if tech.lower() != "none":
                    current_step["technique"] = tech
            elif line == "---":
                if current_step.get("tool"):
                    steps.append(self._create_step_from_dict(current_step))
                current_step = {}
        
        # Don't forget last step
        if current_step.get("tool"):
            steps.append(self._create_step_from_dict(current_step))
        
        return steps
    
    def _create_step_from_dict(self, data: Dict) -> ToolChainStep:
        """Create a ToolChainStep from parsed data"""
        return ToolChainStep(
            tool=data.get("tool", "unknown"),
            command=data.get("command", ""),
            description=data.get("reason", "LLM suggested action"),
            priority=5,
            technique_id=data.get("technique")
        )
    
    async def _execute_step(self, step: ToolChainStep) -> Dict[str, Any]:
        """Execute a tool chain step"""
        
        await self._notify_status(f"Executing: {step.tool}")
        
        result = await self.tool_executor.execute(
            tool=step.tool,
            command=step.command
        )
        
        # Record action
        self.context.actions_taken.append({
            "tool": step.tool,
            "command": step.command,
            "description": step.description,
            "technique_id": step.technique_id,
            "status": "success" if result.get("success") else "failed",
            "timestamp": datetime.now().isoformat()
        })
        
        return result
    
    async def _process_results(self, step: ToolChainStep, result: Dict[str, Any]):
        """Process results from a tool execution"""
        
        if not result.get("success"):
            await self._notify_status(f"Failed: {result.get('error', 'Unknown error')}")
            return
        
        output = result.get("output", "")
        
        # Ask LLM to extract findings
        if output and len(output) > 100:
            findings = await self._extract_findings(step, output)
            
            if findings:
                # Update context with findings
                for finding_type, finding_data in findings.items():
                    self.chain_builder.add_finding(finding_type, finding_data)
                    self.context.findings[finding_type] = finding_data
                    
                    if finding_type == "vulnerabilities" and finding_data:
                        self.context.discovered_vulnerabilities.extend(
                            [{"type": v, "source": step.tool} for v in finding_data]
                            if isinstance(finding_data, list) else [finding_data]
                        )
                
                if self.on_finding:
                    await self.on_finding(findings)
        
        # Record in memory for learning
        if self.memory:
            fingerprint = self.memory._generate_fingerprint(self.context.target)
            await self.memory.record_action_pattern(
                target_fingerprint=fingerprint,
                action_type=self.context.current_tactic.value,
                tool=step.tool,
                command_pattern=self._generalize_command(step.command),
                success=result.get("success", False),
                execution_time=result.get("execution_time", 0)
            )
    
    async def _extract_findings(self, step: ToolChainStep, output: str) -> Dict[str, Any]:
        """Use LLM to extract findings from tool output"""
        
        prompt = f"""Extract key findings from this {step.tool} output.

Output (truncated):
```
{output[:3000]}
```

Extract and categorize:
- IP addresses/hosts found
- Open ports/services
- Vulnerabilities identified
- Credentials or sensitive info
- Technologies detected
- Interesting paths/files

Return as JSON:
{{
    "hosts": [],
    "services": [],
    "vulnerabilities": [],
    "credentials": [],
    "technologies": [],
    "paths": [],
    "other": []
}}
"""
        
        response = await self.llm.generate(prompt, include_history=False)
        
        try:
            import json
            content = response.content
            
            # Extract JSON from response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            return json.loads(content)
        except:
            return {}
    
    def _generalize_command(self, command: str) -> str:
        """Generalize a command for pattern storage"""
        import re
        
        # Replace IPs with placeholder
        generalized = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '{IP}', command)
        
        # Replace domains with placeholder
        generalized = re.sub(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', '{DOMAIN}', generalized)
        
        # Replace ports with placeholder  
        generalized = re.sub(r':\d{2,5}', ':{PORT}', generalized)
        
        return generalized
    
    async def _record_technique(self, technique_id: str):
        """Record usage of a MITRE ATT&CK technique"""
        
        if technique_id not in self.context.techniques_used:
            self.context.techniques_used.append(technique_id)
            
            technique = self.mitre_kb.get_technique(technique_id)
            if technique and self.on_technique_used:
                await self.on_technique_used(technique)
    
    def pause(self):
        """Pause the agent"""
        self.paused = True
    
    def resume(self):
        """Resume the agent"""
        self.paused = False
    
    def stop(self):
        """Stop the agent"""
        self.running = False
    
    async def step(self) -> Optional[Dict]:
        """Execute a single step (for manual mode)"""
        
        next_steps = self._get_next_actions()
        
        if not next_steps:
            next_steps = await self._ask_llm_for_next_steps()
        
        if not next_steps:
            return None
        
        step = next_steps[0]
        result = await self._execute_step(step)
        await self._process_results(step, result)
        
        return {
            "step": step,
            "result": result
        }
    
    def get_attack_path(self) -> List[Dict]:
        """Get the current attack path with MITRE mappings"""
        
        path = []
        for action in self.context.actions_taken:
            technique_id = action.get("technique_id")
            technique = self.mitre_kb.get_technique(technique_id) if technique_id else None
            
            path.append({
                "tool": action.get("tool"),
                "command": action.get("command"),
                "status": action.get("status"),
                "timestamp": action.get("timestamp"),
                "mitre": {
                    "technique_id": technique_id,
                    "technique_name": technique.name if technique else None,
                    "tactic": technique.tactic.value if technique else None
                } if technique_id else None
            })
        
        return path
    
    def get_mitre_coverage(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK coverage statistics"""
        
        tactics_touched = set()
        techniques_by_tactic = {}
        
        for tech_id in self.context.techniques_used:
            technique = self.mitre_kb.get_technique(tech_id)
            if technique:
                tactic = technique.tactic.value
                tactics_touched.add(tactic)
                
                if tactic not in techniques_by_tactic:
                    techniques_by_tactic[tactic] = []
                techniques_by_tactic[tactic].append({
                    "id": tech_id,
                    "name": technique.name
                })
        
        return {
            "tactics_covered": list(tactics_touched),
            "techniques_used": len(self.context.techniques_used),
            "techniques_by_tactic": techniques_by_tactic
        }
