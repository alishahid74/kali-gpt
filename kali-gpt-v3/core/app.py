"""
Kali-GPT v3 Core Application

Main application class that orchestrates:
- LLM initialization
- Tool execution
- Autonomous agent
- Memory management
"""

import asyncio
import os
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Awaitable
from dataclasses import dataclass

from .llm import LLMFactory, LLMConfig, LLMProvider, get_llm, SECURITY_SYSTEM_PROMPTS
from .agents import (
    AutonomousAgent, 
    AgentState, 
    AgentAction, 
    AgentObservation,
    AgentThought,
    EngagementContext,
    PentestPhase
)
from .tools import ToolExecutor, AsyncToolExecutor
from .memory import MemoryStore


@dataclass
class AppConfig:
    """Application configuration"""
    # LLM settings
    llm_provider: LLMProvider = LLMProvider.OLLAMA
    llm_model: str = "llama3.2"
    llm_temperature: float = 0.7
    
    # Execution settings
    require_confirmation: bool = True
    max_iterations: int = 100
    default_timeout: int = 300
    
    # Memory settings
    enable_memory: bool = True
    memory_db_path: Optional[str] = None
    
    # Agent settings
    autonomous_mode: bool = False
    specialist_mode: str = "autonomous_pentester"
    
    # Paths
    config_dir: str = str(Path.home() / ".kali-gpt-v3")


class KaliGPTApp:
    """
    Main Kali-GPT v3 Application
    
    Provides:
    - Easy initialization
    - LLM abstraction
    - Tool execution
    - Autonomous agent control
    - Memory/learning
    """
    
    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        
        # Core components (initialized lazily)
        self._llm: Optional[LLMFactory] = None
        self._tool_executor: Optional[ToolExecutor] = None
        self._memory: Optional[MemoryStore] = None
        self._agent: Optional[AutonomousAgent] = None
        
        # State
        self._initialized = False
        self._current_engagement_id: Optional[int] = None
        
        # Ensure config directory exists
        Path(self.config.config_dir).mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> bool:
        """Initialize all components"""
        if self._initialized:
            return True
        
        try:
            # Initialize LLM
            print("[*] Initializing LLM...")
            llm_config = LLMConfig(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                temperature=self.config.llm_temperature,
                system_prompt=SECURITY_SYSTEM_PROMPTS.get(
                    self.config.specialist_mode,
                    SECURITY_SYSTEM_PROMPTS["autonomous_pentester"]
                )
            )
            
            self._llm = await get_llm(
                preferred_provider=self.config.llm_provider,
                config=llm_config
            )
            print(f"[+] LLM initialized: {self._llm.provider.config.provider.value}")
            
            # Initialize tool executor
            print("[*] Initializing tool executor...")
            self._tool_executor = AsyncToolExecutor({
                "default_timeout": self.config.default_timeout,
                "require_confirmation": self.config.require_confirmation
            })
            
            # Check available tools
            available_tools = await self._tool_executor.get_available_tools()
            print(f"[+] Available tools: {len(available_tools)}")
            
            # Initialize memory
            if self.config.enable_memory:
                print("[*] Initializing memory store...")
                db_path = self.config.memory_db_path or str(
                    Path(self.config.config_dir) / "memory.db"
                )
                self._memory = MemoryStore(db_path)
                await self._memory.initialize()
                print("[+] Memory store initialized")
            
            self._initialized = True
            return True
            
        except Exception as e:
            print(f"[!] Initialization failed: {e}")
            return False
    
    @property
    def llm(self) -> LLMFactory:
        """Get LLM instance"""
        if not self._llm:
            raise RuntimeError("App not initialized. Call initialize() first.")
        return self._llm
    
    @property
    def tool_executor(self) -> AsyncToolExecutor:
        """Get tool executor"""
        if not self._tool_executor:
            raise RuntimeError("App not initialized. Call initialize() first.")
        return self._tool_executor
    
    @property
    def memory(self) -> Optional[MemoryStore]:
        """Get memory store"""
        return self._memory
    
    async def ask(self, prompt: str, **kwargs) -> str:
        """Simple query to the LLM"""
        response = await self.llm.generate(prompt, **kwargs)
        return response.content
    
    async def execute_tool(self, command: str, **kwargs) -> Dict[str, Any]:
        """Execute a tool/command"""
        return await self.tool_executor.execute(
            tool=command,
            command=command,
            **kwargs
        )
    
    async def start_engagement(
        self,
        target: str,
        scope: list = None,
        autonomous: bool = None,
        **kwargs
    ) -> AutonomousAgent:
        """
        Start a new penetration testing engagement
        
        Args:
            target: Primary target (IP, domain, URL)
            scope: List of in-scope targets
            autonomous: Run autonomously (override config)
            **kwargs: Additional engagement parameters
            
        Returns:
            AutonomousAgent instance
        """
        if not self._initialized:
            await self.initialize()
        
        # Create engagement in memory
        if self._memory:
            self._current_engagement_id = await self._memory.create_engagement(
                target=target,
                metadata={
                    "scope": scope or [target],
                    "autonomous": autonomous if autonomous is not None else self.config.autonomous_mode,
                    **kwargs
                }
            )
        
        # Create agent
        self._agent = AutonomousAgent(
            llm=self.llm,
            tool_executor=self.tool_executor
        )
        
        # Initialize agent
        await self._agent.initialize(
            target=target,
            scope=scope,
            **kwargs
        )
        
        return self._agent
    
    async def run_autonomous(
        self,
        target: str,
        scope: list = None,
        on_state_change: Callable[[AgentState], Awaitable[None]] = None,
        on_thought: Callable[[AgentThought], Awaitable[None]] = None,
        on_action: Callable[[AgentAction], Awaitable[bool]] = None,
        on_observation: Callable[[AgentObservation], Awaitable[None]] = None,
        **kwargs
    ) -> EngagementContext:
        """
        Run a full autonomous penetration test
        
        Args:
            target: Primary target
            scope: In-scope targets
            on_*: Callback functions for events
            **kwargs: Additional parameters
            
        Returns:
            EngagementContext with results
        """
        agent = await self.start_engagement(target, scope, **kwargs)
        
        # Set callbacks
        if on_state_change:
            agent.on_state_change = on_state_change
        if on_thought:
            agent.on_thought = on_thought
        if on_action:
            agent.on_action = on_action
        if on_observation:
            agent.on_observation = on_observation
        
        # Run
        context = await agent.run(autonomous=True)
        
        # Save results to memory
        if self._memory and self._current_engagement_id:
            await self._memory.update_engagement(
                self._current_engagement_id,
                end_time=context.start_time.isoformat(),
                phase_reached=context.current_phase.value,
                total_actions=len(context.actions_taken),
                vulnerabilities_found=len(context.discovered_vulnerabilities)
            )
        
        return context
    
    async def interactive_step(self) -> Optional[AgentObservation]:
        """Execute a single step in interactive mode"""
        if not self._agent:
            raise RuntimeError("No active engagement. Call start_engagement() first.")
        
        return await self._agent.step()
    
    def pause_agent(self):
        """Pause the autonomous agent"""
        if self._agent:
            self._agent.pause()
    
    def resume_agent(self):
        """Resume the autonomous agent"""
        if self._agent:
            self._agent.resume()
    
    def stop_agent(self):
        """Stop the autonomous agent"""
        if self._agent:
            self._agent.stop()
    
    async def get_recommendations(self, target: str) -> Dict[str, Any]:
        """Get recommendations based on past engagements"""
        if not self._memory:
            return {"error": "Memory not enabled"}
        
        # Find similar engagements
        similar = await self._memory.get_similar_engagements(target)
        
        # Get fingerprint
        fingerprint = self._memory._generate_fingerprint(target)
        
        # Get successful patterns
        patterns = await self._memory.get_successful_patterns(fingerprint)
        
        return {
            "similar_engagements": len(similar),
            "past_results": [
                {
                    "target": e.target,
                    "vulnerabilities": e.vulnerabilities_found,
                    "phase_reached": e.phase_reached
                }
                for e in similar
            ],
            "recommended_actions": [
                {
                    "tool": p.tool,
                    "command": p.command_pattern,
                    "success_rate": p.success_rate
                }
                for p in patterns
            ]
        }
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        if not self._memory:
            return {"error": "Memory not enabled"}
        
        return await self._memory.get_statistics()
    
    def set_specialist_mode(self, mode: str):
        """Change the specialist mode"""
        if mode in SECURITY_SYSTEM_PROMPTS:
            self.config.specialist_mode = mode
            if self._llm:
                self._llm.set_system_prompt(mode)
        else:
            raise ValueError(f"Unknown mode: {mode}. Available: {list(SECURITY_SYSTEM_PROMPTS.keys())}")
    
    async def close(self):
        """Clean up resources"""
        if self._llm:
            await self._llm.close()


# Singleton app instance
_app: Optional[KaliGPTApp] = None


async def get_app(config: Optional[AppConfig] = None) -> KaliGPTApp:
    """Get or create the global app instance"""
    global _app
    
    if _app is None:
        _app = KaliGPTApp(config)
        await _app.initialize()
    
    return _app
