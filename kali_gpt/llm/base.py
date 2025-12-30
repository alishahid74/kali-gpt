"""
LLM Provider Abstraction Layer

Supports multiple LLM backends:
- Ollama (local, free)
- OpenAI (cloud, paid)
- Groq (cloud, free tier)
- Custom/Fine-tuned models
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, AsyncGenerator
from enum import Enum
import asyncio


class LLMProvider(str, Enum):
    """Supported LLM providers"""
    OLLAMA = "ollama"
    OPENAI = "openai"
    GROQ = "groq"
    ANTHROPIC = "anthropic"
    LOCAL = "local"  # Custom local model


@dataclass
class LLMConfig:
    """Configuration for LLM providers"""
    provider: LLMProvider = LLMProvider.OLLAMA
    model: str = "llama3.2"
    base_url: str = "http://localhost:11434"
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    top_p: float = 0.9
    timeout: int = 120
    retry_attempts: int = 3
    stream: bool = False
    
    # Security-specific settings
    system_prompt: Optional[str] = None
    context_window: int = 8192
    

@dataclass
class LLMMessage:
    """Represents a message in conversation"""
    role: str  # "system", "user", "assistant"
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Response from LLM"""
    content: str
    model: str
    provider: LLMProvider
    tokens_used: int = 0
    finish_reason: str = "stop"
    raw_response: Optional[Dict] = None
    
    # For autonomous agent
    thought: Optional[str] = None  # Internal reasoning
    action: Optional[str] = None   # Decided action
    action_input: Optional[str] = None  # Action parameters


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.conversation_history: List[LLMMessage] = []
        
    @abstractmethod
    async def generate(
        self, 
        prompt: str, 
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """Generate a response from the LLM"""
        pass
    
    @abstractmethod
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Generate streaming response"""
        pass
    
    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the provider is available"""
        pass
    
    def add_to_history(self, message: LLMMessage):
        """Add message to conversation history"""
        self.conversation_history.append(message)
        
        # Trim history if too long (keep last N messages)
        max_history = 20
        if len(self.conversation_history) > max_history:
            # Always keep system message if present
            system_msgs = [m for m in self.conversation_history if m.role == "system"]
            other_msgs = [m for m in self.conversation_history if m.role != "system"]
            self.conversation_history = system_msgs + other_msgs[-(max_history-len(system_msgs)):]
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
    
    def get_history_as_messages(self) -> List[Dict[str, str]]:
        """Get history formatted for API calls"""
        return [{"role": m.role, "content": m.content} for m in self.conversation_history]


# Security-focused system prompts
SECURITY_SYSTEM_PROMPTS = {
    "autonomous_pentester": """You are an autonomous penetration testing AI agent. Your role is to:

1. THINK: Analyze the current situation and available information
2. PLAN: Decide on the next logical action in the penetration testing methodology
3. ACT: Specify the exact command or action to take
4. OBSERVE: Analyze results and update your understanding

You follow the standard penetration testing methodology:
- Reconnaissance (passive and active)
- Scanning and enumeration
- Vulnerability analysis
- Exploitation
- Post-exploitation
- Reporting

IMPORTANT RULES:
- Only test systems you have explicit authorization to test
- Always stay within the defined scope
- Document all findings
- Prioritize stealth when required
- Follow ethical hacking guidelines

When responding, use this format:
THOUGHT: [Your reasoning about the current situation]
PLAN: [Your plan for the next steps]
ACTION: [The specific action to take - tool name]
ACTION_INPUT: [The exact command or parameters]
OBSERVATION: [What you expect to learn]
""",

    "recon_specialist": """You are a reconnaissance specialist AI. Focus on:
- OSINT gathering
- Subdomain enumeration
- Port scanning
- Service identification
- Technology fingerprinting

Be thorough but stealthy. Prioritize passive reconnaissance before active scanning.
""",

    "exploit_specialist": """You are an exploitation specialist AI. Focus on:
- Vulnerability identification
- Exploit selection and customization
- Payload generation
- Exploitation execution
- Initial access establishment

Always verify vulnerabilities before exploitation. Prefer reliable exploits over destructive ones.
""",

    "web_specialist": """You are a web application security specialist AI. Focus on:
- OWASP Top 10 vulnerabilities
- Authentication and session management flaws
- Injection vulnerabilities (SQL, XSS, Command injection)
- Business logic flaws
- API security testing

Use a methodical approach to web application testing.
""",
}
