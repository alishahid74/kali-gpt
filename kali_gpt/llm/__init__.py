"""
LLM Module - Multi-provider LLM Support

Supports:
- Ollama (local, free, private)
- OpenAI (cloud, paid)
- Groq (cloud, free tier)
"""

from .base import (
    LLMProvider,
    LLMConfig,
    LLMMessage,
    LLMResponse,
    BaseLLMProvider,
    SECURITY_SYSTEM_PROMPTS
)

from .ollama_provider import OllamaProvider, OllamaModelManager
from .openai_provider import OpenAIProvider
from .factory import LLMFactory, get_llm, ask, ask_security

__all__ = [
    # Enums and configs
    "LLMProvider",
    "LLMConfig", 
    "LLMMessage",
    "LLMResponse",
    
    # Base class
    "BaseLLMProvider",
    
    # Providers
    "OllamaProvider",
    "OllamaModelManager",
    "OpenAIProvider",
    
    # Factory and helpers
    "LLMFactory",
    "get_llm",
    "ask",
    "ask_security",
    
    # Prompts
    "SECURITY_SYSTEM_PROMPTS",
]
