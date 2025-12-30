"""
LLM Factory - Automatic Provider Selection

Automatically selects the best available LLM provider:
1. Ollama (local) - preferred for privacy/cost
2. OpenAI (cloud) - fallback if local unavailable
3. Groq (cloud) - fast inference, free tier
"""

import asyncio
import os
from typing import Optional, List

from .base import (
    BaseLLMProvider,
    LLMConfig,
    LLMProvider,
    LLMResponse,
    SECURITY_SYSTEM_PROMPTS
)
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider


class LLMFactory:
    """Factory for creating and managing LLM providers"""
    
    def __init__(self):
        self._providers: dict[LLMProvider, BaseLLMProvider] = {}
        self._active_provider: Optional[BaseLLMProvider] = None
        self._config: Optional[LLMConfig] = None
    
    async def initialize(
        self,
        preferred_provider: LLMProvider = LLMProvider.OLLAMA,
        config: Optional[LLMConfig] = None,
        auto_fallback: bool = True
    ) -> BaseLLMProvider:
        """
        Initialize LLM with automatic fallback
        
        Args:
            preferred_provider: Preferred LLM provider
            config: LLM configuration
            auto_fallback: If True, try other providers if preferred is unavailable
            
        Returns:
            Active LLM provider
        """
        self._config = config or LLMConfig()
        
        # Provider priority order
        provider_order = [
            LLMProvider.OLLAMA,
            LLMProvider.OPENAI,
            LLMProvider.GROQ
        ]
        
        # Move preferred to front
        if preferred_provider in provider_order:
            provider_order.remove(preferred_provider)
            provider_order.insert(0, preferred_provider)
        
        # Try each provider
        for provider_type in provider_order:
            try:
                provider = await self._create_provider(provider_type)
                
                if provider and await provider.is_available():
                    self._active_provider = provider
                    self._providers[provider_type] = provider
                    print(f"[+] Using LLM provider: {provider_type.value}")
                    return provider
                    
            except Exception as e:
                print(f"[!] Provider {provider_type.value} failed: {e}")
            
            if not auto_fallback:
                break
        
        raise RuntimeError("No LLM provider available! Please install Ollama or set OPENAI_API_KEY")
    
    async def _create_provider(self, provider_type: LLMProvider) -> Optional[BaseLLMProvider]:
        """Create a specific provider instance"""
        
        config = LLMConfig(
            provider=provider_type,
            model=self._config.model if self._config else "llama3.2",
            temperature=self._config.temperature if self._config else 0.7,
            max_tokens=self._config.max_tokens if self._config else 4096,
            system_prompt=self._config.system_prompt if self._config else None
        )
        
        if provider_type == LLMProvider.OLLAMA:
            config.base_url = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            config.model = os.getenv("OLLAMA_MODEL", config.model or "llama3.2")
            return OllamaProvider(config)
            
        elif provider_type == LLMProvider.OPENAI:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                return None
            config.api_key = api_key
            config.model = os.getenv("OPENAI_MODEL", config.model or "gpt-4o-mini")
            return OpenAIProvider(config)
            
        # Add more providers here (Groq, Anthropic, etc.)
        
        return None
    
    @property
    def provider(self) -> BaseLLMProvider:
        """Get the active provider"""
        if not self._active_provider:
            raise RuntimeError("LLM not initialized. Call initialize() first.")
        return self._active_provider
    
    async def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate response using active provider"""
        return await self.provider.generate(prompt, **kwargs)
    
    async def generate_stream(self, prompt: str, **kwargs):
        """Generate streaming response"""
        async for chunk in self.provider.generate_stream(prompt, **kwargs):
            yield chunk
    
    def set_system_prompt(self, prompt_name: str):
        """Set system prompt from predefined security prompts"""
        if prompt_name in SECURITY_SYSTEM_PROMPTS:
            self.provider.config.system_prompt = SECURITY_SYSTEM_PROMPTS[prompt_name]
        else:
            raise ValueError(f"Unknown prompt: {prompt_name}. Available: {list(SECURITY_SYSTEM_PROMPTS.keys())}")
    
    def clear_history(self):
        """Clear conversation history"""
        if self._active_provider:
            self._active_provider.clear_history()
    
    async def switch_provider(self, provider_type: LLMProvider) -> bool:
        """Switch to a different provider"""
        if provider_type in self._providers:
            self._active_provider = self._providers[provider_type]
            return True
        
        try:
            provider = await self._create_provider(provider_type)
            if provider and await provider.is_available():
                self._providers[provider_type] = provider
                self._active_provider = provider
                return True
        except Exception:
            pass
        
        return False
    
    async def close(self):
        """Close all providers"""
        for provider in self._providers.values():
            if hasattr(provider, 'close'):
                await provider.close()


# Singleton instance
_llm_factory: Optional[LLMFactory] = None


async def get_llm(
    preferred_provider: LLMProvider = LLMProvider.OLLAMA,
    config: Optional[LLMConfig] = None,
    reinitialize: bool = False
) -> LLMFactory:
    """
    Get or create the global LLM factory instance
    
    Usage:
        llm = await get_llm()
        response = await llm.generate("What is SQL injection?")
    """
    global _llm_factory
    
    if _llm_factory is None or reinitialize:
        _llm_factory = LLMFactory()
        await _llm_factory.initialize(preferred_provider, config)
    
    return _llm_factory


# Quick helper functions
async def ask(prompt: str, system_prompt: Optional[str] = None) -> str:
    """Quick helper to ask a question"""
    llm = await get_llm()
    response = await llm.generate(prompt, system_prompt=system_prompt)
    return response.content


async def ask_security(prompt: str, specialist: str = "autonomous_pentester") -> LLMResponse:
    """Ask a security-focused question"""
    llm = await get_llm()
    system_prompt = SECURITY_SYSTEM_PROMPTS.get(specialist, SECURITY_SYSTEM_PROMPTS["autonomous_pentester"])
    return await llm.generate(prompt, system_prompt=system_prompt)
