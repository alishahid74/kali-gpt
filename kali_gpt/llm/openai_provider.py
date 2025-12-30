"""
OpenAI LLM Provider

Cloud-based LLM using OpenAI API
Requires API key, paid usage
"""

import os
import asyncio
from typing import Optional, AsyncGenerator, Dict, Any, List

from .base import (
    BaseLLMProvider,
    LLMConfig,
    LLMResponse,
    LLMMessage,
    LLMProvider
)


class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI provider for cloud LLM inference
    
    Supports models like:
    - gpt-4o (recommended)
    - gpt-4o-mini (faster, cheaper)
    - gpt-4-turbo
    - gpt-3.5-turbo
    """
    
    RECOMMENDED_MODELS = {
        "best": "gpt-4o",
        "fast": "gpt-4o-mini", 
        "legacy": "gpt-4-turbo",
        "cheap": "gpt-3.5-turbo"
    }
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("OPENAI_API_KEY")
        self._client = None
        
    @property
    def client(self):
        """Lazy load OpenAI client"""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                self._client = AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("OpenAI package not installed. Run: pip install openai")
        return self._client
    
    async def is_available(self) -> bool:
        """Check if OpenAI API is accessible"""
        if not self.api_key:
            return False
        
        try:
            # Simple API test
            response = await self.client.models.list()
            return True
        except Exception as e:
            print(f"[!] OpenAI not available: {e}")
            return False
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        include_history: bool = True,
        **kwargs
    ) -> LLMResponse:
        """Generate response using OpenAI"""
        
        messages = []
        
        # Add system prompt
        if system_prompt or self.config.system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt or self.config.system_prompt
            })
        
        # Add conversation history
        if include_history and self.conversation_history:
            messages.extend(self.get_history_as_messages())
        
        # Add current prompt
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = await self.client.chat.completions.create(
                model=kwargs.get("model", self.config.model),
                messages=messages,
                temperature=kwargs.get("temperature", self.config.temperature),
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                top_p=kwargs.get("top_p", self.config.top_p),
            )
            
            content = response.choices[0].message.content
            
            # Parse ReAct format if present
            thought, action, action_input = self._parse_react_response(content)
            
            # Update history
            self.add_to_history(LLMMessage(role="user", content=prompt))
            self.add_to_history(LLMMessage(role="assistant", content=content))
            
            return LLMResponse(
                content=content,
                model=response.model,
                provider=LLMProvider.OPENAI,
                tokens_used=response.usage.total_tokens if response.usage else 0,
                finish_reason=response.choices[0].finish_reason,
                raw_response=response.model_dump(),
                thought=thought,
                action=action,
                action_input=action_input
            )
            
        except Exception as e:
            raise Exception(f"OpenAI generation failed: {str(e)}")
    
    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        include_history: bool = True,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Generate streaming response"""
        
        messages = []
        
        if system_prompt or self.config.system_prompt:
            messages.append({
                "role": "system", 
                "content": system_prompt or self.config.system_prompt
            })
        
        if include_history and self.conversation_history:
            messages.extend(self.get_history_as_messages())
        
        messages.append({"role": "user", "content": prompt})
        
        full_response = ""
        
        try:
            stream = await self.client.chat.completions.create(
                model=kwargs.get("model", self.config.model),
                messages=messages,
                temperature=kwargs.get("temperature", self.config.temperature),
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
                stream=True
            )
            
            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_response += content
                    yield content
            
            # Update history
            self.add_to_history(LLMMessage(role="user", content=prompt))
            self.add_to_history(LLMMessage(role="assistant", content=full_response))
            
        except Exception as e:
            yield f"\n[ERROR] Streaming failed: {str(e)}"
    
    def _parse_react_response(self, content: str) -> tuple:
        """Parse ReAct format response"""
        thought = None
        action = None
        action_input = None
        
        lines = content.split('\n')
        current_section = None
        current_content = []
        
        for line in lines:
            line_upper = line.upper().strip()
            
            if line_upper.startswith("THOUGHT:"):
                current_section = "thought"
                current_content = [line.split(":", 1)[1].strip() if ":" in line else ""]
            elif line_upper.startswith("ACTION:"):
                if current_section == "thought":
                    thought = '\n'.join(current_content).strip()
                current_section = "action"
                current_content = [line.split(":", 1)[1].strip() if ":" in line else ""]
            elif line_upper.startswith("ACTION_INPUT:") or line_upper.startswith("ACTION INPUT:"):
                if current_section == "action":
                    action = '\n'.join(current_content).strip()
                current_section = "action_input"
                current_content = [line.split(":", 1)[1].strip() if ":" in line else ""]
            elif current_section:
                current_content.append(line)
        
        if current_section == "thought":
            thought = '\n'.join(current_content).strip()
        elif current_section == "action":
            action = '\n'.join(current_content).strip()
        elif current_section == "action_input":
            action_input = '\n'.join(current_content).strip()
        
        return thought, action, action_input
