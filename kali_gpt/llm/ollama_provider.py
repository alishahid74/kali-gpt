"""
Ollama LLM Provider

Local LLM inference using Ollama
Free, private, no API key required
"""

import httpx
import asyncio
import json
from typing import Optional, AsyncGenerator, Dict, Any, List

from .base import (
    BaseLLMProvider, 
    LLMConfig, 
    LLMResponse, 
    LLMMessage,
    LLMProvider
)


class OllamaProvider(BaseLLMProvider):
    """
    Ollama provider for local LLM inference
    
    Supports models like:
    - llama3.2 (recommended for general use)
    - llama3.2:70b (larger, more capable)
    - codellama (good for code/commands)
    - mistral (good reasoning)
    - mixtral (mixture of experts)
    - deepseek-coder (code specialist)
    - phi3 (small but capable)
    """
    
    # Recommended models for security tasks
    RECOMMENDED_MODELS = {
        "general": "llama3.2",
        "code": "codellama:13b",
        "reasoning": "mistral",
        "large": "llama3.2:70b",
        "small": "phi3",
        "fast": "llama3.2:1b"
    }
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=config.timeout)
        
    async def is_available(self) -> bool:
        """Check if Ollama server is running and model is available"""
        try:
            # Check if server is running
            response = await self.client.get(f"{self.base_url}/api/tags")
            if response.status_code != 200:
                return False
            
            # Check if our model is available
            data = response.json()
            available_models = [m["name"] for m in data.get("models", [])]
            
            # Check both exact match and base model name
            model_base = self.config.model.split(":")[0]
            return any(
                self.config.model in m or model_base in m 
                for m in available_models
            )
            
        except Exception as e:
            print(f"[!] Ollama not available: {e}")
            return False
    
    async def list_models(self) -> List[str]:
        """List available models"""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return []
    
    async def pull_model(self, model_name: str) -> bool:
        """Pull/download a model"""
        try:
            print(f"[*] Pulling model {model_name}... This may take a while.")
            
            async with self.client.stream(
                "POST",
                f"{self.base_url}/api/pull",
                json={"name": model_name},
                timeout=None  # No timeout for large downloads
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        data = json.loads(line)
                        status = data.get("status", "")
                        if "pulling" in status:
                            # Show progress
                            completed = data.get("completed", 0)
                            total = data.get("total", 0)
                            if total > 0:
                                pct = (completed / total) * 100
                                print(f"\r[*] Downloading: {pct:.1f}%", end="", flush=True)
                        elif status == "success":
                            print(f"\n[+] Model {model_name} pulled successfully!")
                            return True
            return True
        except Exception as e:
            print(f"\n[!] Failed to pull model: {e}")
            return False
    
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        include_history: bool = True,
        **kwargs
    ) -> LLMResponse:
        """Generate response using Ollama"""
        
        # Build messages
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
        
        # Build request payload
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "top_p": kwargs.get("top_p", self.config.top_p),
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
            }
        }
        
        try:
            response = await self.client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.config.timeout
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama API error: {response.status_code} - {response.text}")
            
            data = response.json()
            content = data.get("message", {}).get("content", "")
            
            # Parse ReAct format if present
            thought, action, action_input = self._parse_react_response(content)
            
            # Update history
            self.add_to_history(LLMMessage(role="user", content=prompt))
            self.add_to_history(LLMMessage(role="assistant", content=content))
            
            return LLMResponse(
                content=content,
                model=self.config.model,
                provider=LLMProvider.OLLAMA,
                tokens_used=data.get("eval_count", 0),
                finish_reason=data.get("done_reason", "stop"),
                raw_response=data,
                thought=thought,
                action=action,
                action_input=action_input
            )
            
        except httpx.TimeoutException:
            raise Exception(f"Ollama request timed out after {self.config.timeout}s")
        except Exception as e:
            raise Exception(f"Ollama generation failed: {str(e)}")
    
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
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "top_p": kwargs.get("top_p", self.config.top_p),
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
            }
        }
        
        full_response = ""
        
        try:
            async with self.client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.config.timeout
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        data = json.loads(line)
                        if "message" in data:
                            chunk = data["message"].get("content", "")
                            full_response += chunk
                            yield chunk
            
            # Update history after streaming completes
            self.add_to_history(LLMMessage(role="user", content=prompt))
            self.add_to_history(LLMMessage(role="assistant", content=full_response))
            
        except Exception as e:
            yield f"\n[ERROR] Streaming failed: {str(e)}"
    
    def _parse_react_response(self, content: str) -> tuple:
        """Parse ReAct format response (THOUGHT, ACTION, ACTION_INPUT)"""
        thought = None
        action = None
        action_input = None
        
        lines = content.split('\n')
        current_section = None
        current_content = []
        
        for line in lines:
            line_upper = line.upper().strip()
            
            if line_upper.startswith("THOUGHT:"):
                if current_section and current_content:
                    self._assign_section(current_section, '\n'.join(current_content))
                current_section = "thought"
                current_content = [line.split(":", 1)[1].strip() if ":" in line else ""]
            elif line_upper.startswith("ACTION:"):
                if current_section and current_content:
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
        
        # Handle last section
        if current_section == "thought":
            thought = '\n'.join(current_content).strip()
        elif current_section == "action":
            action = '\n'.join(current_content).strip()
        elif current_section == "action_input":
            action_input = '\n'.join(current_content).strip()
        
        return thought, action, action_input
    
    def _assign_section(self, section: str, content: str):
        """Helper to assign section content"""
        pass  # Used in parsing logic
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


class OllamaModelManager:
    """Utility class to manage Ollama models"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30)
    
    async def get_running_models(self) -> List[Dict]:
        """Get currently loaded/running models"""
        try:
            response = await self.client.get(f"{self.base_url}/api/ps")
            if response.status_code == 200:
                return response.json().get("models", [])
        except Exception:
            pass
        return []
    
    async def get_model_info(self, model_name: str) -> Optional[Dict]:
        """Get detailed info about a model"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/show",
                json={"name": model_name}
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None
    
    async def delete_model(self, model_name: str) -> bool:
        """Delete a model"""
        try:
            response = await self.client.delete(
                f"{self.base_url}/api/delete",
                json={"name": model_name}
            )
            return response.status_code == 200
        except Exception:
            return False
    
    async def close(self):
        await self.client.aclose()
