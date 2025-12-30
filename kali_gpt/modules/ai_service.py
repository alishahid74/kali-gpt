"""
AI Service Module - Enhanced with Local LLM Support

Supports:
- OpenAI (cloud, paid) - Original
- Ollama (local, free) - NEW!

Backward compatible with original AIService interface.
"""

import os
import httpx
import json
from typing import List, Dict, Optional, Any

# Try importing OpenAI, but don't fail if not installed
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    OpenAI = None


class AIService:
    """
    Handles all AI/LLM interactions
    
    Enhanced to support both OpenAI and Ollama (local LLM)
    """

    def __init__(self, config_manager=None, provider: str = "auto"):
        """
        Initialize AI service with configuration
        
        Args:
            config_manager: Configuration manager instance
            provider: "openai", "ollama", or "auto" (auto-detect)
        """
        self.config = config_manager
        self.conversation_history = []
        self.provider = provider
        
        # Auto-detect provider
        if provider == "auto":
            self.provider = self._detect_provider()
        
        # Initialize the appropriate client
        if self.provider == "openai":
            if not OPENAI_AVAILABLE:
                raise ImportError("OpenAI package not installed. Run: pip install openai")
            self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self._model = self._get_config("model", "gpt-4o")
        else:  # ollama
            self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            self._model = os.getenv("OLLAMA_MODEL", self._get_config("ollama_model", "llama3.2"))
            self.client = None
        
        print(f"[*] AI Service initialized with provider: {self.provider}")
        print(f"[*] Using model: {self._model}")

    def _detect_provider(self) -> str:
        """Auto-detect the best available provider"""
        # Check for Ollama first (free, local)
        if self._check_ollama():
            print("[+] Ollama detected - using local LLM (free)")
            return "ollama"
        
        # Fall back to OpenAI if API key exists
        if os.getenv("OPENAI_API_KEY") and OPENAI_AVAILABLE:
            print("[+] OpenAI API key found - using cloud LLM")
            return "openai"
        
        # Default to ollama and hope it works
        print("[!] No provider detected, defaulting to Ollama")
        return "ollama"

    def _check_ollama(self) -> bool:
        """Check if Ollama is running"""
        try:
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            response = httpx.get(f"{host}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def _get_config(self, key: str, default: Any = None) -> Any:
        """Get config value with fallback"""
        if self.config:
            return self.config.get(key, default)
        return default

    def ask(self, prompt: str, system_prompt: str = None,
            include_history: bool = True, max_history: int = 5) -> str:
        """
        Send a prompt to the AI and get a response
        
        Works with both OpenAI and Ollama!

        Args:
            prompt: User's question or task
            system_prompt: System/role prompt for the AI
            include_history: Whether to include conversation history
            max_history: Maximum number of history items to include

        Returns:
            AI's response as a string
        """
        messages = []

        # Add system prompt
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        # Add conversation history
        if include_history and self.conversation_history:
            recent_history = self.conversation_history[-max_history:]
            for item in recent_history:
                messages.append({"role": "user", "content": item["user"]})
                messages.append({"role": "assistant", "content": item["assistant"]})

        # Add current prompt
        messages.append({"role": "user", "content": prompt})

        try:
            if self.provider == "openai":
                response = self._ask_openai(messages)
            else:
                response = self._ask_ollama(messages)

            # Store in conversation history
            self.conversation_history.append({
                "user": prompt,
                "assistant": response
            })

            return response

        except Exception as e:
            error_msg = f"AI request failed: {str(e)}"
            print(f"[!] {error_msg}")
            return error_msg

    def _ask_openai(self, messages: List[Dict]) -> str:
        """Send request to OpenAI"""
        temperature = self._get_config("temperature", 0.7)
        max_tokens = self._get_config("max_tokens", 2000)

        response = self.client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )

        return response.choices[0].message.content

    def _ask_ollama(self, messages: List[Dict]) -> str:
        """Send request to Ollama (local LLM)"""
        temperature = self._get_config("temperature", 0.7)
        
        payload = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }

        try:
            response = httpx.post(
                f"{self.ollama_host}/api/chat",
                json=payload,
                timeout=120  # Longer timeout for local inference
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama error: {response.status_code}")
            
            data = response.json()
            return data.get("message", {}).get("content", "")
            
        except httpx.ConnectError:
            raise Exception(
                "Cannot connect to Ollama. Make sure it's running:\n"
                "  1. Install: curl -fsSL https://ollama.com/install.sh | sh\n"
                "  2. Pull model: ollama pull llama3.2\n"
                "  3. Start: ollama serve"
            )

    def generate_command(self, task: str, context: str = None) -> Dict[str, str]:
        """
        Generate a command for a security task
        
        Args:
            task: Description of what needs to be done
            context: Additional context about the target/environment

        Returns:
            Dict with 'command' and 'explanation' keys
        """
        system_prompt = """You are an expert penetration testing assistant. 
Generate precise, safe commands for security testing tasks.
Only generate commands for authorized security testing.
Always explain what the command does."""

        prompt = f"Task: {task}"
        if context:
            prompt += f"\nContext: {context}"
        prompt += "\n\nProvide the command and a brief explanation."

        response = self.ask(prompt, system_prompt=system_prompt, include_history=False)

        # Parse response
        lines = response.strip().split('\n')
        command = ""
        explanation = ""

        for i, line in enumerate(lines):
            if line.startswith("```"):
                # Extract command from code block
                for j in range(i + 1, len(lines)):
                    if lines[j].startswith("```"):
                        break
                    command += lines[j] + "\n"
            elif "command:" in line.lower():
                command = line.split(":", 1)[1].strip()
            elif any(word in line.lower() for word in ["explanation", "this command", "this will"]):
                explanation = line

        return {
            "command": command.strip() or response,
            "explanation": explanation or "Command generated by AI"
        }

    def analyze_output(self, command: str, output: str) -> str:
        """
        Analyze command output for security findings
        
        Args:
            command: The command that was executed
            output: The command's output

        Returns:
            Analysis of the output
        """
        system_prompt = """You are a security analyst reviewing penetration testing output.
Identify:
1. Key findings (open ports, services, vulnerabilities)
2. Potential attack vectors
3. Recommended next steps
Be concise and actionable."""

        prompt = f"""Command executed: {command}

Output:
```
{output[:3000]}  
```

Analyze this output and identify security findings."""

        return self.ask(prompt, system_prompt=system_prompt, include_history=False)

    def suggest_next_action(self, findings: str, current_phase: str = "reconnaissance") -> str:
        """
        Suggest the next action based on findings
        
        Args:
            findings: Current findings/discoveries
            current_phase: Current phase of testing

        Returns:
            Suggested next action with command
        """
        system_prompt = """You are an expert penetration tester. 
Based on current findings, suggest the most logical next step.
Follow standard methodology: recon -> scanning -> enumeration -> exploitation.
Provide a specific command to run."""

        prompt = f"""Current Phase: {current_phase}

Findings so far:
{findings}

What should be the next step? Provide a specific command."""

        return self.ask(prompt, system_prompt=system_prompt)

    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []

    def switch_provider(self, provider: str):
        """
        Switch between OpenAI and Ollama
        
        Args:
            provider: "openai" or "ollama"
        """
        if provider not in ["openai", "ollama"]:
            raise ValueError("Provider must be 'openai' or 'ollama'")
        
        self.provider = provider
        
        if provider == "openai":
            if not OPENAI_AVAILABLE:
                raise ImportError("OpenAI package not installed")
            self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self._model = self._get_config("model", "gpt-4o")
        else:
            self._model = os.getenv("OLLAMA_MODEL", "llama3.2")
            self.client = None
        
        print(f"[*] Switched to {provider} provider, model: {self._model}")

    def get_provider_info(self) -> Dict[str, str]:
        """Get current provider information"""
        return {
            "provider": self.provider,
            "model": self._model,
            "ollama_available": self._check_ollama(),
            "openai_available": bool(os.getenv("OPENAI_API_KEY")) and OPENAI_AVAILABLE
        }


# Backward compatibility alias
OpenAIService = AIService
