"""AI Service Module for OpenAI interactions"""

from openai import OpenAI
from typing import List, Dict, Optional
import os

class AIService:
    """Handles all AI/LLM interactions"""

    def __init__(self, config_manager):
        """Initialize AI service with configuration"""
        self.config = config_manager
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.conversation_history = []

    def ask(self, prompt: str, system_prompt: str = None,
            include_history: bool = True, max_history: int = 5) -> str:
        """
        Send a prompt to the AI and get a response

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
            # Get model parameters from config
            model = self.config.get("model", "gpt-4o")
            temperature = self.config.get("temperature", 0.7)
            max_tokens = self.config.get("max_tokens", 2000)

            response = self.client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )

            ai_response = response.choices[0].message.content

            # Update conversation history
            if self.config.get("save_history", True):
                self.conversation_history.append({
                    "user": prompt,
                    "assistant": ai_response
                })

            return ai_response

        except Exception as e:
            return f"Error communicating with AI: {str(e)}"

    def analyze_output(self, command: str, output: str, context: str = "") -> str:
        """
        Analyze command output using AI

        Args:
            command: The command that was executed
            output: Command output
            context: Additional context

        Returns:
            AI analysis of the output
        """
        analysis_prompt = f"""Analyze this command output from a penetration testing session:

Command: {command}
{f'Context: {context}' if context else ''}

Output:
```
{output[:3000]}  # Limit output length
```

Provide:
1. Key findings and discoveries
2. Security implications
3. Recommended next steps
4. Any vulnerabilities or interesting observations
"""
        return self.ask(analysis_prompt, include_history=False)

    def generate_command(self, task_description: str, target_info: str = "") -> Dict[str, str]:
        """
        Generate a command based on task description

        Args:
            task_description: What the user wants to accomplish
            target_info: Information about the target

        Returns:
            Dictionary with command, explanation, and expected output
        """
        generation_prompt = f"""Generate a Kali Linux command for the following task:

Task: {task_description}
{f'Target: {target_info}' if target_info else ''}

Provide:
1. The exact command to run
2. Brief explanation of what it does
3. Key parameters explained
4. Expected output format

Format your response as:
COMMAND: <the command>
EXPLANATION: <brief explanation>
PARAMETERS: <parameter details>
EXPECTED: <what to expect>
"""
        response = self.ask(generation_prompt, include_history=False)

        # Parse response
        command = ""
        explanation = ""
        parameters = ""
        expected = ""

        for line in response.split('\n'):
            if line.startswith('COMMAND:'):
                command = line.replace('COMMAND:', '').strip()
            elif line.startswith('EXPLANATION:'):
                explanation = line.replace('EXPLANATION:', '').strip()
            elif line.startswith('PARAMETERS:'):
                parameters = line.replace('PARAMETERS:', '').strip()
            elif line.startswith('EXPECTED:'):
                expected = line.replace('EXPECTED:', '').strip()

        return {
            'command': command,
            'explanation': explanation,
            'parameters': parameters,
            'expected': expected,
            'full_response': response
        }

    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []

    def get_history(self) -> List[Dict]:
        """Get conversation history"""
        return self.conversation_history
