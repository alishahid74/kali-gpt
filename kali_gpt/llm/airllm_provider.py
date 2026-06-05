#!/usr/bin/env python3
"""
Kali-GPT v5.0 - AirLLM Provider
Run 70B+ parameter models on a SINGLE 4GB GPU!
Install: pip install airllm bitsandbytes
"""

import asyncio
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

try:
    from .base import BaseLLMProvider
except ImportError:
    class BaseLLMProvider:
        pass


@dataclass
class AirLLMConfig:
    model_name: str = "meta-llama/Llama-2-70b-chat-hf"
    compression: Optional[str] = "4bit"
    max_new_tokens: int = 512
    max_length: int = 2048
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 50
    use_cache: bool = True
    prefetching: bool = True
    delete_original: bool = False
    layer_shards_saving_path: Optional[str] = None
    hf_token: Optional[str] = None
    device: str = "auto"


RECOMMENDED_MODELS = {
    "llama3.1-405b": {"model_id": "meta-llama/Meta-Llama-3.1-405B-Instruct", "description": "Most powerful - 405B", "min_vram": "8GB (4bit)", "compression": "4bit"},
    "llama3-70b": {"model_id": "meta-llama/Meta-Llama-3-70B-Instruct", "description": "Excellent for security analysis", "min_vram": "4GB (4bit)", "compression": "4bit"},
    "llama2-70b": {"model_id": "meta-llama/Llama-2-70b-chat-hf", "description": "Great all-around", "min_vram": "4GB (4bit)", "compression": "4bit"},
    "mistral-7b": {"model_id": "mistralai/Mistral-7B-Instruct-v0.2", "description": "Fast and efficient", "min_vram": "3GB", "compression": None},
    "qwen2.5-72b": {"model_id": "Qwen/Qwen2.5-72B-Instruct", "description": "Excellent multilingual", "min_vram": "4GB (4bit)", "compression": "4bit"},
    "phi-3": {"model_id": "microsoft/Phi-3-mini-4k-instruct", "description": "Small, runs on CPU", "min_vram": "CPU", "compression": None},
}

PENTEST_SYSTEM_PROMPTS = {
    "default": "You are an expert penetration tester. Identify vulnerabilities, generate payloads, and provide security analysis.",
    "payload_generation": "You are a security expert. Generate precise, working payloads. One per line, no explanations.",
    "vulnerability_analysis": "You are analyzing security vulnerabilities. Provide severity, exploitability, and impact assessment.",
    "code_review": "You are a security code reviewer. Find injection flaws, auth issues, crypto weaknesses. Give line numbers and fixes.",
}


class AirLLMProvider(BaseLLMProvider):
    """Run massive LLMs (70B+) on consumer hardware via layer-by-layer inference."""

    def __init__(self, model_name=None, config=None, compression="4bit", hf_token=None, **kwargs):
        if config:
            self.config = config
        else:
            self.config = AirLLMConfig(model_name=model_name or "meta-llama/Llama-2-70b-chat-hf",
                                       compression=compression, hf_token=hf_token or os.environ.get("HF_TOKEN"), **kwargs)
        self.model = None
        self.tokenizer = None
        self._initialized = False
        try:
            import airllm
            self._airllm_available = True
        except ImportError:
            self._airllm_available = False

    def _ensure_initialized(self):
        if self._initialized:
            return
        if not self._airllm_available:
            raise RuntimeError("AirLLM not installed. Run: pip install airllm bitsandbytes")
        from airllm import AutoModel
        print(f"[*] Loading model: {self.config.model_name} (compression: {self.config.compression or 'None'})")
        init_kwargs = {"profiling_mode": False}
        if self.config.compression:
            init_kwargs["compression"] = self.config.compression
        if self.config.hf_token:
            init_kwargs["hf_token"] = self.config.hf_token
        if self.config.prefetching:
            init_kwargs["prefetching"] = True
        if self.config.delete_original:
            init_kwargs["delete_original"] = True
        self.model = AutoModel.from_pretrained(self.config.model_name, **init_kwargs)
        self.tokenizer = self.model.tokenizer
        self._initialized = True
        print("[+] Model loaded!")

    async def generate(self, prompt, system_prompt=None, max_new_tokens=None, temperature=None, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._generate_sync, prompt, system_prompt,
                                          max_new_tokens or self.config.max_new_tokens, temperature or self.config.temperature)

    def _generate_sync(self, prompt, system_prompt=None, max_new_tokens=512, temperature=0.7):
        self._ensure_initialized()
        if system_prompt and system_prompt in PENTEST_SYSTEM_PROMPTS:
            system_prompt = PENTEST_SYSTEM_PROMPTS[system_prompt]
        full = f"{system_prompt or PENTEST_SYSTEM_PROMPTS['default']}\n\nUser: {prompt}\n\nAssistant:"
        tokens = self.tokenizer([full], return_tensors="pt", return_attention_mask=False, truncation=True,
                                max_length=self.config.max_length, padding=False)
        import torch
        device = "cuda" if torch.cuda.is_available() else "cpu"
        output = self.model.generate(tokens["input_ids"].to(device), max_new_tokens=max_new_tokens, use_cache=self.config.use_cache,
                                     return_dict_in_generate=True, do_sample=temperature > 0, temperature=temperature if temperature > 0 else None)
        text = self.tokenizer.decode(output.sequences[0], skip_special_tokens=True)
        return text.split("Assistant:")[-1].strip() if "Assistant:" in text else text

    async def generate_payloads(self, vuln_type, context, count=10):
        prompt = f"Generate {count} working {vuln_type} payloads for:\nEndpoint: {context.get('endpoint')}\nParameter: {context.get('parameter')}\nOne per line.\nPayloads:"
        resp = await self.generate(prompt, system_prompt="payload_generation", max_new_tokens=256)
        return [l.strip() for l in resp.split("\n") if l.strip() and not l.startswith("#")][:count]

    async def analyze_vulnerability(self, finding):
        prompt = f"Analyze vulnerability:\nType: {finding.get('vuln_type')}\nEndpoint: {finding.get('endpoint')}\nEvidence: {finding.get('evidence')}\nProvide likelihood, exploitability, impact, CVSS."
        return {"analysis": await self.generate(prompt, system_prompt="vulnerability_analysis"), "finding": finding}

    async def review_code(self, code, language="python"):
        prompt = f"Review this {language} code for security vulnerabilities:\n```{language}\n{code[:3000]}\n```\nFindings:"
        return {"review": await self.generate(prompt, system_prompt="code_review"), "language": language}

    @classmethod
    def from_preset(cls, preset, **kwargs):
        if preset not in RECOMMENDED_MODELS:
            raise ValueError(f"Unknown preset '{preset}'. Available: {', '.join(RECOMMENDED_MODELS.keys())}")
        m = RECOMMENDED_MODELS[preset]
        return cls(model_name=m["model_id"], compression=m.get("compression"), **kwargs)

    @classmethod
    def list_recommended_models(cls):
        return RECOMMENDED_MODELS


__all__ = ["AirLLMProvider", "AirLLMConfig", "RECOMMENDED_MODELS", "PENTEST_SYSTEM_PROMPTS"]
