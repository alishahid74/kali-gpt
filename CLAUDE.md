# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kali GPT is an AI-powered penetration testing assistant integrating OpenAI GPT models and local Ollama LLMs with Kali Linux tooling. It has four versioned entry points with increasing capability, from simple CLI chat to fully autonomous pentesting agents.

## Setup & Running

```bash
# Automated setup (installs deps, creates venv, configures paths)
./setup.sh

# Manual setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env   # Set OPENAI_API_KEY or OLLAMA_HOST/OLLAMA_MODEL
```

### Entry Points (from simplest to most advanced)

| Script | Description |
|---|---|
| `python kali-gpt.py` | Basic CLI — menu-driven Q&A, payload generation, tool explanations. Uses OpenAI directly. |
| `python kali-gpt-advanced.py` | Command execution with safety controls, 7 security profiles, workflow builder. Uses OpenAI directly. |
| `python kali-gpt-enhanced.py` | Modular architecture — imports from `kali_gpt/` package. Metasploit, reports, multi-target, plugins. |
| `python kali-gpt-autonomous.py` | v4.1 — Self-contained 93KB script. ReAct autonomous agent, PTES methodology, MITRE ATT&CK, 220+ tools, REST API, browser automation. |

### Supporting Scripts

- `multi_agent.py` — Multi-agent collaboration
- `bug_bounty_hunter.py` / `bug_bounty_menu.py` — Bug bounty workflows
- `attack_tree.py` — Attack tree visualization
- `install-models.sh` — Ollama model installer

### Standalone Root-Level Modules

These are standalone versions of functionality that also exists inside `kali_gpt/`: `api_server.py`, `api_client.py`, `persistent_memory.py`, `dashboard_server.py`, `exploit_engine.py`, `scan_scheduler.py`, `network_mapper.py`, `team_collaboration.py`, `vuln_database.py`, `report_generator.py`. They can be run independently without the full `kali_gpt/` package.

## Architecture

### `kali_gpt/` Package

The modular package used by `kali-gpt-enhanced.py`. Key sub-packages:

- **`llm/`** — LLM provider abstraction. `BaseLLMProvider` defines the interface; `OpenAIProvider` and `OllamaProvider` implement it. `LLMFactory` auto-detects providers with priority order: Ollama (local) → OpenAI (cloud) → Groq (cloud), falling back automatically if preferred provider is unavailable.
- **`agents/`** — `autonomous_agent.py` (ReAct pattern: Observe→Think→Act→Learn), `agents_v4.py` (12 specialized agents), `enhanced_agent.py`
- **`modules/`** — Core services: `ai_service.py` (dual-provider), `command_executor.py` (safe execution with validation + 30s timeout), `profile_manager.py` (7 security profiles with specialized system prompts), `report_generator.py` (HTML/Markdown/JSON), `history_manager.py`, `target_manager.py`
- **`integrations/`** — External tools: Metasploit RPC, Nmap/Nikto scanners, NVD/CVE/ExploitDB, team collaboration
- **`tools/`** — `tool_registry.py` (220+ security tool definitions), `browser_agent.py` (Selenium/Playwright), `mcp_server.py` (IDE integration)
- **`knowledge/`** — MITRE ATT&CK framework mapping, intelligent tool chaining
- **`memory/store.py`** — SQLite-backed persistent memory
- **`utils/validators.py`** — `CommandValidator` checks for dangerous command patterns; execution requires user confirmation
- **`plugins/plugin_manager.py`** — Dynamic plugin loading from `~/.kali-gpt/plugins/`
- **`ui/`** — Rich terminal UI (menu.py, colors.py)

### Key Patterns

- **LLM Provider Selection**: `LLMFactory.initialize()` takes a `preferred_provider` and `auto_fallback` flag. Provider availability is checked at runtime. Env vars: `OPENAI_API_KEY` for OpenAI, `OLLAMA_HOST`/`OLLAMA_MODEL` for Ollama.
- **ReAct Agent Loop**: Autonomous agent cycles through Observe→Think→Act→Learn, following PTES phases (Reconnaissance → Scanning → Enumeration → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting).
- **Command Safety**: `CommandValidator` blocks dangerous patterns; execution requires confirmation and has timeout protection (default 30s).
- **Security Profiles**: 7 built-in profiles (General, Recon, Exploit, Web, Wireless, Post-Exploit, Forensics) each with specialized system prompts and tool sets, managed by `ProfileManager`.
- **Dual architecture**: The basic/advanced scripts (`kali-gpt.py`, `kali-gpt-advanced.py`) use OpenAI directly. The enhanced script imports from the `kali_gpt/` package. The autonomous script (`kali-gpt-autonomous.py`) is a large self-contained file with its own implementations.

## Configuration

- `config.example.json` — Full config template (model, temperature, tokens, Metasploit, scanners, collaboration)
- `.env.example` — Environment variables (`OPENAI_API_KEY`, `OLLAMA_HOST`, `OLLAMA_MODEL`)
- Runtime config stored in `~/.kali-gpt/config.json`
- Plugins loaded from `~/.kali-gpt/plugins/`

## Fine-Tuning

- `fine_tune/fine_tune.py` — Model fine-tuning script
- `fine_tune/evaluate_model.py` — Evaluation
- `fine_tune/pentest_training_data.jsonl` — Training data
- `Modelfile.pentester` / `Modelfile.redteam` — Custom Ollama model definitions

## Additional Components

- **VSCode Extension**: `vscode-extension/` — Node.js/TypeScript extension for IDE integration
- **Jupyter Notebook**: `Kali_GPT_Fine_Tuning.ipynb` — Interactive fine-tuning workflow
- **Examples**: `examples/` — Usage docs and payload examples

## Dependencies

Python 3.8+ with: openai, rich, pyperclip, python-dotenv, requests (see `requirements.txt`). The autonomous version uses additional optional deps: fastapi, uvicorn, selenium, playwright, msfrpc.

## Testing & CI

No test suite, linting configuration, or CI/CD pipeline exists yet. The `.gitignore` includes pytest patterns for future use.
