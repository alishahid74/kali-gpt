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
| `python kali-gpt.py` | Basic CLI — menu-driven Q&A, payload generation, tool explanations |
| `python kali-gpt-advanced.py` | Command execution with safety controls, 7 security profiles, workflow builder |
| `python kali-gpt-enhanced.py` | Modular architecture — Metasploit integration, report generation, multi-target, plugins |
| `python kali-gpt-autonomous.py` | v4.1 — ReAct autonomous agent, PTES methodology, MITRE ATT&CK, 220+ tools, REST API, browser automation |

### Supporting Scripts

- `multi_agent.py` — Multi-agent collaboration
- `bug_bounty_hunter.py` / `bug_bounty_menu.py` — Bug bounty workflows
- `attack_tree.py` — Attack tree visualization
- `install-models.sh` — Ollama model installer

## Architecture

### `kali_gpt/` Package Structure

```
kali_gpt/
├── core/config.py          # ConfigManager — loads/saves ~/.kali-gpt/config.json
├── llm/                    # LLM provider abstraction
│   ├── base.py             #   BaseLLMProvider (abstract)
│   ├── factory.py          #   LLMProviderFactory — auto-detects available providers
│   ├── openai_provider.py  #   OpenAI implementation
│   └── ollama_provider.py  #   Ollama (local) implementation
├── agents/                 # Agent implementations
│   ├── autonomous_agent.py #   ReAct pattern (Observe→Think→Act→Learn)
│   ├── agents_v4.py        #   v4 multi-agent system (12 specialized agents)
│   └── enhanced_agent.py   #   Enhanced agent features
├── modules/                # Core modules
│   ├── ai_service.py       #   Dual-provider AI service
│   ├── command_executor.py #   Safe command execution with validation
│   ├── profile_manager.py  #   Security profiles (Recon, Exploit, Web, etc.)
│   ├── report_generator.py #   HTML/Markdown/JSON reports
│   ├── history_manager.py  #   Conversation history
│   └── target_manager.py   #   Multi-target tracking
├── integrations/           # External tool integrations
│   ├── metasploit.py       #   Metasploit RPC
│   ├── scanner.py          #   Nmap/Nikto scanner manager
│   ├── vulnerability_db.py #   NVD, CVE, ExploitDB
│   └── collaboration.py   #   Team collaboration
├── tools/
│   ├── tool_registry.py    #   220+ security tool definitions
│   ├── browser_agent.py    #   Selenium/Playwright automation
│   └── mcp_server.py       #   MCP server for IDE integration
├── knowledge/
│   ├── mitre_attack.py     #   MITRE ATT&CK framework mapping
│   └── tool_chains.py      #   Intelligent tool chaining
├── memory/store.py         #   SQLite-backed persistent memory
├── utils/validators.py     #   CommandValidator — dangerous command detection
├── api_server.py           #   FastAPI REST server with WebSocket support
├── plugins/plugin_manager.py  # Dynamic plugin loading from ~/.kali-gpt/plugins
└── ui/                     #   Rich terminal UI (menu.py, colors.py)
```

### Key Patterns

- **LLM Provider Abstraction**: `BaseLLMProvider` → `OpenAIProvider` / `OllamaProvider`, selected via `LLMProviderFactory` with auto-detection and fallback
- **ReAct Agent Loop**: Autonomous agent cycles through Observe→Think→Act→Learn, following PTES phases (Reconnaissance through Reporting)
- **Command Safety**: `CommandValidator` in `utils/validators.py` checks for dangerous patterns; execution requires confirmation and has timeout protection (default 30s)
- **Security Profiles**: 7 built-in profiles (General, Recon, Exploit, Web, Wireless, Post-Exploit, Forensics) each with specialized system prompts and tool sets

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

## Dependencies

Python 3.8+ with: openai, rich, pyperclip, python-dotenv, requests (see `requirements.txt`). The autonomous version uses additional optional deps: fastapi, uvicorn, selenium, playwright, msfrpc.
