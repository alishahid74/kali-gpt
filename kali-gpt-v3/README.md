# 🐉 Kali-GPT v3 - Autonomous AI Penetration Testing Assistant

**The world's first truly autonomous AI-powered penetration testing tool.**

Kali-GPT v3 combines the power of large language models with the ReAct (Reasoning + Acting) pattern to create an AI agent that can think and act like a human penetration tester.

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🚀 What's New in v3

| Feature | Description |
|---------|-------------|
| 🤖 **Autonomous Agent** | ReAct pattern - reasons and acts like a human |
| 🧠 **Local LLM Support** | Free, private AI with Ollama (no API keys!) |
| 💾 **Persistent Memory** | Learns from past engagements |
| 🔧 **Safe Execution** | Validated commands with confirmation |
| 📊 **MITRE ATT&CK** | Follows established methodology |
| 🔌 **Modular Design** | Easy to extend and customize |

---

## 📦 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    KALI-GPT v3 ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    🧠 AI BRAIN LAYER                     │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────────┐   │   │
│  │  │  Ollama   │  │  OpenAI   │  │  Custom Models    │   │   │
│  │  │  (Local)  │  │  (Cloud)  │  │  (Fine-tuned)     │   │   │
│  │  └───────────┘  └───────────┘  └───────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌───────────────────────────▼─────────────────────────────┐   │
│  │                  🎯 AUTONOMOUS AGENT                     │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐   │   │
│  │  │ OBSERVE │→│  THINK  │→│   ACT   │→│    LEARN    │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌───────────────────────────▼─────────────────────────────┐   │
│  │                   🔧 TOOL LAYER                          │   │
│  │  nmap │ nikto │ gobuster │ sqlmap │ nuclei │ ...        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                  │
│  ┌───────────────────────────▼─────────────────────────────┐   │
│  │                   💾 MEMORY LAYER                        │   │
│  │  Past Engagements │ Patterns │ Vulnerabilities          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Installation

### Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/kali-gpt-v3
cd kali-gpt-v3

# Run setup
chmod +x setup.sh
./setup.sh

# Start the tool
./start.sh
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

### Installing Ollama (Local LLM)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull recommended model
ollama pull llama3.2

# Start Ollama server
ollama serve
```

---

## 🎮 Usage

### Interactive Menu

```
╔═══════════════════════════════════════════════════════════════╗
║                         MAIN MENU                              ║
╠═══════════════════════════════════════════════════════════════╣
║  1  │  🎯 New Engagement     │  Start autonomous pentest      ║
║  2  │  💬 Interactive Mode   │  Step-by-step guided testing   ║
║  3  │  🔧 Quick Command      │  Execute a single tool         ║
║  4  │  ❓ Ask AI             │  Ask security questions        ║
║  5  │  📊 Statistics         │  View learning statistics      ║
║  6  │  ⚙️  Settings          │  Configure options             ║
║  0  │  🚪 Exit               │  Exit application              ║
╚═══════════════════════════════════════════════════════════════╝
```

### Autonomous Mode

The agent will:
1. **Observe** - Analyze the current state
2. **Think** - Decide the best next action
3. **Act** - Execute tools with your confirmation
4. **Learn** - Update knowledge from results

```
🧠 Agent Thinking
├── Situation: No hosts discovered yet, starting reconnaissance
├── Plan: Begin with port scanning to identify services
├── Action: nmap
└── Confidence: 85%

⚠️  Action Requires Confirmation
├── Tool: nmap
├── Command: nmap -sV -T4 192.168.1.1
└── Risk Level: low

Execute this action? [y/N]:
```

### Programmatic Usage

```python
import asyncio
from core.app import KaliGPTApp

async def main():
    app = KaliGPTApp()
    await app.initialize()
    
    # Simple query
    response = await app.ask("How do I scan for open ports?")
    print(response)
    
    # Run autonomous engagement
    context = await app.run_autonomous(
        target="192.168.1.1",
        scope=["192.168.1.0/24"]
    )
    
    print(f"Found {len(context.discovered_vulnerabilities)} vulnerabilities")

asyncio.run(main())
```

---

## 🧠 LLM Providers

### Ollama (Recommended - Free & Private)

```bash
# Install
curl -fsSL https://ollama.com/install.sh | sh

# Recommended models
ollama pull llama3.2      # Best general purpose
ollama pull codellama     # Good for code/commands
ollama pull mistral       # Good reasoning
```

### OpenAI (Cloud)

```bash
# Set API key
export OPENAI_API_KEY=your-key-here

# Or in .env file
OPENAI_API_KEY=your-key-here
```

### Model Comparison

| Model | Type | Cost | Privacy | Speed | Quality |
|-------|------|------|---------|-------|---------|
| llama3.2 | Local | Free | ✅ High | Fast | Good |
| codellama | Local | Free | ✅ High | Fast | Good (code) |
| gpt-4o | Cloud | Paid | ⚠️ Low | Fast | Excellent |
| gpt-4o-mini | Cloud | Low | ⚠️ Low | Very Fast | Good |

---

## 🔒 Security Features

### Command Validation

All commands are validated before execution:
- Dangerous patterns blocked (rm -rf, etc.)
- High-risk tools require confirmation
- Scope enforcement prevents accidental testing

### Risk Levels

| Level | Tools | Requires Confirmation |
|-------|-------|----------------------|
| Safe | whois, dig, whatweb | No |
| Low | nmap, gobuster, nikto | No |
| Medium | nuclei, masscan | Optional |
| High | sqlmap, hydra, msfconsole | Yes |

---

## 📊 Memory & Learning

The tool learns from your engagements:

```
📊 Statistics
├── Total Engagements: 47
├── Vulnerabilities Found: 156
├── Actions Logged: 1,203
├── Average Success Rate: 73%
└── Top Vulnerability Types:
    ├── SQL Injection: 23
    ├── XSS: 19
    └── Open Ports: 114
```

### What It Remembers

- Successful command patterns for similar targets
- Discovered vulnerabilities and exploitation paths
- Tool effectiveness per target type
- Engagement duration and outcomes

---

## 🎯 Specialist Modes

Switch between specialized AI personas:

| Mode | Focus | Best For |
|------|-------|----------|
| `autonomous_pentester` | Full methodology | Complete engagements |
| `recon_specialist` | Information gathering | OSINT, enumeration |
| `exploit_specialist` | Vulnerability exploitation | After finding vulns |
| `web_specialist` | Web application testing | OWASP Top 10 |

```python
app.set_specialist_mode("web_specialist")
```

---

## 📁 Project Structure

```
kali-gpt-v3/
├── main.py              # Entry point
├── setup.sh             # Installation script
├── requirements.txt     # Dependencies
├── core/
│   └── app.py           # Main application
├── llm/
│   ├── base.py          # LLM abstractions
│   ├── ollama_provider.py
│   ├── openai_provider.py
│   └── factory.py       # Auto provider selection
├── agents/
│   └── autonomous_agent.py  # ReAct agent
├── tools/
│   └── executor.py      # Safe command execution
├── memory/
│   └── store.py         # SQLite persistence
└── configs/
    └── ...
```

---

## 🗺️ Roadmap

### Phase 1 ✅ (Current)
- [x] Autonomous agent architecture
- [x] Local LLM support (Ollama)
- [x] Memory/persistence layer
- [x] Safe tool execution

### Phase 2 (Next)
- [ ] MITRE ATT&CK mapping
- [ ] Intelligent tool chaining
- [ ] Attack tree visualization
- [ ] Report generation

### Phase 3 (Future)
- [ ] Fine-tuned security LLM
- [ ] Multi-agent collaboration
- [ ] Evasion techniques
- [ ] Real-time adaptation

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. 

- ✅ Only test systems you have explicit authorization to test
- ✅ Stay within defined scope
- ✅ Follow responsible disclosure
- ❌ Never use for unauthorized access
- ❌ Never use for malicious purposes

**The authors are not responsible for misuse of this tool.**

---

## 🤝 Contributing

Contributions welcome! Please:
- Follow responsible disclosure practices
- Add safety controls for new features
- Include tests for new modules
- Update documentation

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **GitHub**: [https://github.com/yourusername/kali-gpt-v3](https://github.com/yourusername/kali-gpt-v3)
- **Ollama**: [https://ollama.com](https://ollama.com)
- **MITRE ATT&CK**: [https://attack.mitre.org](https://attack.mitre.org)

---

**Happy Hacking! 🐉**
