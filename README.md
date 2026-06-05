
<img width="1875" height="897" alt="Screenshot 2026-01-16 200517" src="https://github.com/user-attachments/assets/a85db055-60a7-48e4-9021-f1364d68bc13" />

# 🐉 Kali GPT - AI-Powered Penetration Testing Assistant

**Kali GPT** is a powerful terminal-based AI assistant designed for penetration testers and security professionals. Available in four versions — from simple CLI chat to a fully autonomous AI pentesting agent with 220+ tools, MITRE ATT&CK mapping, and browser automation.

---

## 🚀 NEW: Version 3.0 - Autonomous AI Pentester

**🔥 MAJOR UPDATE: World's first truly autonomous AI penetration testing tool!**

### What's New in v3.0

| Feature | Description |
|---------|-------------|
| 🤖 **Autonomous ReAct Agent** | AI that thinks and acts like a human pentester - Observe → Think → Act → Learn |
| 🧠 **FREE Local LLM (Ollama)** | No API costs! Private, offline capable, runs on your machine |
| 📚 **MITRE ATT&CK Framework** | 50+ techniques mapped, follows established methodology |
| ⛓️ **Intelligent Tool Chaining** | Auto-selects next tool based on discoveries (HTTP→whatweb→nikto→nuclei) |
| 💾 **Persistent Memory** | SQLite database remembers past engagements and learns patterns |
| 🔄 **Multi-LLM Support** | Switch between Ollama (free) and OpenAI (cloud) anytime |

---

### 🤖 Autonomous Agent - How It Works

The agent follows the **ReAct (Reasoning + Acting)** pattern:

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTONOMOUS AGENT LOOP                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────┐  │
│   │ OBSERVE  │───▶│  THINK  │───▶│   ACT   │───▶│LEARN │  │
│   │          │    │          │    │          │    │      │  │
│   │ Gather   │    │ Analyze  │    │ Execute  │    │Update│  │
│   │ current  │    │ & decide │    │ tools    │    │memory│  │
│   │ state    │    │ next step│    │          │    │      │  │
│   └──────────┘    └──────────┘    └──────────┘    └──────┘  │
│        ▲                                              │     │
│        └──────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Pentesting Phases (PTES Methodology):**
1. **Reconnaissance** → nmap, whois, theHarvester, amass
2. **Scanning** → nmap, masscan, rustscan
3. **Enumeration** → gobuster, nikto, enum4linux, smbmap
4. **Vulnerability Analysis** → nuclei, nikto, searchsploit
5. **Exploitation** → metasploit, sqlmap, hydra
6. **Post-Exploitation** → linpeas, winpeas, bloodhound
7. **Reporting** → Auto-generated reports

---

### 🧠 FREE Local AI with Ollama

**No more API costs!** Run AI completely locally:

```bash
# Install Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh

# Download model (one-time, ~4GB)
ollama pull llama3.2

# Start Ollama server
ollama serve
```

**Supported Models:**
| Model | Size | Best For |
|-------|------|----------|
| `llama3.2` | 4GB | General use (recommended) |
| `llama3.2:70b` | 40GB | Best quality |
| `codellama` | 7GB | Code/command generation |
| `mistral` | 4GB | Good reasoning |
| `phi3` | 2GB | Fast, lightweight |

**Switch between providers anytime:**
```python
# In code
ai_service.switch_provider("ollama")  # Free, local
ai_service.switch_provider("openai")  # Cloud, paid
```

---

### 📚 MITRE ATT&CK Integration

All actions mapped to MITRE ATT&CK framework:

```
TACTIC                    TECHNIQUES                      TOOLS
─────────────────────────────────────────────────────────────────
Reconnaissance     T1595 Active Scanning          nmap, masscan
                   T1592 Gather Host Info         whatweb, wappalyzer
                   T1589 Gather Identity Info     theHarvester
                   
Initial Access     T1190 Exploit Public App       sqlmap, nuclei
                   T1133 External Services        hydra, medusa
                   
Discovery          T1046 Network Service Scan     nmap -sV
                   T1087 Account Discovery        enum4linux
                   T1082 System Info Discovery    linpeas
                   
Credential Access  T1110 Brute Force              hydra, john
                   T1003 Credential Dumping       mimikatz
```

---

### ⛓️ Intelligent Tool Chaining

Auto-selects tools based on what's discovered:

```
Discovery                    Auto-Chain
─────────────────────────────────────────────────────────────────
Port 80/443 open      →     whatweb → nikto → gobuster → nuclei
Port 22 open          →     ssh-audit → hydra (if weak)
Port 445 open (SMB)   →     enum4linux → smbmap → crackmapexec
WordPress detected    →     wpscan → nuclei wordpress templates
Login page found      →     hydra → sqlmap (if parameters)
```

**Example Chain:**
```
[+] nmap found port 80 open
    └─→ whatweb identifies WordPress 5.8
        └─→ wpscan enumerates users/plugins
            └─→ nuclei scans for CVEs
                └─→ searchsploit finds exploits
```

---

### 💾 Persistent Memory System

Learns from every engagement:

```
┌─────────────────────────────────────────────────────────────┐
│                    MEMORY DATABASE                          │
├─────────────────────────────────────────────────────────────┤
│  📊 Engagements        │ Past targets, phases reached       │
│  🔓 Vulnerabilities    │ CVEs found, exploitation success   │
│  🎯 Action Patterns    │ What worked on similar targets     │
│  📈 Success Rates      │ Tool effectiveness per target type │
└─────────────────────────────────────────────────────────────┘
```

**Features:**
- Remembers successful techniques per target fingerprint
- Suggests actions based on similar past engagements
- Tracks vulnerability discovery patterns
- Reports on tool effectiveness

---

### 🚀 Quick Start v3.0

**Option 1: With Ollama (FREE - Recommended)**
```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama serve

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run autonomous mode
python kali-gpt-autonomous.py
```

**Option 2: With OpenAI (Cloud)**
```bash
# 1. Set API key
export OPENAI_API_KEY=your-key-here

# 2. Run
python kali-gpt-autonomous.py --provider openai
```

**Command Line Options:**
```bash
python kali-gpt-autonomous.py --help

Options:
  -t, --target TARGET      Target for immediate scan
  -p, --provider PROVIDER  AI provider: ollama, openai, auto
  -m, --model MODEL        Model name (e.g., llama3.2, gpt-4o)
```

---

### 🎮 Usage Examples

**1. Start Autonomous Test:**
```bash
python kali-gpt-autonomous.py

# Menu:
# 1. 🎯 Autonomous Test - AI decides everything
# 2. 👣 Step-by-Step - You confirm each action
# 3. 🔧 Quick Scan - Single nmap scan
# 4. ❓ Ask AI - Security questions
```

**2. Target Specific IP:**
```bash
python kali-gpt-autonomous.py --target 192.168.1.100
```

**3. Use Specific Model:**
```bash
python kali-gpt-autonomous.py --provider ollama --model codellama
```

**4. Switch Provider Mid-Session:**
```
> Menu option 6 (Provider)
> Current: ollama (llama3.2)
> Switch to: openai
> [+] Switched to OpenAI (gpt-4o)
```

---

### 📊 Status & Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 | ✅ Complete | Autonomous Agent + Local LLM |
| Phase 2 | ✅ Complete | MITRE ATT&CK + Tool Chaining |
| Phase 3 | ✅ Complete | Report Generation |
| Phase 4 | ✅ Complete | Attack Tree Visualization (`attack_tree.py`) |
| Phase 5 | ✅ Complete | Multi-Agent Collaboration (`multi_agent.py`) |
| Phase 6 | ✅ Complete | Bug Bounty Hunter (`bug_bounty_hunter.py`) |
| Phase 7 | ⏳ Planned | Fine-tuned Security LLM |

---

## 📦 Four Versions Available

### 🔷 Kali GPT (Basic) — `kali-gpt.py`
Simple and lightweight AI assistant for:
- Quick questions about security tools
- Basic payload generation
- Tool explanations
- Learning pentesting basics

### 🔶 Kali GPT Advanced — `kali-gpt-advanced.py`
Professional-grade assistant with:
- ⚡ **Command Execution**: Run and analyze Kali tools directly
- 🎯 **7 Security Profiles**: Specialized modes (Recon, Exploitation, Web, Wireless, etc.)
- 🧠 **Context-Aware AI**: Maintains conversation history
- 🔧 **Workflow Automation**: Multi-step pentesting workflows
- 📋 **Advanced Payload Generation**: With evasion techniques
- 🔍 **Output Analysis**: AI-powered results interpretation
- 🛡️ **Safety Controls**: Protection against dangerous commands

➡️ **[Read Advanced Documentation](README_ADVANCED.md)** for full features

### ⭐ Kali GPT Enhanced v2.0 — `kali-gpt-enhanced.py`
Enterprise-grade penetration testing platform with all advanced features PLUS:
- 🎯 **Metasploit Framework Integration**: Automated exploitation and payload generation
- 📊 **Custom Tool Profiles**: Create specialized profiles for your workflow
- 📈 **Report Generation**: Professional HTML, Markdown, and JSON reports
- 🎯 **Multi-Target Management**: Track multiple targets with findings and notes
- 🔌 **Plugin System**: Extensible architecture for custom functionality
- 👥 **Team Collaboration**: Share sessions and coordinate with team members
- 🔍 **Automated Vulnerability Scanning**: Integrated Nmap, Nikto, and custom scanners
- 🌐 **Vulnerability Database Integration**: Real-time CVE, NVD, and ExploitDB lookups

➡️ **[Read Features Documentation](FEATURES.md)** for complete feature list

### 🚀 Kali GPT Autonomous v4.1 — `kali-gpt-autonomous.py`
Fully autonomous AI pentesting agent — the most capable version:
- 🤖 **ReAct Autonomous Agent**: AI that thinks and acts like a human pentester
- 🧠 **FREE Local LLM (Ollama)**: No API costs, private, offline capable
- 📚 **MITRE ATT&CK Framework**: 50+ techniques mapped
- ⛓️ **Intelligent Tool Chaining**: Auto-selects tools based on discoveries
- 💾 **Persistent Memory**: Learns from past engagements
- 🛡️ **220+ Security Tools**: Comprehensive tool registry
- 🌐 **REST API + WebSocket**: Remote control via FastAPI
- 🔍 **Browser Automation**: Selenium/Playwright for web testing
- 👥 **12 Specialized AI Agents**: Multi-agent collaboration
- ☁️ **Cloud Security Module**: AWS/Azure/GCP/K8s scanning

➡️ See [Quick Start v3.0](#-quick-start-v30) above for setup

---

## 🚀 Quick Installation

### Automated Setup (Recommended)

```bash
# Clone repository
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt

# Run the installation script
chmod +x setup.sh
./setup.sh

# If you encounter the error:
# "bad interpreter: /bin/bash^M"
# fix Windows line endings and run again
sed -i 's/\r$//' setup.sh
./setup.sh


# Add your OpenAI API key
nano .env
# Add: OPENAI_API_KEY=your-api-key-here

# Activate environment
source venv/bin/activate

# Run Enhanced version (recommended for professionals)
python3 kali-gpt-enhanced.py

# Or run Advanced version

./kali-gpt-advanced.py

# OR run Basic version
./kali-gpt.py
```

### Manual Installation

```bash
# Clone repository
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
echo "OPENAI_API_KEY=your-api-key-here" > .env

# Edit .env and add your actual API key
nano .env

# Run the tool
./kali-gpt-advanced.py
```

---

## 🔑 Getting OpenAI API Key

1. Go to [OpenAI Platform](https://platform.openai.com/api-keys)
2. Sign up or log in
3. Click "Create new secret key"
4. Copy the key and add to `.env` file

---

## 🎮 Quick Start Guide

### Basic Version
```bash
source venv/bin/activate
python3 kali-gpt.py
```

Simple menu-driven interface for:
- Asking cybersecurity questions
- Generating basic payloads
- Getting tool explanations

### Advanced Version
```bash
source venv/bin/activate
python3 kali-gpt-advanced.py
```

**Main Menu Options:**
1. 💬 AI-Assisted Questions - Ask anything about pentesting
2. ⚡ Quick Command Generation - Generate commands instantly
3. 🎯 Execute Commands - Run tools with AI analysis
4. 🔧 Workflow Builder - Automate multi-step processes
5. 🛡️ Security Profiles - Switch between specialized modes
6. 📋 Payload Generator - Advanced payload creation
7. 🔍 Output Analysis - Analyze tool outputs
8. 📚 Conversation History - Review past interactions
9. ⚙️ Settings - Customize behavior

### Enhanced Version
```bash
source venv/bin/activate
python3 kali-gpt-enhanced.py
```

Adds Metasploit integration, report generation, multi-target management, plugins, team collaboration, and vulnerability database lookups on top of all advanced features.

### Autonomous Version
```bash
source venv/bin/activate
python3 kali-gpt-autonomous.py
```

Fully autonomous ReAct agent that follows PTES methodology. Can run with free local Ollama models or cloud OpenAI. See [Quick Start v3.0](#-quick-start-v30) above.

---

## 🧰 Requirements

- **OS**: Kali Linux (or any Debian-based distro)
- **Python**: 3.8 or higher
- **API Key**: OpenAI API key (GPT-4 recommended)
- **Tools**: xclip (for clipboard support)

---

## 📖 Documentation

- **[README_ADVANCED.md](README_ADVANCED.md)** - Complete advanced features guide
- **[FEATURES.md](FEATURES.md)** - Enhanced version feature documentation
- **[MODELS.md](MODELS.md)** - Model selection and recommendations
- **[QUICK_START.md](QUICK_START.md)** - Quick start reference card
- **[SECURITY.md](SECURITY.md)** - Security policy and best practices
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[config.example.json](config.example.json)** - Configuration options

---

## 🎯 Example Usage

### Reconnaissance Example
```
User: How do I enumerate subdomains for target.com?
AI: [Provides multiple tools and commands]

User: [Selects command to execute]
System: [Runs command with confirmation]
AI: [Analyzes results and suggests next steps]
```

### Exploitation Example
```
User: Generate reverse shell payloads for Linux target
AI: [Creates bash, python, nc payloads + listener setup]

User: [Copies payload, sets up listener]
```

### Web Testing Example
```
User: Build workflow for web app testing on https://target.com
AI: [Creates step-by-step workflow]
  1. Directory enumeration with ffuf
  2. Vulnerability scanning with nikto
  3. SQL injection testing with sqlmap
  4. XSS detection
  [Each with specific commands and analysis]
```

---

## 🛡️ Security Profiles (Advanced Only)

Switch between specialized AI modes:

- 🎯 **General Pentesting** - Balanced general guidance
- 🔍 **Reconnaissance** - OSINT and scanning focus
- ⚡ **Exploitation** - Vulnerability exploitation
- 🌐 **Web Application** - OWASP Top 10 testing
- 📡 **Wireless Security** - WiFi attacks
- 🔐 **Post-Exploitation** - Persistence and lateral movement
- 🔬 **Digital Forensics** - Evidence and analysis

---

## ⚙️ Configuration

Advanced version uses: `~/.kali-gpt/config.json`

```json
{
  "model": "gpt-4o",
  "temperature": 0.7,
  "require_confirmation": true,
  "auto_copy": true,
  "save_history": true
}
```

---

## 🐛 Troubleshooting

### API Key Not Working
```bash
# Verify .env file
cat .env
# Should show: OPENAI_API_KEY=sk-...

# Make sure no spaces around =
# Correct: OPENAI_API_KEY=sk-xxx
# Wrong: OPENAI_API_KEY = sk-xxx
```

### Permission Errors
```bash
# Make scripts executable
chmod +x kali-gpt.py kali-gpt-advanced.py

# For system commands that need root
sudo ./kali-gpt-advanced.py
```

### Module Not Found
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

---

## 🔐 Security & Ethics

### ⚠️ Important Guidelines

- ✅ **Only test authorized systems**
- ✅ **Use for legal pentesting, CTFs, research**
- ✅ **Respect privacy and data protection laws**
- ❌ **Never use for unauthorized access**
- ❌ **Never use for malicious purposes**

### Data Privacy
- All logs stored locally in `~/.kali-gpt/`
- API requests sent only to OpenAI
- No third-party data sharing
- Secure your API key in `.env`

---

## 🚀 Advanced Features Highlights

### Command Execution with Safety
- Automatic dangerous command detection
- Confirmation before execution
- Timeout protection
- Safe mode controls

### Intelligent Workflows
- Multi-step pentesting automation
- Context-aware suggestions
- Tool chaining capabilities
- Result-based decision making

### Output Analysis
- AI-powered result interpretation
- Vulnerability identification
- Next-step recommendations
- Finding prioritization

---

## 🤝 Contributing

Contributions are welcome! Please:
- Follow responsible disclosure
- Add safety controls for new features
- Update documentation
- Test thoroughly

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. Users must ensure proper authorization before testing any systems. The author is not responsible for misuse.

**Use responsibly. Hack ethically. Stay legal.** 🐉

---

## 🔗 Links

- **GitHub**: [https://github.com/alishahid74/kali-gpt](https://github.com/alishahid74/kali-gpt)
- **OpenAI API**: [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- **Ollama**: [https://ollama.com](https://ollama.com)
- **Advanced Docs**: [README_ADVANCED.md](README_ADVANCED.md)
- **Features Docs**: [FEATURES.md](FEATURES.md)
- **Models Guide**: [MODELS.md](MODELS.md)
