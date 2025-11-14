# 🐉 Kali GPT - AI-Powered Penetration Testing Assistant

**Kali GPT** is a powerful terminal-based AI assistant designed for penetration testers and security professionals. Available in two versions: **Basic** for simple tasks and **Advanced** for professional red team operations with command execution capabilities.

---

## 📦 Three Versions Available

### 🔷 Kali GPT (Basic)
Simple and lightweight AI assistant for:
- Quick questions about security tools
- Basic payload generation
- Tool explanations
- Learning pentesting basics

### 🔶 Kali GPT Advanced
Professional-grade assistant with:
- ⚡ **Command Execution**: Run and analyze Kali tools directly
- 🎯 **7 Security Profiles**: Specialized modes (Recon, Exploitation, Web, Wireless, etc.)
- 🧠 **Context-Aware AI**: Maintains conversation history
- 🔧 **Workflow Automation**: Multi-step pentesting workflows
- 📋 **Advanced Payload Generation**: With evasion techniques
- 🔍 **Output Analysis**: AI-powered results interpretation
- 🛡️ **Safety Controls**: Protection against dangerous commands

➡️ **[Read Advanced Documentation](README_ADVANCED.md)** for full features

### ⭐ Kali GPT Enhanced v2.0 (NEW - Recommended)
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

---

## 🚀 Quick Installation

### Automated Setup (Recommended)

```bash
# Clone repository
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt

# Run installation script
chmod +x setup.sh
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
./kali-gpt.py
```

Simple menu-driven interface for:
- Asking cybersecurity questions
- Generating basic payloads
- Getting tool explanations

### Advanced Version
```bash
source venv/bin/activate
./kali-gpt-advanced.py
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

---

## 🧰 Requirements

- **OS**: Kali Linux (or any Debian-based distro)
- **Python**: 3.8 or higher
- **API Key**: OpenAI API key (GPT-4 recommended)
- **Tools**: xclip (for clipboard support)

---

## 📖 Documentation

- **[README_ADVANCED.md](README_ADVANCED.md)** - Complete advanced features guide
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

---

## 🤝 Contributing

Contributions are welcome! Please:
- Follow responsible disclosure
- Add safety controls for new features
- Update documentation
- Test thoroughly

---
---

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. Users must ensure proper authorization before testing any systems. The author is not responsible for misuse.

**Use responsibly. Hack ethically. Stay legal.** 🐉

---

## 🔗 Links

- **GitHub**: [https://github.com/alishahid74/kali-gpt](https://github.com/alishahid74/kali-gpt)
- **OpenAI API**: [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- **Advanced Docs**: [README_ADVANCED.md](README_ADVANCED.md)
