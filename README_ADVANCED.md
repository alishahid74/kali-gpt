# 🐉 Kali GPT Advanced - AI-Powered Penetration Testing Assistant

**Kali GPT Advanced** is a next-generation terminal-based AI assistant designed specifically for penetration testers, red teamers, and security researchers. It combines the power of OpenAI's GPT models with direct command execution, intelligent workflow automation, and specialized security expertise.

---

## 🚀 What's New in Advanced Version

### Major Features

- ⚡ **Command Execution Engine**: Run Kali Linux commands directly with AI guidance
- 🎯 **7 Security Profiles**: Specialized AI modes for different pentesting phases
- 🧠 **Context-Aware AI**: Maintains conversation history for intelligent follow-ups
- 🔧 **Workflow Automation**: Build and execute multi-step pentesting workflows
- 📋 **Smart Payload Generator**: Context-aware payload generation with evasion techniques
- 🔍 **Output Analysis**: AI-powered analysis of tool outputs and findings
- ⚙️ **Customizable Settings**: Fine-tune behavior, models, and safety controls
- 📚 **Persistent History**: Track all interactions across sessions
- 🛡️ **Safety Controls**: Built-in protections against dangerous commands

---

## 📋 Feature Comparison

| Feature | Basic Version | Advanced Version |
|---------|--------------|------------------|
| AI Questions | ✅ | ✅ |
| Payload Generation | ✅ Basic | ✅ Advanced + Evasion |
| Tool Explanations | ✅ | ✅ Enhanced |
| Command Execution | ❌ | ✅ |
| Security Profiles | ❌ | ✅ 7 Modes |
| Conversation History | ❌ | ✅ |
| Output Analysis | ❌ | ✅ |
| Workflow Builder | ❌ | ✅ |
| Configurable Settings | ❌ | ✅ |
| Safety Controls | ❌ | ✅ |

---

## 🛡️ Security Profiles

Kali GPT Advanced includes 7 specialized AI profiles:

### 1. 🎯 General Pentesting
- Default mode for general security assessments
- Balanced guidance across all pentesting phases
- Best for: Mixed engagements, learning, general questions

### 2. 🔍 Reconnaissance
- Focus: OSINT, network scanning, enumeration
- Tools: nmap, recon-ng, theHarvester, amass, subfinder
- Best for: Information gathering, target profiling

### 3. ⚡ Exploitation
- Focus: Vulnerability exploitation, payload delivery
- Tools: Metasploit, exploit-db, searchsploit, custom exploits
- Best for: Active exploitation, privilege escalation

### 4. 🌐 Web Application Testing
- Focus: OWASP Top 10, web vulnerabilities
- Tools: BurpSuite, sqlmap, nikto, wfuzz, ffuf
- Best for: Web app pentesting, API testing

### 5. 📡 Wireless Security
- Focus: WiFi attacks, wireless protocols
- Tools: aircrack-ng, wifite, reaver, bettercap
- Best for: Wireless assessments, rogue AP detection

### 6. 🔐 Post-Exploitation
- Focus: Persistence, lateral movement, data exfiltration
- Tools: Privilege escalation, pivoting, covering tracks
- Best for: Post-compromise operations, red team exercises

### 7. 🔬 Digital Forensics
- Focus: Evidence collection, malware analysis
- Tools: Volatility, Autopsy, Sleuthkit
- Best for: Incident response, forensic investigations

---

## 🎮 Usage Guide

### Quick Start

```bash
# Clone the repository
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt

# Run installation script
chmod +x setup.sh
./setup.sh

# Add your OpenAI API key to .env
nano .env

# Activate virtual environment
source venv/bin/activate

# Run Kali GPT Advanced
./kali-gpt-advanced.py
```

### Main Menu Options

#### 1. 💬 AI-Assisted Question/Task
Ask anything related to pentesting, security, or Kali Linux tools.

**Example:**
```
User: How do I perform subdomain enumeration on target.com?
AI: [Provides detailed explanation with tools and commands]
```

#### 2. ⚡ Quick Command Generation
Instantly generate commands for specific tasks.

**Example:**
```
User: nmap scan for web servers on 192.168.1.0/24
AI: [Generates optimized nmap command with explanations]
```

#### 3. 🎯 Execute Command with AI Analysis
Run commands and get intelligent analysis of results.

**Example:**
```
User: nmap -sV -p- 192.168.1.100
System: [Executes command]
AI: [Analyzes output, identifies services, suggests next steps]
```

#### 4. 🔧 Tool Workflow Builder
Create automated pentesting workflows.

**Example:**
```
User: Full web app assessment on https://target.com
AI: [Generates step-by-step workflow with commands]
```

#### 5. 🛡️ Change Security Profile
Switch between specialized AI modes.

**Example:**
```
Switch to: Reconnaissance Mode
AI: [Now optimized for recon tasks]
```

#### 6. 📋 Payload Generator
Advanced payload generation with multiple formats.

**Example:**
```
Payload Type: reverse shell
LHOST: 10.10.14.5
LPORT: 4444
AI: [Generates bash, python, php payloads + listener setup]
```

#### 7. 🔍 Analyze Output
Paste any tool output for AI analysis.

**Example:**
```
User: [Pastes nmap scan results]
AI: [Identifies vulnerabilities, suggests exploitation paths]
```

---

## 🔧 Configuration

### Settings File: `~/.kali-gpt/config.json`

```json
{
  "model": "gpt-4o",              // AI model to use
  "temperature": 0.7,              // Response creativity (0.0-1.0)
  "max_tokens": 2000,              // Maximum response length
  "require_confirmation": true,    // Confirm before executing commands
  "auto_copy": true,               // Auto-copy responses to clipboard
  "save_history": true,            // Save conversation history
  "max_history": 10               // Number of exchanges to remember
}
```

### Available Models
- `gpt-4o` - Best performance, most intelligent (recommended)
- `gpt-4o-mini` - Faster, cost-effective
- `gpt-4-turbo` - Previous generation, still powerful
- `gpt-3.5-turbo` - Fastest, basic tasks

---

## 🛡️ Safety Features

### Command Execution Safety

1. **Dangerous Command Detection**
   - Automatically detects destructive commands
   - Requires double confirmation for dangerous operations
   - Protected against: `rm -rf`, `dd if=`, `mkfs`, fork bombs

2. **User Confirmation**
   - Optional confirmation before executing any command
   - Shows command preview before execution
   - Can be disabled in settings for experienced users

3. **Timeout Protection**
   - Commands timeout after 30 seconds by default
   - Prevents hanging processes
   - Configurable per command

### Best Practices

- ✅ Always verify commands before execution
- ✅ Use on authorized targets only
- ✅ Keep API keys secure in `.env` file
- ✅ Review AI suggestions critically
- ✅ Maintain proper documentation of pentests

---

## 📚 Example Workflows

### 1. Complete Network Reconnaissance

```
1. Switch to Reconnaissance Profile
2. Ask: "Full network recon on 10.10.10.0/24"
3. Execute suggested nmap commands
4. Analyze results with AI
5. Generate enumeration commands for discovered services
```

### 2. Web Application Assessment

```
1. Switch to Web Application Profile
2. Use Workflow Builder: "OWASP Top 10 scan on https://target.com"
3. Execute directory fuzzing
4. Analyze findings
5. Generate SQL injection payloads based on findings
```

### 3. Post-Exploitation Workflow

```
1. Switch to Post-Exploitation Profile
2. Ask: "Linux privilege escalation enumeration"
3. Execute enumeration scripts
4. Analyze output for vulns
5. Generate exploitation commands
```

---

## 🔍 Advanced Tips

### Getting Better Results

1. **Be Specific**: "Port scan for SMB on 192.168.1.100" vs "scan target"
2. **Use Context**: AI remembers previous exchanges in session
3. **Switch Profiles**: Use appropriate profile for task
4. **Analyze Outputs**: Always use output analysis feature
5. **Build Workflows**: Automate repetitive tasks

### Keyboard Shortcuts

- `Ctrl+C` - Interrupt (doesn't exit)
- Choose `0` - Proper exit
- Paste into terminal - Use right-click or Shift+Insert

---

## 📖 File Structure

```
kali-gpt/
├── kali-gpt.py              # Basic version
├── kali-gpt-advanced.py     # Advanced version (main)
├── setup.sh                 # Installation script
├── requirements.txt         # Python dependencies
├── config.example.json      # Example configuration
├── .env                     # API keys (create this)
├── README.md               # Basic documentation
└── README_ADVANCED.md      # This file

~/.kali-gpt/                # User data directory
├── config.json             # User configuration
├── conversation_history.json  # Chat history
└── interaction_logs.json   # Detailed logs
```

---

## 🐛 Troubleshooting

### API Key Issues
```bash
# Check if .env exists and has valid key
cat .env
# Should show: OPENAI_API_KEY=sk-...
```

### Command Execution Fails
```bash
# Ensure you have permissions
# Some commands require sudo
sudo ./kali-gpt-advanced.py
```

### Clipboard Not Working
```bash
# Install xclip (Linux)
sudo apt install xclip

# Install pbcopy (macOS) - built-in
```

### Import Errors
```bash
# Reinstall dependencies
source venv/bin/activate
pip install -r requirements.txt --force-reinstall
```

---

## 🔐 Security Considerations

### Responsible Use

- ⚠️ **Authorization Required**: Only test systems you own or have explicit permission to test
- ⚠️ **Legal Compliance**: Follow local laws and regulations
- ⚠️ **Ethical Hacking**: Use for defensive security, CTFs, research, or authorized pentests
- ⚠️ **Data Privacy**: Logs may contain sensitive information - secure them properly
- ⚠️ **API Security**: Never share your OpenAI API key

### Data Handling

- Conversation history stored locally in `~/.kali-gpt/`
- Logs contain commands and outputs
- No data sent to third parties except OpenAI API
- Clear history regularly for sensitive engagements

---

## 🎯 Use Cases

### ✅ Authorized Use Cases

- Penetration testing engagements
- Bug bounty hunting (authorized programs)
- CTF competitions
- Security research and education
- Red team exercises
- Vulnerability assessments
- Security training
- Personal lab environments

### ❌ Prohibited Use Cases

- Unauthorized access to systems
- Malicious hacking
- Data theft or destruction
- DoS/DDoS attacks
- Any illegal activities

---

## 🚀 Future Enhancements

Planned features:
- [ ] Integration with Metasploit Framework
- [ ] Custom tool profiles
- [ ] Report generation
- [ ] Multi-target management
- [ ] Plugin system
- [ ] Team collaboration features
- [ ] Automated vulnerability scanning
- [ ] Integration with vulnerability databases

---

## 📄 License

This project is provided for educational and authorized security testing purposes only.

---

## 🤝 Contributing

Contributions welcome! Please ensure:
- Code follows ethical hacking principles
- Features include safety controls
- Documentation is updated
- Testing is thorough

---

## 📧 Support

- GitHub Issues: [Report bugs or request features](https://github.com/alishahid74/kali-gpt/issues)
- Security: Report security issues responsibly

---

## 🙏 Acknowledgments

- OpenAI for GPT models
- Kali Linux team for the platform
- Security community for tools and knowledge

---

## ⚠️ Disclaimer

This tool is provided "as is" for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for misuse or damage caused by this tool.

**Use responsibly. Hack ethically. Stay legal.** 🐉
