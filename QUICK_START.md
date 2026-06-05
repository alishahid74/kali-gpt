# ⚡ Kali GPT - Quick Start Guide

## 🚀 Installation (2 minutes)

```bash
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt
chmod +x setup.sh && ./setup.sh
```

Add API key to `.env`:
```bash
nano .env
# Add: OPENAI_API_KEY=sk-your-key-here
```

---

## 🏃 Launch

```bash
source venv/bin/activate

# Choose your version:
python3 kali-gpt.py              # Basic — simple Q&A
python3 kali-gpt-advanced.py     # Advanced — command execution + profiles
python3 kali-gpt-enhanced.py     # Enhanced — Metasploit, reports, plugins
python3 kali-gpt-autonomous.py   # Autonomous — ReAct agent, 220+ tools (recommended)
```

---

## 📋 Menu Shortcuts

| Key | Feature |
|-----|---------|
| `1` | 💬 Ask AI questions |
| `2` | ⚡ Generate commands |
| `3` | 🎯 Execute + analyze |
| `4` | 🔧 Build workflow |
| `5` | 🛡️ Change mode |
| `6` | 📋 Generate payloads |
| `7` | 🔍 Analyze output |
| `8` | 📚 View history |
| `9` | ⚙️ Settings |
| `0` | ❌ Exit |

---

## 🎯 Security Profiles

| Profile | Best For |
|---------|----------|
| General | Mixed tasks, learning |
| Recon | Scanning, OSINT, enumeration |
| Exploit | Vulnerability exploitation |
| Web | OWASP Top 10, web apps |
| Wireless | WiFi attacks |
| Post-Exploit | Persistence, lateral movement |
| Forensics | Evidence, malware analysis |

---

## 💡 Common Tasks

### Reconnaissance
```
1. Switch to Recon mode (Menu → 5)
2. Ask: "Enumerate subdomains for target.com"
3. Execute suggested commands
4. Analyze results with AI
```

### Generate Payloads
```
Menu → 6 (Payload Generator)
- Type: reverse shell
- LHOST: your-ip
- LPORT: 4444
→ Get multiple payload formats + listener
```

### Execute & Analyze
```
Menu → 3 (Execute Command)
- Enter: nmap -sV target.com
- Confirm execution
→ Get AI analysis and next steps
```

### Build Workflow
```
Menu → 4 (Workflow Builder)
- Describe: "Full web app test on https://target.com"
→ Get step-by-step automated workflow
```

---

## 🛡️ Safety Features

- ✅ Confirms before executing commands
- ✅ Detects dangerous operations
- ✅ 30-second timeout protection
- ✅ Local logging for audit

Disable confirmations: Menu → 9 → require_confirmation → No

---

## 🔧 Configuration

File: `~/.kali-gpt/config.json`

Quick changes:
```bash
# Use faster model (cheaper)
"model": "gpt-4o-mini"

# More creative responses
"temperature": 0.9

# Disable confirmations
"require_confirmation": false
```

---

## 🎓 Example Workflows

### 1. Port Scan → Service Enumeration
```
User: Quick nmap scan on 192.168.1.100
AI: [Generates command]
User: [Executes]
AI: [Finds open ports]
User: Enumerate those services
AI: [Generates enumeration commands]
```

### 2. Web App Testing
```
Switch to Web mode
User: Test OWASP Top 10 on target.com
AI: [Creates testing workflow]
  → Directory fuzzing
  → SQL injection
  → XSS testing
  → Result analysis
```

### 3. Generate Exploit
```
User: Create PHP reverse shell for 10.10.14.5:4444
AI: [Generates multiple versions]
  → PHP payload
  → Obfuscated version
  → Listener command
  → Upload instructions
```

---

## 🐛 Quick Fixes

### "API Key Error"
```bash
cat .env  # Verify key exists
# Should show: OPENAI_API_KEY=sk-...
```

### "Command Not Found"
```bash
source venv/bin/activate  # Activate environment first
```

### "Permission Denied"
```bash
chmod +x kali-gpt-advanced.py
# Or use: python3 kali-gpt-advanced.py
```

---

## 💰 Cost Optimization

| Model | Speed | Cost | Use For |
|-------|-------|------|---------|
| gpt-4o | Medium | $$ | Complex tasks |
| gpt-4o-mini | Fast | $ | Quick questions |
| gpt-3.5-turbo | Fastest | ¢ | Simple tasks |

Change model: Menu → 9 → model → Select

---

## 🎯 Pro Tips

1. **Be Specific**: "Scan port 445 on 192.168.1.100 for SMB vulns" > "scan target"
2. **Use History**: AI remembers last 5-10 exchanges
3. **Switch Profiles**: Use appropriate mode for task
4. **Analyze Everything**: Always get AI analysis of outputs
5. **Build Workflows**: Automate repetitive multi-step tasks

---

## 🤖 Autonomous Mode (v4.1)

```bash
# With Ollama (FREE, local)
ollama pull llama3.2 && ollama serve
python3 kali-gpt-autonomous.py

# With OpenAI (cloud)
python3 kali-gpt-autonomous.py --provider openai

# Target a specific IP
python3 kali-gpt-autonomous.py --target 192.168.1.100
```

**Autonomous Menu:**
| Key | Feature |
|-----|---------|
| `1` | 🎯 Autonomous Test — AI decides everything |
| `2` | 👣 Step-by-Step — You confirm each action |
| `3` | 🔧 Quick Scan — Single nmap scan |
| `4` | ❓ Ask AI — Security questions |
| `5` | 🐛 Bug Bounty — Bug bounty workflows |
| `6` | 🔄 Switch Model — Change LLM provider |

See [MODELS.md](MODELS.md) for model recommendations.

---

## 📚 Resources

- Full Docs: `README_ADVANCED.md`
- Features: `FEATURES.md`
- Models Guide: `MODELS.md`
- Config Example: `config.example.json`
- Logs: `~/.kali-gpt/interaction_logs.json`

---

## ⚠️ Remember

- ✅ Authorized testing only
- ✅ Legal pentesting, CTFs, research
- ❌ Never unauthorized access
- ❌ Never malicious use

**Hack ethically. Stay legal.** 🐉
