# Security Policy

## 🔒 Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < Latest| :x:                |

**Recommendation:** Always use the latest version for the most up-to-date security features and patches.

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability in Kali GPT, please follow responsible disclosure:

### DO:
1. **Email maintainers directly** with details
2. Provide step-by-step reproduction
3. Include potential impact assessment
4. Allow reasonable time for patch (typically 90 days)
5. Coordinate disclosure timing

### DO NOT:
- Open a public GitHub issue
- Disclose vulnerability publicly before patch
- Exploit the vulnerability maliciously
- Share details with unauthorized parties

### What to Include:
- Description of the vulnerability
- Affected versions
- Steps to reproduce
- Potential impact and severity
- Suggested fix (if available)
- Your contact information

### Response Timeline:
- **24-48 hours**: Initial acknowledgment
- **7 days**: Preliminary assessment
- **30-90 days**: Patch development and testing
- **Coordinated disclosure**: Public announcement

## 🛡️ Security Features

Kali GPT includes multiple security controls:

### Command Execution Safety
- ✅ Dangerous command detection
- ✅ User confirmation before execution
- ✅ Command timeout protection
- ✅ Input sanitization
- ✅ Execution logging

### Data Protection
- ✅ API keys stored in `.env` (git-ignored)
- ✅ Sensitive data excluded from logs
- ✅ Local-only data storage
- ✅ No third-party analytics
- ✅ Encrypted API communication (HTTPS)

### Audit Trail
- ✅ All commands logged with timestamps
- ✅ Conversation history maintained
- ✅ Failed command attempts recorded
- ✅ User confirmations logged

## ⚠️ Security Considerations for Users

### API Key Security
```bash
# GOOD: API key in .env file (git-ignored)
OPENAI_API_KEY=sk-your-key-here

# BAD: Hardcoding API key in code
client = OpenAI(api_key="sk-your-key-here")  # DON'T DO THIS
```

### Command Execution Risks
- Always review commands before execution
- Use `require_confirmation: true` in settings
- Be cautious with commands from untrusted sources
- Test in isolated environments first

### Sensitive Data in Logs
```bash
# Review and clean logs regularly
~/.kali-gpt/interaction_logs.json
~/.kali-gpt/conversation_history.json

# Remove sensitive data
# Logs may contain:
# - Target IP addresses
# - Command outputs
# - Potential credentials found
```

### Network Communication
- All OpenAI API calls use HTTPS
- No data sent to third parties
- API requests may contain:
  - Your questions/prompts
  - Command outputs (for analysis)
  - Tool responses

## 🔐 Best Practices for Secure Usage

### 1. API Key Management
```bash
# Generate new API key for this tool
# Don't reuse keys across multiple tools
# Rotate keys periodically
# Use OpenAI API key restrictions if available
```

### 2. Environment Isolation
```bash
# Use Kali GPT in isolated environments
# Don't run on production systems
# Use VMs or containers for testing
# Separate credentials for lab vs. production
```

### 3. Access Control
```bash
# Restrict file permissions
chmod 600 ~/.kali-gpt/config.json
chmod 600 .env

# Don't run as root unnecessarily
# Use sudo only when required for specific commands
```

### 4. Audit and Review
```bash
# Regularly review logs
cat ~/.kali-gpt/interaction_logs.json | jq

# Monitor for unauthorized usage
# Check for unexpected commands
# Review API usage on OpenAI dashboard
```

### 5. Update Regularly
```bash
# Keep Kali GPT updated
cd kali-gpt
git pull origin main
pip install -r requirements.txt --upgrade
```

## 🚫 Known Security Limitations

### By Design:
1. **Command Execution**: Tool can execute any command user confirms
2. **API Communication**: Prompts/outputs sent to OpenAI API
3. **Local Storage**: Logs stored unencrypted locally
4. **User Trust**: Assumes user has proper authorization

### Mitigations:
- Confirmation prompts before execution
- Dangerous command detection
- Clear documentation and warnings
- Audit logging

## 📋 Security Checklist for Users

Before using Kali GPT on an engagement:

- [ ] Confirmed authorized testing scope
- [ ] API key secured in `.env` file
- [ ] `.env` added to `.gitignore`
- [ ] Reviewed and understood command execution risks
- [ ] Enabled `require_confirmation` setting
- [ ] Set up in isolated testing environment
- [ ] Understand data sent to OpenAI API
- [ ] Have plan for handling sensitive findings
- [ ] Know how to review/clean logs
- [ ] Updated to latest version

## 🔍 Vulnerability Disclosure History

_(None currently - first release)_

Future security advisories will be listed here.

## 📞 Contact

For security concerns:
- Create an issue (for non-sensitive matters)
- Use GitHub Security Advisory (for vulnerabilities)

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

**Remember:** Security is a shared responsibility. Use Kali GPT ethically, legally, and responsibly.
