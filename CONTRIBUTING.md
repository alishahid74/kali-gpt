# Contributing to Kali GPT

Thank you for your interest in contributing to Kali GPT! We welcome contributions from the security community.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, Ollama version, model used)
- Relevant logs or error messages

### Suggesting Features

Feature requests are welcome! Please include:
- Clear description of the feature
- Use case and benefits
- Potential implementation approach
- Any security considerations

### Pull Requests

1. **Fork the repository**
   ```bash
   git clone https://github.com/alishahid74/kali-gpt
   cd kali-gpt
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation as needed
   - Test your changes thoroughly

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add: Brief description of your changes"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a Pull Request on GitHub

## 📝 Coding Standards

### Python Style
- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions focused and modular

### Security Considerations
- **CRITICAL**: All new features must include safety controls
- Never remove or weaken existing security checks
- Add confirmation prompts for dangerous operations
- Validate all user inputs
- Sanitize commands before execution
- Document security implications

### Documentation
- Update README.md for new features
- Add examples for new functionality
- Update QUICK_START.md if adding menu options
- Comment complex code sections

## 🔒 Security Guidelines

### Responsible Development
- Only add features for **authorized** security testing
- Include safety warnings for dangerous operations
- Never encourage illegal activities
- Add proper error handling
- Validate and sanitize all inputs

### Testing Security Features
- Test with safe, isolated environments
- Never test on production systems
- Use local VMs or authorized lab environments
- Document testing procedures

## 🎯 Priority Areas

We especially welcome contributions in:

### High Priority
- [ ] More fallback commands for autonomous mode
- [ ] Better prompts for different models
- [ ] Unit tests and test coverage
- [ ] Integration with more Kali tools
- [ ] Improved error handling
- [ ] Better command parsing and validation

### Medium Priority
- [ ] Custom Modelfile presets for different use cases
- [ ] Report generation improvements
- [ ] Additional security profiles
- [ ] Web interface
- [ ] Unit tests and test coverage improvements

### Already Implemented (in Enhanced/Autonomous versions)
- ✅ Team collaboration features (`kali_gpt/integrations/collaboration.py`)
- ✅ Attack tree visualization (`attack_tree.py`)
- ✅ Multi-target management (`kali_gpt/modules/target_manager.py`)
- ✅ Database integration for findings (SQLite via `kali_gpt/memory/store.py`)
- ✅ Custom tool profiles (`kali_gpt/modules/profile_manager.py`)

## 🔧 Adding New Tools (v3.0)

To add support for a new penetration testing tool:

1. **Add to VALID_TOOLS** in `kali-gpt-autonomous.py`:
   ```python
   VALID_TOOLS = {
       'nmap', 'nikto',
       'your-new-tool',  # Add here
       ...
   }
   ```

2. **Add timeout** if needed in `get_timeout()`:
   ```python
   def get_timeout(tool):
       if tool in ['nmap', 'masscan']:
           return 300
       elif tool == 'your-new-tool':
           return 120  # Add custom timeout
       ...
   ```

3. **Add fallback command** (optional):
   ```python
   self.fallbacks = [
       f"nmap -sV {target}",
       f"your-new-tool --option {target}",  # Add here
       ...
   ]
   ```

## 🐬 Adding Model Support (v3.0)

To add a new uncensored model:

1. **Add to UNCENSORED_MODELS** list:
   ```python
   UNCENSORED_MODELS = [
       'kali-pentester',
       'dolphin-llama3',
       'your-new-model',  # Add here
       ...
   ]
   ```

2. **Create a Modelfile** (optional):
   ```dockerfile
   # Modelfile.your-model
   FROM base-model
   PARAMETER temperature 0.7
   SYSTEM """Your custom system prompt for pentesting..."""
   ```

3. **Update install-models.sh** if needed

## 🧪 Testing

Before submitting a PR:

1. **Test autonomous mode**
   ```bash
   python3 kali-gpt-autonomous.py
   # Test with different models
   # Test on safe targets like scanme.nmap.org
   ```

2. **Test model selection**
   ```bash
   # Option 6 should show all models
   # Switching should work
   ```

3. **Test command validation**
   ```python
   # These should be accepted
   assert is_valid_command("nmap -sV target") == True
   
   # These should be rejected
   assert is_valid_command("Scan the target") == False
   ```

4. **Syntax check**
   ```bash
   python3 -m py_compile kali-gpt-autonomous.py
   ```

5. **Test with both model types**
   - Test with uncensored model (dolphin-llama3)
   - Test with standard model (llama3.2)
   - Verify fallback system works when LLM gives bad output

## 📋 Commit Message Guidelines

Use clear, descriptive commit messages:

```
Add: New feature description
Fix: Bug fix description
Update: Enhancement to existing feature
Docs: Documentation updates
Security: Security-related changes
Refactor: Code refactoring
Test: Adding or updating tests
```

Examples:
- `Add: nuclei support with timeout config`
- `Fix: gobuster not including target in command`
- `Update: Better prompts for dolphin models`
- `Docs: Update MODELS.md with new recommendations`

## 🚫 What We Won't Accept

- Features designed for malicious use
- Removal of safety controls or command validation
- Encouraging unauthorized access
- Poorly documented code
- Breaking changes without discussion
- Code that violates ethical hacking principles
- Removal of confirmation prompts

## 🔐 Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email the maintainers directly
3. Provide detailed information
4. Allow time for a fix before disclosure
5. We'll credit you in the fix (if desired)

## 💬 Getting Help

- Check existing issues and documentation
- Read MODELS.md for model-related questions
- Ask questions in issue discussions
- Be respectful and patient
- Provide context and examples

## 📜 Code of Conduct

### Our Standards

- Be respectful and inclusive
- Focus on what's best for the community
- Show empathy towards others
- Accept constructive criticism
- Use welcoming and inclusive language

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Encouraging illegal activities
- Any unethical conduct

## 🎓 Learning Resources

New to contributing? Check out:
- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)
- [Python PEP 8](https://www.python.org/dev/peps/pep-0008/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Ollama Documentation](https://ollama.com/docs)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License with the security notice as specified in the LICENSE file.

## 🙏 Recognition

Contributors will be recognized in:
- Release notes
- CHANGELOG.md
- Special thanks in major releases

---

**Thank you for helping make Kali GPT better! 🐉**

Together, we're building a tool that helps security professionals work more efficiently while maintaining the highest ethical standards.
