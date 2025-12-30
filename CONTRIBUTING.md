# Contributing to Kali GPT

Thank you for your interest in contributing to Kali GPT! We welcome contributions from the security community.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)
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
- [ ] Unit tests and test coverage
- [ ] Integration with more Kali tools
- [ ] Improved error handling
- [ ] Performance optimizations
- [ ] Better command parsing and validation

### Medium Priority
- [ ] Additional security profiles
- [ ] Report generation features
- [ ] Multi-target management
- [ ] Plugin system architecture
- [ ] Alternative AI model support

### Nice to Have
- [ ] GUI/Web interface
- [ ] Team collaboration features
- [ ] Database integration for findings
- [ ] Automated vulnerability scanning
- [ ] Custom tool profiles

## 🧪 Testing

Before submitting a PR:

1. **Test the basic functionality**
   ```bash
   source venv/bin/activate
   ./kali-gpt.py
   # Test basic features
   ```

2. **Test the advanced version**
   ```bash
   ./kali-gpt-advanced.py
   # Test your new feature
   # Test existing features still work
   ```

3. **Test edge cases**
   - Invalid inputs
   - Missing dependencies
   - Network errors
   - Permission issues

4. **Check for errors**
   ```bash
   python3 -m py_compile kali-gpt-advanced.py
   ```

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
- `Add: Wireless security profile with aircrack-ng integration`
- `Fix: Command timeout not being respected`
- `Security: Add validation for user-provided file paths`
- `Docs: Update README with new installation instructions`

## 🚫 What We Won't Accept

- Features designed for malicious use
- Removal of safety controls
- Encouraging unauthorized access
- Poorly documented code
- Breaking changes without discussion
- Code that violates ethical hacking principles

## 🔐 Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email the maintainers directly
3. Provide detailed information
4. Allow time for a fix before disclosure
5. We'll credit you in the fix (if desired)

## 💬 Getting Help

- Check existing issues and documentation
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

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License with the security notice as specified in the LICENSE file.

## 🙏 Recognition

Contributors will be recognized in:
- Release notes
- Contributors section (coming soon)
- Special thanks in major releases

---

**Thank you for helping make Kali GPT better! 🐉**

Together, we're building a tool that helps security professionals work more efficiently while maintaining the highest ethical standards.
