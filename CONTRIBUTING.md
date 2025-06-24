# Contributing to OpenX

We welcome contributions to OpenX! This document provides guidelines for contributing to the project.

## Ways to Contribute

### 1. Bug Reports
- Use the GitHub issue tracker
- Include detailed reproduction steps
- Provide system information (OS, Python version)
- Include full error messages and logs

### 2. Feature Requests
- Check existing issues for similar requests
- Provide clear use cases and examples
- Explain the security impact or improvement

### 3. Code Contributions
- Fork the repository
- Create a feature branch
- Follow coding standards
- Include tests for new features
- Update documentation

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/openx.git
cd openx

# Create virtual environment
python -m venv dev-env
source dev-env/bin/activate  # Linux/Mac
# OR
dev-env\Scripts\activate     # Windows

# Install dependencies
pip install flask colorama requests urllib3

# Install development dependencies (optional)
pip install pytest black flake8
```

## Coding Standards

### Python Style
- Follow PEP 8 guidelines
- Use descriptive variable names
- Include docstrings for functions and classes
- Keep functions focused and small

### Payload Development
- Test all new payloads against the Flask lab
- Include comments explaining bypass techniques
- Verify payloads work in real-world scenarios
- Document encoding variations

### Testing
- Test new features against the Flask lab
- Include both positive and negative test cases
- Verify compatibility with different Python versions
- Test on different operating systems

## Submission Process

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/openx.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/amazing-new-feature
   ```

3. **Make Changes**
   - Write code following our standards
   - Test thoroughly
   - Update documentation

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "Add amazing new feature"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/amazing-new-feature
   ```

## Areas for Contribution

### High Priority
- New bypass payload techniques
- Performance optimizations
- Additional output formats
- Integration with more external tools

### Medium Priority
- UI/UX improvements for Flask lab
- Documentation enhancements
- Error handling improvements
- Code refactoring

### Low Priority
- Additional test cases
- Configuration file support
- Plugin architecture
- Alternative language bindings

## Payload Contribution Guidelines

When contributing new payloads:

1. **Test Effectiveness**
   - Verify against multiple targets
   - Test against common WAF solutions
   - Document success rates

2. **Categorize Properly**
   - Basic redirects
   - Encoding bypasses
   - Protocol manipulation
   - Domain validation bypasses
   - Header injection
   - Enterprise-specific

3. **Document Technique**
   - Explain the bypass method
   - Reference related CVEs or research
   - Include real-world examples

## Security Considerations

- Never include actual malicious URLs
- Use example.com, evil.com, or similar test domains
- Ensure payloads are for legitimate security testing only
- Follow responsible disclosure practices

## Review Process

1. **Automated Checks**
   - Code style validation
   - Basic functionality tests
   - Security scanning

2. **Manual Review**
   - Code quality assessment
   - Security impact evaluation
   - Documentation review

3. **Testing**
   - Functionality verification
   - Performance impact assessment
   - Compatibility testing

## Release Process

Major releases include:
- New vulnerability detection techniques
- Significant performance improvements
- Major feature additions

Minor releases include:
- Bug fixes
- Small feature additions
- Documentation updates

## Recognition

Contributors will be:
- Listed in the project contributors
- Credited in release notes
- Mentioned in relevant documentation

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help newcomers learn
- Maintain project quality standards

## Getting Help

- Join GitHub Discussions for questions
- Use GitHub Issues for bug reports
- Check existing documentation first
- Provide detailed information when asking for help

## License

By contributing to OpenX, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to OpenX!