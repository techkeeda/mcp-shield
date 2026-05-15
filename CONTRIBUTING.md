# Contributing to MCP Shield

Thank you for your interest in contributing! MCP Shield is an open-source project and we welcome contributions of all kinds.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Include your Python version, OS, and MCP Shield version
- For security vulnerabilities, email security@mcp-shield.dev instead of opening a public issue

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `pytest`
6. Submit a pull request

### Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/mcp-shield.git
cd mcp-shield
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

### Code Style

- Follow PEP 8
- Use type hints for all function signatures
- Add docstrings to public classes and methods
- Keep functions focused and small

### Areas We Need Help

- Additional threat detection patterns
- Integration tests with real MCP servers
- Documentation improvements
- Support for more MCP transport types (SSE, HTTP)
- Dashboard/UI for audit log visualization

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to make AI agents safer.
