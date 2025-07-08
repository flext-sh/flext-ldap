# Contributing to FLEXT LDAP

Thank you for your interest in contributing to FLEXT LDAP! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Development Process

### 1. Setting Up Your Development Environment

```bash
# Clone the repository
git clone https://github.com/flext-sh/flext-ldap.git
cd flext-ldap

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
poetry install --with dev
```

### 2. Code Standards

This project enforces strict code quality standards:

- **Python Version**: 3.13+
- **Code Style**: Black formatter (automatically applied)
- **Linting**: Ruff with ALL rules enabled
- **Type Checking**: MyPy in strict mode
- **Test Coverage**: Minimum 95%

### 3. Pre-commit Checks

Before committing, ensure your code passes all quality checks:

```bash
# Run all checks
make check

# Individual checks
ruff check .          # Linting
mypy src/ --strict    # Type checking
black .               # Format code
pytest --cov-fail-under=95  # Tests with coverage
```

### 4. Making Changes

1. **Create a branch**: `git checkout -b feature/your-feature-name`
2. **Make your changes**: Follow the existing code patterns and style
3. **Add tests**: All new code must have comprehensive tests
4. **Update documentation**: Include docstrings and update relevant docs
5. **Run checks**: Ensure all quality checks pass

### 5. Commit Messages

Follow the conventional commits specification:

```
type(scope): brief description

Longer explanation if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### 6. Testing

Write tests for all new functionality:

```python
# Unit tests in tests/unit/
# Integration tests in tests/integration/
# End-to-end tests in tests/e2e/
```

Run specific test categories:
```bash
pytest -m unit
pytest -m integration
pytest -m "not slow"
```

### 7. Documentation

- Add docstrings to all public functions and classes
- Follow Google style docstrings
- Update README.md if adding new features
- Add examples in `examples/` for complex features

## Pull Request Process

1. **Update dependencies**: If you add dependencies, update `pyproject.toml`
2. **Update CHANGELOG.md**: Add your changes under "Unreleased"
3. **Ensure CI passes**: All GitHub Actions must pass
4. **Request review**: Tag maintainers for review
5. **Address feedback**: Make requested changes promptly

## Reporting Issues

When reporting issues, please include:

1. Python version and OS
2. Complete error traceback
3. Minimal code example to reproduce
4. Expected vs actual behavior

## Feature Requests

Feature requests are welcome! Please:

1. Check existing issues first
2. Provide clear use case
3. Explain why it benefits the project
4. Consider submitting a PR

## Questions?

- Open a GitHub Discussion for general questions
- Check existing documentation first
- Be specific and provide context

Thank you for contributing to FLEXT LDAP!