# Contributing to FLEXT LDAP

Thank you for your interest in contributing to FLEXT LDAP! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Development Process

### 1. Setting Up Your Development Environment

**Note**: This is part of the FLEXT workspace. Development setup differs from standalone projects.

```bash
# Workspace setup (use workspace virtual environment)
cd /home/marlonsc/flext/flext-ldap
source /home/marlonsc/flext/.venv/bin/activate

# Install dependencies using Poetry
poetry install --all-extras

# Verify installation
python -c "from flext_ldap import LDAPService; print('✅ Installation successful')"
```

### 2. Code Standards

This project enforces strict code quality standards:

- **Python Version**: 3.13+
- **Code Style**: Ruff formatter (automatically applied)
- **Linting**: Ruff with standard rules
- **Type Checking**: MyPy in strict mode
- **Test Coverage**: Target 95% (current: 37.97%)

### 3. Pre-commit Checks

Before committing, ensure your code passes all quality checks:

```bash
# Run all checks
make check

# Individual checks  
ruff check src/       # Linting
mypy src/ --strict    # Type checking
ruff format src/      # Format code
pytest --cov=src/flext_ldap --cov-report=term-missing  # Tests with coverage
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

## Questions

- Open a GitHub Discussion for general questions
- Check existing documentation first
- Be specific and provide context

Thank you for contributing to FLEXT LDAP!
