# Development Guide


<!-- TOC START -->
- Overview
- Table of Contents
  - Getting Started
  - Development Practices
  - Contributing
- Quick Start
  - Initial Setup
  - Development Cycle
- Quality Standards
  - ZERO TOLERANCE
  - Code Quality Rules
- Testing
  - Test Categories
  - Docker Test Server
- Essential Commands
- FLEXT Patterns
  - Railway-Oriented Programming
  - Use x
  - Pydantic v2 Models
- Git Workflow
  - Branch Naming
  - Commit Messages
- Pull Request Checklist
- Getting Help
  - Resources
  - Communication
- Best Practices
  - DO ✅
  - DON'T ❌
- Related Documentation
<!-- TOC END -->

**Version**: 1.0
**Date**: 2025-01-24
**Target**: v0.10.0+

## Overview

Comprehensive development guides for contributing to flext-ldap, including setup, workflow, testing, and quality standards.

## Table of Contents

### Getting Started

1. **Setup** - Development environment setup
2. **Workflow** - Development workflow and git process
3. **Quality Gates** - ZERO TOLERANCE standards

### Development Practices

4. **Testing Guide** - Unit, integration, E2E testing
5. **Code Standards** - Style, types, documentation
6. **Architecture Guide** - Clean Architecture patterns

### Contributing

7. **Contributing** - How to contribute
8. **Pull Request Guide** - PR process and checklist
9. **Release Process** - Versioning and releases

## Quick Start

### Initial Setup

```bash
# Clone repository
git clone <repository-url>
cd flext-ldap

# Setup development environment
make setup

# Verify installation
make validate
```

### Development Cycle

```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Make changes
# ... edit files ...

# 3. Run quality gates (MANDATORY)
make validate

# 4. Run tests
make test

# 5. Commit and push
git add .
git commit -m "feat: add new feature"
git push origin feature/my-feature

# 6. Create pull request
```

## Quality Standards

### ZERO TOLERANCE

**Required before EVERY commit**:

```bash
make validate  # Must pass: lint + type + security + test
```

**Standards**:

- ✅ Ruff linting: ZERO violations
- ✅ Pyrefly type checking: ZERO errors
- ✅ Bandit security: ZERO critical issues
- ✅ Test coverage: 75%+ for new features
- ✅ All tests passing

### Code Quality Rules

1. **Use FlextResult[T]** for all operations
2. **Complete type annotations** (Python 3.13+ syntax)
3. **Pydantic v2** for models
4. **Clean Architecture** - respect layer boundaries
5. **Zero duplication** - use flext-core patterns

## Testing

### Test Categories

```bash
pytest -m unit              # Fast unit tests
pytest -m integration       # Integration tests (Docker)
pytest -m ldap              # LDAP-specific tests
pytest -m "not slow"        # Fast tests only
```

### Docker Test Server

```bash
make ldap-start    # Start OpenLDAP test container
make ldap-health   # Check health
make ldap-stop     # Stop container
```

## Essential Commands

```bash
# Quality gates
make lint          # Ruff linting
make type-check    # Pyrefly type checking
make security      # Bandit security scan
make test          # Run all tests
make validate      # Complete validation

# Auto-fix
make format        # Format code
make fix           # Auto-fix linting issues

# Docker
make ldap-start    # Start test LDAP server
make ldap-stop     # Stop test LDAP server

# Cleanup
make clean         # Clean build artifacts
make clean-all     # Deep clean including venvs
```

## FLEXT Patterns

### Railway-Oriented Programming

```python
from flext_core import FlextResult

def my_operation(data: dict) -> FlextResult[ProcessedData]:
    """Always return FlextResult[T]."""
    if not data:
        return FlextResult[ProcessedData].fail("Data required")

    return (
        validate(data)
        .flat_map(transform)
        .map(enrich)
    )
```

### Use x

```python
from flext_core import FlextService

class MyService(FlextService[None]):
    """Inherit from FlextService to get mixins."""

    def operation(self):
        # ✅ Use inherited properties
        self.logger.info("message")  # From x
        timeout = self.config.timeout  # From x
        service = self.container.get("service")  # From x
```

### Pydantic v2 Models

```python
from pydantic import BaseModel, PositiveInt

class Config(BaseModel):
    """Use Pydantic v2 native types."""
    timeout: PositiveInt  # Built-in validation
    host: str
```

## Git Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Refactoring
- `docs/description` - Documentation
- `test/description` - Test improvements

### Commit Messages

Follow Conventional Commits:

```
feat: add new LDAP operation
fix: resolve connection timeout issue
refactor: simplify authentication logic
docs: update API documentation
test: add integration tests for OID
```

## Pull Request Checklist

- [ ] Code follows FLEXT patterns
- [ ] All quality gates pass (`make validate`)
- [ ] Tests pass (`make test`)
- [ ] Test coverage maintained (75%+)
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)
- [ ] No breaking changes (or documented)
- [ ] Self-review completed

## Getting Help

### Resources

- **Architecture**: docs/architecture/
- **API Reference**: docs/api/
- **Refactoring Docs**: docs/refactoring/

### Communication

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Security**: Private maintainer contact

## Best Practices

### DO ✅

- Use FlextResult[T] for all operations
- Complete type annotations
- Follow Clean Architecture
- Write tests for new features
- Document public APIs
- Run `make validate` before commits

### DON'T ❌

- Use exceptions for business logic
- Duplicate flext-core functionality
- Skip quality gates
- Commit without tests
- Break layer boundaries
- Use `Any` types

## Related Documentation

- Architecture - System architecture
- API Reference - Complete API docs
- Migration Guide - v0.9.0 → v0.10.0

---

**Last Updated**: 2025-01-24
**Maintainer**: FLEXT Team
