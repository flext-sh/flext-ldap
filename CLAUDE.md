# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Setup and Installation

```bash
# Activate workspace virtual environment (MANDATORY)
source /home/marlonsc/flext/.venv/bin/activate

# Setup complete development environment
make setup

# Install dependencies only
make install  # or poetry install
```

### Running Tests

```bash
# Run all tests with coverage (95% minimum requirement)
make test  # or pytest (configured in pyproject.toml)

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests
pytest -m "not slow"     # Exclude slow tests
pytest -k test_ldap_connection  # Run specific test

# Run tests in parallel
pytest -n auto

# Generate coverage report
make coverage
```

### Code Quality

```bash
# Run ALL quality checks (ULTRA-STRICT standards)
make check  # Runs format + lint + type-check + security + complexity

# Individual checks
make lint            # Ruff (ALL rules), MyPy, Pylint, Flake8, Bandit, pydocstyle
make type-check      # MyPy strict type checking
make format          # Black + isort code formatting
make security        # Bandit + pip-audit security scans
make complexity      # McCabe complexity analysis
make dead-code       # Vulture dead code detection

# Fix auto-fixable issues
make lint-fix
```

### Building

```bash
make build  # Clean + check + test + poetry build
```

## Architecture Overview

### Project Structure

This is an enterprise LDAP library with clean, minimal implementation following SOLID/KISS/DRY principles. It provides:

- **Async-First Design**: Built with Python 3.13+ async/await patterns
- **Type-Safe**: 100% type hints with strict mypy checking  
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **Enterprise Ready**: Connection pooling, error handling, monitoring integration
- **FLEXT Integration**: Leverages flext-core for minimal duplication

### Key Components

#### 1. Main API (`src/flext_ldap/`)

The core library structure:

```
src/flext_ldap/
├── __init__.py       # Public API exports
├── client.py         # LDAPClient - main async LDAP client
├── models.py         # Pydantic models (LDAPEntry, LDAPFilter, LDAPScope)
├── operations.py     # Core LDAP operations
├── utils.py          # Utility functions
├── config.py         # Configuration management
├── cli.py           # Legacy CLI interface
├── cli_new.py       # New CLI interface  
├── simple_api.py    # Simplified API facade
├── application/     # Application services layer
│   ├── services.py  # Business logic services
│   └── __init__.py
└── domain/          # Domain layer (DDD)
    ├── entities.py      # Domain entities
    ├── value_objects.py # Value objects
    ├── ports.py         # Interfaces/ports
    ├── repositories.py  # Repository interfaces
    └── __init__.py
```

#### 2. Domain-Driven Design

- **Domain Layer**: Core business logic isolated from infrastructure
- **Application Layer**: Services orchestrating domain operations
- **Interface Layer**: CLI and API interfaces
- **Clean Dependencies**: flext-core integration for shared functionality

#### 3. Async-First Architecture

- All LDAP operations are async by default
- Connection management with proper resource cleanup
- Error handling with structured result patterns
- Type-safe interfaces throughout

## Critical Project Context

### FLEXT Framework Integration

This library is part of the FLEXT framework ecosystem and depends on:

- **flext-core**: Foundation classes, logging, configuration, utilities
- **flext-observability**: Monitoring, metrics, tracing integration

### Shared Library Usage

This is a SHARED LIBRARY used by multiple projects in the workspace:

- `algar-oud-mig` - PRODUCTION LDAP migration project
- Other FLEXT LDAP integrations

**CRITICAL**: Changes have CASCADE effects. Always verify dependent project compatibility.

### Python Version Requirement

**REQUIRES Python 3.13** - Latest Python version is mandatory for this project.

### Quality Standards (ULTRA-STRICT)

- **Test Coverage**: 95% minimum (enforced by pytest)
- **Type Safety**: 100% strict typing with MyPy
- **Linting**: Ruff with ALL rules enabled, Pylint 10.0/10 required
- **Security**: Bandit security scanning, pip-audit dependency scanning
- **Code Quality**: Black formatting, isort imports, pydocstyle docstrings

### CLI Interfaces

Two CLI interfaces available:

```bash
# New CLI (recommended)
flext-ldap --help
poetry run python -m flext_ldap.cli_new

# Legacy CLI
flext-ldap-legacy
poetry run python -m flext_ldap.cli
```

## Development Workflow

### Adding New Features

1. **Add to Domain Layer**: Implement core logic in `src/flext_ldap/domain/`
2. **Application Service**: Add orchestration in `src/flext_ldap/application/services.py`
3. **Client Interface**: Expose through `LDAPClient` in `client.py`
4. **Tests**: Add comprehensive tests with appropriate markers
5. **Documentation**: Update docstrings using Google style
6. **Quality Check**: Run `make check` to ensure all standards pass

### Working with Configuration

Configuration is managed through `flext-core` integration:

```python
from flext_ldap.config import LDAPConfig

# Configuration loaded from environment variables or .env file
config = LDAPConfig()
```

### CLI Development

Two CLI entry points for different use cases:

- `cli_new.py` - Modern Click-based CLI (recommended for new features)
- `cli.py` - Legacy CLI (maintained for compatibility)

## Testing Infrastructure

### Test Markers (configured in pyproject.toml)

- `unit` - Fast, isolated unit tests
- `integration` - Tests requiring LDAP server
- `slow` - Slow tests (excluded by default)
- `smoke` - Basic functionality tests
- `e2e` - End-to-end workflow tests
- `ldap` - LDAP-specific tests
- `async` - Async operation tests
- `security` - Security-focused tests
- `performance` - Performance benchmarks
- `requires_ldap_server` - Tests needing real LDAP server

### Running Specific Tests

```bash
# Run specific test categories
pytest -m "unit and not slow"
pytest -m "integration and ldap"
pytest -k "test_client"  # Run tests matching name pattern

# Debug failing tests
make test-debug  # Runs with pdb and detailed output
```

## Project Standards

### Code Organization

- **Domain-First**: Business logic in domain layer, never in infrastructure
- **Async-First**: All I/O operations use async/await
- **Type Safety**: Every function/method must have type hints
- **Error Handling**: Use Result pattern from flext-core
- **Testing**: Every feature requires unit and integration tests

### Documentation Requirements

- **Google-style docstrings** for all public APIs
- **Type hints** for all parameters and return values
- **Examples** in docstrings for complex operations
- **ADRs** for architectural decisions (see `docs/architecture/adr/`)

### Makefile Commands Reference

Essential commands for development:

```bash
make help          # Show all available commands
make setup         # One-time development setup
make check         # All quality checks (required before commit)
make test          # Run all tests with coverage
make coverage      # Generate HTML coverage report
make clean         # Clean build artifacts
make build         # Full build process
make ci            # Run full CI pipeline locally
```
