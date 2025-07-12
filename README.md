# FLEXT-LDAP

Enterprise LDAP Operations Library for FLEXT Framework

[![CI](https://github.com/flext-sh/flext-ldap/actions/workflows/ci.yml/badge.svg)](https://github.com/flext-sh/flext-ldap/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/flext-sh/flext-ldap/branch/main/graph/badge.svg)](https://codecov.io/gh/flext-sh/flext-ldap)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Type checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue)](http://mypy-lang.org/)

## Features

- 🚀 **Async-First**: Built with Python 3.13+ async/await
- 🔒 **Type-Safe**: 100% type hints with strict mypy checking
- 🏗️ **Clean Architecture**: SOLID principles, DDD patterns
- 📊 **Enterprise Ready**: Connection pooling, retries, monitoring
- 🧪 **Well Tested**: >95% test coverage
- 📚 **Documented**: Google-style docstrings throughout

## Installation

```bash
pip install flext-ldap
```

## Quick Start

```python
import asyncio
from flext_ldap import LDAPClient, LDAPConfig

async def main():
    config = LDAPConfig(
        server="ldap.example.com",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        bind_password="secret",
        base_dn="dc=example,dc=com"
    )

    async with LDAPClient(config) as client:
        # Search users
        result = await client.search(
            filter_obj="(objectClass=person)",
            attributes=["cn", "mail"]
        )

        if result.is_success:
            for entry in result.value:
                print(f"User: {entry.dn}")

asyncio.run(main())
```

## Development

This project uses a centralized configuration in `pyproject.toml` and is orchestrated via `Makefile`.

### Setup

```bash
# Clone the repository
git clone https://github.com/flext-sh/flext-ldap
cd flext-ldap

# Setup development environment
make setup
```

### Common Commands

```bash
# Show all available commands
make help

# Run all checks (lint, type, security, etc.)
make check

# Run tests
make test

# Format code
make format

# Build package
make build
```

### Code Quality

This project enforces **ULTRA-STRICT** code quality standards:

- **Ruff**: ALL rules enabled (`select = ["ALL"]`)
- **MyPy**: Strict mode with all checks
- **Pylint**: 10.0/10 score required
- **Black**: Code formatting
- **isort**: Import sorting
- **Bandit**: Security scanning
- **Coverage**: >95% required

All tools are configured in `pyproject.toml` for single source of truth.

### Pre-commit

Pre-commit hooks are configured for all quality checks:

```bash
# Install pre-commit hooks
make setup

# Run manually
make pre-commit
```

## Project Structure

```
flext-ldap/
├── src/
│   └── flext_ldap/         # Main package
│       ├── __init__.py
│       ├── client.py       # LDAP client implementation
│       ├── models.py       # Pydantic models
│       ├── operations.py   # LDAP operations
│       ├── result.py       # Result pattern
│       ├── utils.py        # Utilities
│       └── cli.py          # CLI interface
├── tests/                  # Test suite
├── docs/                   # Documentation
├── pyproject.toml         # Single config file
├── Makefile               # Task orchestration
└── README.md
```

## Standards

This project follows FLEXT standards:

- ✅ Python 3.13+ only
- ✅ Async/await patterns
- ✅ Type hints 100%
- ✅ PEP compliance
- ✅ Security scanning
- ✅ Single source of configuration

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Make your changes
4. Run `make check` to ensure quality
5. Commit your changes
6. Push to the branch
7. Open a Pull Request

All contributions must pass CI checks.
