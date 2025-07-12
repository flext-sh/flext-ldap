# FLEXT-LDAP

**Enterprise LDAP Operations Library for FLEXT Framework**

*Built on FLEXT-Core foundation with Clean Architecture and Domain-Driven Design*

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-48%25-yellow.svg)]()
[![Type Safety](https://img.shields.io/badge/mypy-strict-green.svg)]()
[![FLEXT Framework](https://img.shields.io/badge/FLEXT-ecosystem-blue.svg)]()

## Overview

FLEXT-LDAP provides enterprise-grade LDAP operations built on the **FLEXT Framework** foundation. Using Clean Architecture and Domain-Driven Design principles, it delivers type-safe LDAP integration with production-ready features.

### FLEXT Framework Integration

- **flext-core**: Foundation library providing ServiceResult pattern, domain modeling, and configuration management
- **flext-observability**: Structured logging, health checks, and monitoring integration
- **Architecture**: Clean hexagonal architecture with dependency injection following FLEXT patterns

### Enterprise Usage

**Active Deployments**: Powers `client-a-oud-mig` enterprise Oracle migration project
**FLEXT Ecosystem**: Used by `flext-tap-ldap`, `flext-target-ldap`, `flext-dbt-ldap` for LDAP data operations

## Key Features

### FLEXT Foundation
- **ServiceResult Pattern**: Type-safe error handling following FLEXT-Core standards
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **Configuration Management**: FLEXT BaseSettings with environment variable support
- **Dependency Injection**: Uses flext-core patterns for service orchestration

### LDAP Operations
- **Real LDAP Integration**: Built on ldap3 library for production directory operations
- **Protocol Compliance**: Search, modify, add, delete operations with RFC compliance
- **Connection Management**: TLS/SSL support with secure credential handling
- **Memory Fallback**: Complete in-memory implementation for testing environments

### Enterprise Integration
- **Production Deployments**: Powers enterprise migration projects (client-a-oud-mig)
- **FLEXT Ecosystem**: Integrates with flext-observability for monitoring
- **Async Operations**: Python 3.13+ async/await for high-performance operations
- **CLI Interface**: Command-line tools following FLEXT patterns

## Installation

**Part of FLEXT Framework**: This module requires the complete FLEXT workspace environment.

```bash
# Setup FLEXT workspace (required)
source /home/marlonsc/flext/.venv/bin/activate
cd flext-ldap

# Install dependencies
poetry install

# Verify FLEXT integration
python -c "from flext_ldap import LDAPService; print('✅ FLEXT-LDAP ready')"
```

## Quick Start

### Basic Usage (FLEXT ServiceResult Pattern)

```python
import asyncio
from flext_ldap import LDAPService
from flext_ldap.domain.value_objects import CreateUserRequest

async def main():
    # Initialize FLEXT-LDAP service
    ldap_service = LDAPService()
    
    # Create user using FLEXT ServiceResult pattern
    request = CreateUserRequest(
        dn="cn=john.doe,ou=people,dc=example,dc=com",
        uid="john.doe",
        cn="John Doe", 
        sn="Doe",
        mail="john.doe@example.com"
    )
    
    # ServiceResult provides type-safe error handling
    result = await ldap_service.create_user(request)
    if result.is_success:
        user = result.value  # Type: LDAPUser
        print(f"✅ Created user: {user.cn}")
    else:
        error = result.error_message  # Type: str
        print(f"❌ Error: {error}")

asyncio.run(main())
```

### Connecting to Real LDAP Server

```python
# Connect to real LDAP server
connection_result = await ldap_service.connect_to_server(
    "ldap://your-ldap-server.com:389",
    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", 
    "your_password"
)

if connection_result.is_success:
    # Operations now use real LDAP server
    print("✅ Connected to LDAP server")
else:
    # Operations continue in memory mode
    print(f"⚠️ Using memory mode: {connection_result.error_message}")
```

## Configuration

### Environment Variables

```bash
# LDAP Server settings
LDAP_SERVER=ldap://your-server.com
LDAP_PORT=389
LDAP_USE_TLS=false
LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
LDAP_BIND_PASSWORD=your_password

# Search settings  
LDAP_BASE_DN=dc=example,dc=com
LDAP_TIMEOUT=30
```

### Configuration Class

```python
from flext_ldap.config import LDAPConfig

config = LDAPConfig(
    server="ldap.example.com",
    port=389,
    use_ssl=False,
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    bind_password="password"
)
```

## CLI Tools

The library includes command-line tools for LDAP operations:

```bash
# Test connection
python -m flext_ldap.cli_new test ldap.example.com --port 389

# Search directory
python -m flext_ldap.cli_new search ldap.example.com "dc=example,dc=com" --filter "(cn=*)"
```

## Development

### Project Structure

```
src/flext_ldap/
├── application/        # Application services
│   ├── ldap_service.py # Main LDAP service  
│   └── services.py     # Supporting services
├── domain/             # Domain layer
│   ├── entities.py     # Domain entities (User, Group, etc.)
│   ├── ports.py        # Repository interfaces
│   └── value_objects.py # Value objects
├── infrastructure/     # Infrastructure layer
│   ├── ldap_client.py  # LDAP client implementation
│   └── repositories.py # Repository implementations
├── config.py           # Configuration management
├── utils.py           # LDAP utilities
└── cli_new.py         # Command-line interface
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage  
pytest --cov=src/flext_ldap --cov-report=term-missing

# Run specific test types
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
```

### Code Quality

```bash
# Linting
ruff check src/

# Type checking
mypy src/ --strict

# Formatting  
ruff format src/

# Security scanning
bandit -r src/
```

## Architecture

Built on **FLEXT Framework** with Clean Architecture and Domain-Driven Design, extending flext-core patterns for LDAP operations.

### FLEXT Integration Architecture

```
FLEXT-LDAP extends FLEXT-Core:
├── flext-core/          # Foundation (ServiceResult, DI, Config)
└── flext-ldap/         # LDAP-specific implementation
    ├── domain/         # LDAP business logic
    ├── application/    # LDAP use cases
    └── infrastructure/ # LDAP integrations
```

### Layer Structure (FLEXT-Aligned)

```
src/flext_ldap/
├── domain/              # Domain layer (extends flext-core)
│   ├── entities.py      # Business entities (User, Group, Connection)
│   ├── value_objects.py # Immutable values (DN, Filter, Config)
│   └── ports.py         # Service contracts and interfaces
├── application/         # Application layer (uses ServiceResult)
│   ├── ldap_service.py  # Main LDAP service (FLEXT facade)
│   └── services.py      # Supporting application services
├── infrastructure/     # Infrastructure layer
│   ├── ldap_client.py   # Real LDAP client (ldap3)
│   └── repositories.py  # Repository implementations
├── config.py           # FLEXT BaseSettings extension
├── simple_api.py       # Simplified API facade
└── cli_new.py          # CLI interface (Click-based)
```

### Key Architectural Patterns

#### 1. Clean Architecture Boundaries
- **Domain Layer**: Contains business entities, value objects, and business rules
- **Application Layer**: Orchestrates use cases, no framework dependencies
- **Infrastructure Layer**: Handles external concerns (LDAP, file I/O, databases)

#### 2. Service Result Pattern
All operations return `ServiceResult[T]` for type-safe error handling:
```python
result = await ldap_service.create_user(request)
if result.is_success:
    user = result.value  # Type: LDAPUser
else:
    error = result.error_message  # Type: str
```

#### 3. Repository Pattern
Data access abstracted through repository interfaces:
```python
# Domain defines the contract
class LDAPUserRepository(ABC):
    async def save(self, user: LDAPUser) -> ServiceResult[LDAPUser]: ...

# Infrastructure provides implementations
class LDAPUserRepositoryImpl(LDAPUserRepository):
    # Real LDAP implementation
```

#### 4. Dependency Injection
Uses flext-core DI container for loose coupling:
```python
@injectable()
class LDAPService:
    def __init__(self, user_service: LDAPUserService): ...
```

### Integration with FLEXT Ecosystem

- **Extends flext-core**: Uses ServiceResult, DI container, and domain patterns
- **Integrates with flext-observability**: Structured logging and metrics
- **Supports flext-auth**: User management and authentication
- **Powers flext-meltano**: LDAP data extraction and loading

### ServiceResult Pattern

All operations return a `ServiceResult[T]` for type-safe error handling:

```python
result = await ldap_service.create_user(request)

if result.is_success:
    user = result.value  # Type: LDAPUser
    print(f"Success: {user.cn}")
else:
    error = result.error_message  # Type: str
    print(f"Error: {error}")
```

## Project Status

**Status**: 🟡 **FLEXT Integration Complete** - Development continues for 95%+ coverage

Built on solid FLEXT Framework foundation with real LDAP integration. Currently used in production for enterprise migration projects.

### ✅ **FLEXT Framework Integration Complete**

| Component | Status | FLEXT Integration |
|-----------|--------|-------------------|
| **Architecture** | ✅ Complete | Clean Architecture + FLEXT patterns |
| **ServiceResult** | ✅ Complete | Type-safe error handling throughout |
| **Type Safety** | ✅ Complete | 100% MyPy strict compliance |
| **Configuration** | ✅ Complete | FLEXT BaseSettings integration |
| **Linting** | ✅ Complete | 0 errors, full Ruff compliance |
| **Real LDAP** | ✅ Complete | ldap3 production implementation |
| **CLI Interface** | ✅ Complete | Click-based command tools |

### 🟡 **Current Development Focus**

| Area | Current | Target | Priority |
|------|---------|--------|----------|
| **Test Coverage** | 48% | 95%+ | High |
| **Integration Tests** | Basic | TestContainers | Medium |
| **Documentation** | Good | Comprehensive | Medium |
| **Performance Tests** | Manual | Automated | Low |

### 🚀 **Production Usage**

- **Enterprise Deployment**: Powers `client-a-oud-mig` Oracle migration project
- **FLEXT Ecosystem**: Used by multiple FLEXT tap/target components
- **Performance**: Handles production directory operations efficiently
- **Reliability**: ServiceResult pattern ensures type-safe operations

### 📋 **Next Development Phase**

- **Expand Test Suite**: Comprehensive unit and integration testing
- **Real LDAP Testing**: TestContainer integration for server testing
- **Performance Optimization**: Bulk operations and connection pooling
- **Advanced Features**: LDAP controls and extensions support

## Dependencies

### FLEXT Framework Dependencies
- **flext-core**: Foundation library (ServiceResult, DI, Configuration)
- **flext-observability**: Structured logging and monitoring integration
- **Python**: 3.13+ (FLEXT workspace standard)

### Core LDAP Dependencies  
- **ldap3**: Production LDAP client library
- **pydantic**: Data validation and settings management
- **click**: Command-line interface framework

## Examples

See the `examples/` directory for complete usage examples:
- `integrated_ldap_service.py`: Comprehensive service usage

## Contributing

### FLEXT Framework Development

This module is part of the **FLEXT Framework ecosystem**. Contributions must align with FLEXT standards.

#### Development Setup

```bash
# Setup FLEXT workspace (required)
source /home/marlonsc/flext/.venv/bin/activate
cd flext-ldap

# Install with development dependencies
poetry install

# Follow FLEXT quality standards
make check           # Linting, typing, security
make test           # Tests with coverage
```

#### FLEXT Standards Compliance

1. **ServiceResult Pattern**: All operations return `ServiceResult[T]`
2. **Clean Architecture**: Domain → Application → Infrastructure
3. **Type Safety**: 100% MyPy strict compliance required
4. **Configuration**: Use flext-core BaseSettings patterns
5. **Testing**: Minimum 95% coverage for production features

#### Quality Gates (FLEXT-Aligned)

```bash
# Required before any contribution
ruff check src/              # Zero linting errors
mypy src/ --strict          # Zero type errors  
pytest --cov=95            # Minimum coverage
bandit -r src/             # Security scan clean
```

#### FLEXT Integration Rules

- **Extend, don't replace**: Build on flext-core, don't duplicate
- **Follow workspace patterns**: See `CLAUDE.md` for standards
- **Test ecosystem impact**: Verify integration with dependent projects
- **Document FLEXT usage**: Show ServiceResult and DI patterns

#### Code Review Requirements

- [ ] **FLEXT compliance**: Uses flext-core patterns correctly
- [ ] **Type safety**: Passes `mypy --strict` completely
- [ ] **Test coverage**: New features have comprehensive tests
- [ ] **Documentation**: Changes documented with examples
- [ ] **Integration**: Works with client-a-oud-mig and other FLEXT projects

## License

MIT License - see [LICENSE](LICENSE) file.

---

*Part of the FLEXT framework ecosystem*