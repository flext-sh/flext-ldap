# FLEXT-LDAP Source Code

This directory contains the complete source code implementation for FLEXT-LDAP, an LDAP directory services library following Clean Architecture and Domain-Driven Design principles.

## Architecture Overview

FLEXT-LDAP implements a layered architecture that separates concerns and maintains clear boundaries between business logic, application services, and infrastructure components.

```
src/flext_ldap/
├── api.py                      # Unified API interface
├── domain/                     # Pure business logic
├── application/                # Use cases and orchestration
├── infrastructure/             # External system integrations
├── adapters/                   # Interface adapters
├── patterns/                   # Reusable patterns
└── configuration files         # Settings and constants
```

## Key Components

### Core API Layer

- **api.py**: Main FlextLdapClient interface providing unified LDAP operations
- **base.py**: Base functionality and shared patterns
- **config.py**: Configuration management with environment variable support

### Domain Layer

- **entities.py**: Rich domain entities (FlextLdapUser, FlextLdapGroup)
- **values.py**: Value objects and data transfer objects
- **domain/**: Pure business logic without external dependencies

### Application Layer

- **application/**: Use cases, command handlers, and application services
- **services.py**: Application service implementations

### Infrastructure Layer

- **infrastructure/**: Repository implementations and external integrations
- **ldap_infrastructure.py**: LDAP protocol client implementation
- **adapters/**: External system adapters

## Development Standards

All source code follows enterprise-grade standards:

- **Type Safety**: MyPy strict mode adoption; aiming for full coverage
- **Error Handling**: Railway-oriented programming with FlextResult pattern
- **Documentation**: Comprehensive docstrings with business context
- **Testing**: 95%+ test coverage requirement
- **Code Quality**: Ruff linting with comprehensive rule enforcement

## Integration Points

FLEXT-LDAP integrates seamlessly with the broader FLEXT ecosystem:

- **flext-core**: Foundation patterns (FlextResult, FlextContainer, FlextModels.Entity)
- **flext-auth**: Authentication and authorization services
- **flext-meltano**: Data pipeline orchestration
- **Singer ecosystem**: Extract-load-transform operations

## Getting Started

For development setup and usage examples, see:

- [Project README](../README.md) - Complete project overview
- [Documentation Hub](../docs/README.md) - Comprehensive documentation
- [Examples](../examples/) - Practical usage examples

## Module Documentation

Each module directory contains detailed README.md files with specific architectural guidance and implementation details.
