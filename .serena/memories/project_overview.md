# FLEXT-LDAP Project Overview

## Purpose
Enterprise LDAP Operations Library for FLEXT Framework - a production-ready LDAP client library with Clean Architecture, Domain-Driven Design (DDD), and type-safe error handling via FlextResult patterns.

## Tech Stack
- **Python**: 3.13+ (strict typing)
- **Core Dependencies**: 
  - `flext-core` (foundation library)
  - `ldap3` (LDAP protocol implementation)
  - `pydantic` (data validation and models)
  - `pydantic-settings` (configuration management)
  - `structlog` (structured logging)
- **Development Tools**: Poetry, Ruff, MyPy, PyRight, Pytest
- **Architecture**: Clean Architecture + DDD + Railway-oriented programming

## Key Features
- **Async/Await**: All LDAP operations are asynchronous
- **Type Safety**: Strict MyPy configuration with zero tolerance for type errors
- **Clean Architecture**: Domain, Application, Infrastructure layers properly separated
- **FlextResult Pattern**: Railway-oriented error handling throughout
- **Singleton Configuration**: FlextLDAPConfig as single source of truth
- **Docker Integration**: Real LDAP server testing with osixia/openldap

## Project Structure
```
src/flext_ldap/
├── api.py                  # High-level API facade
├── services.py             # Application services (async)
├── adapters.py             # Infrastructure adapters
├── operations.py           # Low-level LDAP operations
├── entities.py             # Domain entities (Pydantic models)
├── value_objects.py        # Domain value objects
├── domain.py               # Domain logic and specifications
├── config.py               # Configuration management
├── clients.py              # LDAP client abstraction
├── repositories.py         # Data access patterns
├── container.py            # Dependency injection
├── exceptions.py           # Domain exceptions
├── constants.py            # Domain constants
├── settings.py             # Infrastructure configuration
├── cli.py                  # CLI interface
└── __init__.py             # Public API exports
```

## Current Status
- **Version**: 0.9.0
- **Test Coverage**: 33% (targeting 90%+)
- **Quality**: MyPy strict mode enabled, Ruff linting
- **Architecture**: Clean Architecture foundation established
- **Integration**: Docker-based LDAP testing environment