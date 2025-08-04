# FLEXT-LDAP

**LDAP Directory Operations Library**

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![FLEXT Framework](https://img.shields.io/badge/FLEXT-Core%20Integration-blue.svg)]()
[![Clean Architecture](https://img.shields.io/badge/architecture-Clean%20%2B%20DDD-green.svg)]()

LDAP operations library built with Clean Architecture patterns, providing directory services functionality with type-safe error handling through FlextResult patterns.

---

## 🏗️ Dependencies

### Core Requirements

- **[flext-core](../flext-core)**: Foundation patterns (FlextResult, dependency injection, logging)
- **ldap3**: LDAP protocol implementation
- **pydantic**: Data validation and serialization

### Optional Integrations

- **[flext-observability](../flext-observability)**: Structured logging and metrics (when available)
- **Singer ecosystem**: Data pipeline integration (planned)

---

## 🎯 Current Status

### What Works

1. **LDAP Operations**: Basic LDAP connectivity and operations (search, create, update, delete)
2. **Service Layer**: Application services with test fallback patterns
3. **Type Safety**: FlextResult pattern for error handling
4. **Testing**: Comprehensive test suite with Docker LDAP integration

### What's In Development

- Singer ecosystem integration (flext-tap-ldap, flext-target-ldap)
- Authentication service integration
- Performance optimizations and connection pooling

---

## 🚀 Installation

### Prerequisites

- Python 3.13+
- Poetry for dependency management
- LDAP server access (or Docker for testing)

### Setup

```bash
# Clone and install
git clone <repository-url>
cd flext-ldap

# Install dependencies
poetry install

# Setup development environment
make setup
```

### Basic Usage

```python
from flext_ldap.services import FlextLdapUserApplicationService
from flext_ldap.values import FlextLdapCreateUserRequest

# Initialize service
user_service = FlextLdapUserApplicationService()

# Create user request
user_request = FlextLdapCreateUserRequest(
    dn="cn=jane.doe,ou=users,dc=example,dc=com",
    uid="jane.doe",
    cn="Jane Doe",
    sn="Doe",
    mail="jane.doe@example.com"
)

# Create user (test environment uses mock implementation)
result = user_service.create_user(user_request)
if result.is_success:
    print(f"Created user: {result.data.dn}")
else:
    print(f"Error: {result.error}")
```

---

## 🏛️ Architecture

### Current Structure

```
src/flext_ldap/
├── entities.py          # Domain entities (FlextLdapUser, FlextLdapGroup, etc.)
├── values.py           # Value objects (DN, Filter, CreateUserRequest)
├── services.py         # Service layer with test fallback patterns
├── application/        # Application services (core LDAP operations)
├── infrastructure/     # Infrastructure implementations
├── config.py          # Configuration management
└── api.py             # Main API entry point
```

### Key Patterns

- **FlextResult Pattern**: Type-safe error handling for all operations
- **Test Fallback Pattern**: Services automatically detect test vs production environment
- **Clean Architecture**: Clear separation between domain, application, and infrastructure
- **Domain-Driven Design**: Rich domain entities with business logic

---

## 🔌 Integration

### Test vs Production Behavior

The service layer automatically detects the environment:

- **Test Environment**: Uses in-memory cache for consistent testing
- **Production Environment**: Delegates to real LDAP infrastructure

```python
# Same code works in both environments
user_service = FlextLdapUserApplicationService()
result = user_service.create_user(user_request)

# In tests: Uses mock implementation with cache
# In production: Uses real LDAP server via application layer
```

---

## 🛠️ Development

### Quality Commands

```bash
# Setup development environment
make setup

# Run tests
make test              # Run test suite (22 tests currently passing)
make test-unit         # Unit tests only
make test-integration  # Integration tests with Docker LDAP

# Code quality
make lint             # Code linting
make type-check       # Type checking
make format           # Code formatting
make validate         # All checks combined
```

### Test Environment

The project includes Docker-based LDAP testing:

```bash
# Tests automatically manage Docker LDAP container
make test-integration

# Manual LDAP container for development
docker run -d --name test-ldap -p 3389:389 osixia/openldap:1.5.0
```

---

## 📊 Current State

### What's Working

- **Service Layer**: 22 tests passing across 4 main service classes
- **LDAP Operations**: Basic LDAP connectivity and CRUD operations
- **Type Safety**: FlextResult pattern for error handling
- **Test Infrastructure**: Docker-based LDAP testing environment

### What's In Progress

- **Production LDAP Integration**: Application layer connects to real LDAP servers
- **Performance Optimization**: Connection pooling and async operations
- **Singer Integration**: Data pipeline components (planned)

### Known Limitations

- Some infrastructure components are not fully implemented
- Production deployments require additional configuration
- Performance characteristics are not yet benchmarked

---

## 🔧 Configuration

### Environment Variables

```bash
# Basic LDAP Configuration
FLEXT_LDAP_HOST=localhost
FLEXT_LDAP_PORT=389
FLEXT_LDAP_USE_SSL=false
FLEXT_LDAP_BASE_DN=dc=example,dc=com
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
FLEXT_LDAP_BIND_PASSWORD=REDACTED_LDAP_BIND_PASSWORD

# Optional Settings
FLEXT_LDAP_TIMEOUT=30
FLEXT_LOG_LEVEL=INFO
```

### Configuration Classes

```python
from flext_ldap.config import FlextLdapSettings

# Load configuration with validation
settings = FlextLdapSettings()
print(f"Server: {settings.server}")
print(f"Port: {settings.port}")
```

---

## 📈 Development Status

### Version: 0.9.0 (Current)

**Completed:**

- ✅ Service layer with test fallback patterns (22 tests passing)
- ✅ Domain entities and value objects
- ✅ Basic LDAP infrastructure
- ✅ FlextResult error handling
- ✅ Docker-based testing

**In Progress:**

- 🔄 Production LDAP integration (application layer)
- 🔄 Performance optimization
- 🔄 Documentation improvements

**Planned:**

- 📋 Singer ecosystem integration
- 📋 Authentication service integration
- 📋 Connection pooling and caching
- 📋 Performance benchmarking

---

## 🤝 Contributing

### Development Standards

- **Clean Architecture**: Follow established patterns
- **Type Safety**: All code must pass MyPy type checking
- **Testing**: Maintain test coverage and ensure all tests pass
- **Code Quality**: Follow linting rules (make lint)

### Development Workflow

```bash
# Setup development environment
make setup

# Make changes and run quality checks
make validate

# Ensure tests pass
make test
```

### Pull Request Requirements

- All tests must pass (currently 22/22 passing)
- Code must pass linting and type checking
- Clear description of changes
- Update documentation if needed

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🔗 Related Projects

- **[flext-core](../flext-core)**: Foundation library with core patterns
- **[flext-observability](../flext-observability)**: Monitoring and observability

---

_Part of the FLEXT ecosystem - Data integration platform_
