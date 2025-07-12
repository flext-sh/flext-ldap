# 📚 FLEXT-LDAP Documentation

**LDAP library for the FLEXT framework with enterprise-grade functionality**

## Overview

This documentation covers the FLEXT-LDAP library, which provides:

- **Real LDAP Integration**: Using ldap3 library for production LDAP operations
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **ServiceResult Pattern**: Type-safe error handling throughout
- **FLEXT Standards**: Integration with flext-core and flext-observability

## 🚀 Quick Start

### Basic Usage

```python
from flext_ldap import LDAPService
from flext_ldap.domain.value_objects import CreateUserRequest

async def main():
    ldap_service = LDAPService()
    
    # Create a user
    request = CreateUserRequest(
        dn="cn=john.doe,ou=people,dc=example,dc=com",
        uid="john.doe",
        cn="John Doe",
        sn="Doe",
        mail="john.doe@example.com"
    )
    
    result = await ldap_service.create_user(request)
    if result.is_success:
        user = result.value
        print(f"Created user: {user.cn}")
    else:
        print(f"Error: {result.error_message}")
```

### Connection Management

```python
# Connect to LDAP server
connection_result = await ldap_service.connect_to_server(
    "ldap://your-ldap-server.com:389",
    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    "your_password"
)

if connection_result.is_success:
    # Perform LDAP operations
    # Operations will use real LDAP server
    pass
else:
    # Operations will use memory mode
    print(f"Connection failed: {connection_result.error_message}")
```

## 🏗️ Architecture

### Project Structure

```
src/flext_ldap/
├── application/        # Application services
│   ├── ldap_service.py # Main LDAP service
│   └── services.py     # Supporting services
├── domain/             # Domain layer
│   ├── entities.py     # Domain entities
│   ├── ports.py        # Repository interfaces
│   └── value_objects.py # Value objects
├── infrastructure/     # Infrastructure layer
│   ├── ldap_client.py  # LDAP client implementation
│   └── repositories.py # Repository implementations
├── config.py           # Configuration management
└── utils.py           # LDAP utilities
```

### Key Components

#### LDAPService
Main application service providing high-level LDAP operations:
- User management (create, update, delete, search)
- Group management 
- Connection management
- Memory mode fallback when disconnected

#### Domain Entities
- **LDAPUser**: Represents LDAP user entries
- **LDAPGroup**: Represents LDAP group entries
- **LDAPConnection**: Represents LDAP server connections

#### Repository Pattern
- **LDAPUserRepository**: User data access
- **LDAPGroupRepository**: Group data access  
- **LDAPConnectionRepository**: Connection management

## 🔧 Configuration

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

config = LDAPConfig()
print(f"Server: {config.server}")
print(f"Port: {config.port}")
print(f"Use TLS: {config.use_tls}")
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/flext_ldap --cov-report=term-missing

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
```

### Test Coverage

Current test coverage: **37.97%**

Areas with good coverage:
- `utils.py`: 94.52% (42 tests)
- `simple_api.py`: 93.10% (17 tests) 
- `config.py`: 87.78%
- `repositories.py`: 72.50% (18 tests)

Areas needing more tests:
- `services.py`: 15.24%
- `ldap_client.py`: 11.81%
- CLI modules: 0%

## 📚 Examples

See the `examples/` directory for complete usage examples:
- `integrated_ldap_service.py`: Comprehensive service usage example

## 🔗 Dependencies

- **Python**: 3.13+
- **flext-core**: FLEXT framework core functionality
- **flext-observability**: Logging and monitoring
- **ldap3**: Python LDAP client library
- **pydantic**: Data validation and settings

## 📋 Status

**Current Status**: ✅ Functional with areas for improvement

- ✅ Real LDAP integration with ldap3
- ✅ ServiceResult pattern implementation
- ✅ Basic domain-driven design
- ✅ Memory mode fallback
- 🟡 Test coverage needs improvement (target: 95%+)
- 🟡 FLEXT integration can be enhanced
- 🟡 Legacy modules need refactoring

## 🚀 Development

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

### Standards

- **Linting**: 0 errors (Ruff)
- **Type Safety**: Strict MyPy compliance
- **Security**: No critical vulnerabilities
- **Code Style**: Ruff formatted

---

*This documentation reflects the actual current state of the flext-ldap library.*  
*Last updated: 2025-01-12*