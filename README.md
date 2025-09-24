# flext-ldap

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)

**LDAP directory services integration library** for the FLEXT ecosystem, providing LDAP operations using **Clean Architecture patterns** with async/await support.

> **⚠️ STATUS**: Active development with 33% test coverage, targeting 90%+ compliance with FLEXT-Core patterns

---

## 🎯 Purpose and Role in FLEXT Ecosystem

### **For the FLEXT Ecosystem**

FLEXT-LDAP serves as the centralized LDAP operations library for all directory service needs across the FLEXT ecosystem. It provides a standardized interface for LDAP authentication, user management, and directory queries using Clean Architecture principles and domain-driven design patterns.

### **Universal Compatibility**

FLEXT-LDAP now provides **universal compatibility** with any LDAP server implementation through automatic schema discovery and server quirks handling:

- **OpenLDAP** - Full support with VLV and sync capabilities
- **Active Directory** - Case-insensitive operations and attribute mappings
- **Oracle Directory Server** - Complete feature support
- **Apache Directory Server** - Standard LDAP operations
- **389 Directory Server** - Enterprise features support
- **Novell eDirectory** - Legacy compatibility
- **Any LDAP3-compatible server** - Automatic adaptation

### **Key Responsibilities**

1. **Universal LDAP Operations** - Works with any LDAP server automatically
2. **Automatic Schema Discovery** - Detects server capabilities and quirks
3. **Server-Specific Adaptations** - Normalizes operations per server type
4. **Clean Architecture** - Domain-driven design with separated layers
5. **FLEXT Integration** - FlextResult error handling, dependency injection, logging

### **Integration Points**

- **flext-core** → FlextResult, FlextContainer, FlextLogger patterns
- **flext-auth** → LDAP authentication provider for SSO systems
- **Singer ecosystem** → flext-tap-ldap, flext-target-ldap for data extraction

---

## 🏗️ Architecture and Patterns

### **FLEXT-Core Integration Status**

| Pattern             | Status  | Description                           |
| ------------------- | ------- | ------------------------------------- |
| **FlextResult&lt;T&gt;**  | 🟢 100% | All operations return FlextResult     |
| **FlextService**    | 🟡 75%  | Domain services implemented           |
| **FlextContainer**  | 🟡 60%  | Dependency injection in progress      |
| **Domain Patterns** | 🟢 85%  | Entities, value objects, repositories |

> **Status**: 🔴 Critical · 1.0.0 Release Preparation | 🟡 Partial | 🟢 Complete

### **Architecture Diagram**

```mermaid
graph TB
    A[FlextLdapClient] --> B[FlextLdapServices]
    B --> C[FlextLdapDomain]
    B --> D[FlextLdapRepositories]
    D --> E[FlextLdapOperations]
    E --> F[FlextLdapClient]
    F --> G[ldap3 Library]

    subgraph "Clean Architecture Layers"
        C --> H[Entities]
        C --> I[Value Objects]
        H --> J[User, Group, Entry]
        I --> K[DN, Filter, Scope]
    end
```

---

## 🌐 Universal LDAP Compatibility

### **GenericLdapClient - Works with Any LDAP Server**

The `GenericLdapClient` automatically adapts to any LDAP server implementation:

```python
from flext_ldap import GenericLdapClient

# Works with ANY LDAP server automatically
client = GenericLdapClient()

# Connect with automatic schema discovery
await client.connect_with_discovery(
    server_uri="ldap://your-server:389",
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", 
    password="password"
)

# Server information is automatically discovered
server_type = client.get_server_type()  # "openldap", "active_directory", etc.
server_quirks = client.get_server_quirks()  # Server-specific behaviors

# Universal search - works on any server
results = await client.search_generic(
    base_dn="dc=example,dc=com",
    search_filter="(objectClass=person)",
    attributes=["cn", "sn", "mail"]
)

# Universal CRUD operations
await client.add_entry_generic("cn=user,dc=example,dc=com", {
    "cn": "user",
    "sn": "User", 
    "objectClass": ["person"]
})
```

### **Automatic Server Detection**

The client automatically detects and adapts to:

| Server Type | Detection | Adaptations |
|-------------|-----------|-------------|
| **OpenLDAP** | Vendor name patterns | Case-sensitive, VLV support |
| **Active Directory** | Microsoft patterns | Case-insensitive, attribute mappings |
| **Oracle Directory** | Oracle patterns | Full feature support |
| **Apache DS** | Apache patterns | Standard LDAP operations |
| **Generic** | Fallback | Conservative defaults |

### **Server Quirks Handling**

```python
# Automatic quirks detection
quirks = client.get_server_quirks()

if quirks.case_sensitive_dns:
    # Server requires exact case in DNs
    dn = "cn=TestUser,dc=Example,dc=Com"
else:
    # Server accepts any case
    dn = "cn=testuser,dc=example,dc=com"

if quirks.supports_paged_results:
    # Large result sets automatically paginated
    results = await client.search_generic(base_dn, filter, size_limit=10000)
else:
    # Limited to server's max page size
    results = await client.search_generic(base_dn, filter, size_limit=1000)
```

---

## 🚀 Quick Start

### **Installation**

**Production environment:**

```bash
poetry add flext-ldap
```

**Development environment:**

```bash
git clone <repository-url>
cd flext-ldap
make setup     # Install dependencies and pre-commit hooks
make validate  # Run quality checks
```

### **Basic Usage**

```python
import asyncio
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

async def basic_ldap_search():
    """Basic LDAP search using FlextResult patterns."""
    api = get_flext_ldap_api()

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=person)",
        scope="subtree",
        attributes=["uid", "cn", "mail"]
    )

    result = await api.search_entries(search_request)
    if result.is_success:
        entries = result.unwrap()
        print(f"Found {len(entries)} entries")
    else:
        print(f"Search failed: {result.error}")

asyncio.run(basic_ldap_search())
```

---

## 🔧 Development

### **Essential Commands**

```bash
make setup                    # Development environment setup
make validate                 # Complete quality pipeline (lint + type + security + test)
make test                     # Run test suite
make lint                     # Code linting with ruff
make type-check               # Type checking with mypy
make format                   # Code formatting
make clean                    # Clean build artifacts
```

### **Quality Gates**

- **Coverage**: 33% minimum (targeting 90%)
- **Type Checking**: mypy --strict compliance
- **Linting**: ruff with zero violations
- **Security**: bandit security analysis

---

## 🧪 Testing

### **Test Structure**

```
tests/
├── unit/              # Unit tests for individual components
├── integration/       # Integration tests with real LDAP server
├── e2e/              # End-to-end workflow tests
└── conftest.py       # Shared test fixtures
```

### **Testing Commands**

```bash
make test                     # Run all tests
pytest tests/unit/           # Unit tests only
pytest tests/integration/   # Integration tests (requires Docker)
pytest --cov=src            # Coverage report
```

**Docker Test Environment:**

```bash
make ldap-test-server        # Start OpenLDAP container for testing
make ldap-test-server-stop   # Stop test container
```

---

## 📊 Status and Metrics

### **Quality Standards**

- **Coverage**: 33% (target: 90%)
- **Type Safety**: mypy --strict enabled
- **Security**: bandit analysis passing
- **FLEXT-Core Compliance**: 80%

### **Ecosystem Integration**

- **Direct Dependencies**: flext-auth (authentication provider)
- **Service Dependencies**: flext-core (patterns), flext-observability (logging)
- **Integration Points**: 3 active integrations in ecosystem

---

## 🗺️ Roadmap

### **Current Version (0.9.9)**

- Clean Architecture foundation complete
- FlextResult pattern implementation
- Basic LDAP operations (authentication, search, CRUD)
- Domain entities and value objects

### **Next Version (1.0.0)**

- 90% test coverage achievement
- Complete FLEXT-Core pattern compliance
- Performance optimization for large directories
- Enhanced error handling and validation

---

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)** - Installation and setup
- **[Architecture](docs/architecture.md)** - Design patterns and structure
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Development](docs/development.md)** - Contributing and workflows
- **[Integration](docs/integration.md)** - Ecosystem integration patterns
- **[Examples](docs/examples/)** - Working code examples
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues
- **[TODO & Roadmap](docs/TODO.md)** - Development status and plans

---

## 🤝 Contributing

### **FLEXT-Core Compliance Checklist**

- [ ] Use FlextResult<T> for all operations
- [ ] Implement domain entities with business logic
- [ ] Follow Clean Architecture layer separation
- [ ] Use FlextContainer for dependency injection
- [ ] Implement proper error handling patterns

### **Quality Standards**

- All code must pass `make validate`
- Test coverage for new features required
- Type annotations required for all public APIs
- Security analysis must pass

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext/issues)
- **Security**: Report security issues privately to maintainers

---

**flext-ldap v0.9.9** - LDAP directory services enabling authentication and user management across the FLEXT ecosystem.

**Mission**: Provide reliable LDAP operations with Clean Architecture patterns for enterprise directory service integration.
