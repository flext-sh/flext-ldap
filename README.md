# FLEXT-LDAP

**Enterprise LDAP Directory Services Integration for FLEXT Data Platform**

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![FLEXT Framework](https://img.shields.io/badge/FLEXT-Core%20Integration-blue.svg)]()
[![Clean Architecture](https://img.shields.io/badge/architecture-Clean%20%2B%20DDD-green.svg)]()
[![Type Safety](https://img.shields.io/badge/mypy-strict-green.svg)]()
[![Test Coverage](https://img.shields.io/badge/coverage-90%25+-brightgreen.svg)]()

Modern LDAP operations library built on **FLEXT-Core** foundation implementing Clean Architecture and Domain-Driven Design patterns. Provides comprehensive directory services integration for the FLEXT data integration ecosystem with Singer/Meltano pipeline support.

---

## 🏗️ FLEXT Ecosystem Integration

FLEXT-LDAP is a core infrastructure component of the **FLEXT Data Platform**, providing enterprise-grade LDAP directory services with full integration across the ecosystem:

### Core Dependencies

- **[flext-core](../flext-core)**: Foundation patterns (FlextResult, FlextContainer, FlextLDAPConfig)
- **[flext-observability](../flext-observability)**: Structured logging, metrics, and health monitoring

### Data Pipeline Integration

- **[flext-tap-ldap](../flext-tap-ldap)**: Singer tap for LDAP data extraction
- **[flext-target-ldap](../flext-target-ldap)**: Singer target for LDAP data loading
- **[flext-dbt-ldap](../flext-dbt-ldap)**: DBT transformations for LDAP directory data
- **[flext-meltano](../flext-meltano)**: Orchestration of LDAP data pipelines

### Authentication & Security

- **[flext-auth](../flext-auth)**: Enterprise authentication with LDAP directory integration
- **[flext-ldif](../flext-ldif)**: LDIF data format support for backup/restore operations

---

## 🎯 Project Objectives

### Primary Mission

Provide enterprise-grade LDAP directory services integration for the FLEXT data platform, enabling:

1. **Data Pipeline Integration**: Extract, transform, and load directory data using Singer/Meltano patterns
2. **Authentication Services**: Power enterprise authentication through flext-auth integration
3. **Directory Management**: Comprehensive LDAP operations with Clean Architecture patterns
4. **Production Reliability**: Type-safe operations with comprehensive error handling

### Business Value

- **Enterprise Migrations**: Powers large-scale directory migrations (e.g., Oracle Unified Directory)
- **Data Integration**: Enables LDAP data in analytical pipelines and data warehouses
- **Identity Management**: Provides foundation for enterprise identity and access management
- **Operational Excellence**: Production-ready LDAP operations with monitoring and observability

---

## 🚀 Quick Start

### Prerequisites

- Python 3.13+
- FLEXT workspace environment
- LDAP server access (or Docker for testing)

### Installation

```bash
# Clone FLEXT ecosystem
git clone https://github.com/flext-sh/flext.git
cd flext/flext-ldap

# Install with FLEXT workspace
make setup
```

### Basic Usage

```python
from flext_ldap import get_ldap_api, FlextLdapCreateUserRequest

async def example_ldap_operations():
    # Initialize FLEXT-LDAP API with dependency injection
    api = get_ldap_api()

    # Establish secure connection with FlextResult pattern
    async with api.connection(
        "ldap://directory.company.com",
        "cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        "secure_password"
    ) as session:

        # Search directory entries
        users = await api.search(
            session,
            "ou=users,dc=company,dc=com",
            "(objectClass=person)"
        )

        if users.is_success:
            print(f"Found {len(users.data)} users")

        # Create new user with domain validation
        user_request = FlextLdapCreateUserRequest(
            dn="cn=jane.doe,ou=users,dc=company,dc=com",
            uid="jane.doe",
            cn="Jane Doe",
            sn="Doe",
            mail="jane.doe@company.com"
        )

        result = await api.create_user(session, user_request)
        if result.is_success:
            print(f"Created user: {result.data.dn}")
        else:
            print(f"Error: {result.error}")
```

---

## 🏛️ Architecture

### Clean Architecture + DDD Implementation

```
src/flext_ldap/
├── domain/              # Business Logic Layer
│   ├── entities.py      # Domain entities (FlextLdapUser, FlextLdapGroup)
│   ├── value_objects.py # Value objects (DN, Filter, Scope)
│   ├── repositories.py  # Repository interfaces
│   ├── services.py      # Domain services
│   └── events.py        # Domain events
├── application/         # Application Layer
│   ├── ldap_service.py  # Application services
│   └── handlers/        # Command/Query handlers
├── infrastructure/     # Infrastructure Layer
│   ├── repositories.py  # Repository implementations
│   ├── ldap_client.py   # LDAP protocol client
│   └── adapters/        # External system adapters
├── adapters/           # Interface Adapters
│   └── directory_adapter.py # Directory service adapter
└── api.py              # Unified API entry point
```

### FLEXT-Core Integration

- **FlextResult Pattern**: Type-safe error handling throughout all operations
- **FlextContainer**: Dependency injection for service orchestration
- **FlextLDAPConfig**: Centralized configuration management
- **FlextLogger**: Structured logging with correlation IDs

---

## 🔌 Ecosystem Integration

### Singer Data Pipeline Integration

```python
# Extract LDAP data for analytics
from flext_tap_ldap import FlextLdapTap

tap = FlextLdapTap(config={
    "server_url": "ldap://directory.company.com",
    "base_dn": "dc=company,dc=com"
})

# Stream directory data to data warehouse
catalog = tap.discover_catalog()
tap.sync(catalog)
```

### Authentication Integration

```python
# Integrate with flext-auth for SSO
from flext_auth import FlextAuthService
from flext_ldap import get_ldap_api

auth_service = FlextAuthService()
ldap_api = get_ldap_api()

# Authenticate users against LDAP directory
user_result = await auth_service.authenticate_ldap(
    username="jane.doe",
    password="user_password",
    ldap_provider=ldap_api
)
```

### Data Format Integration

```python
# Export/Import with LDIF format
from flext_ldif import FlextLdifProcessor
from flext_ldap import get_ldap_api

ldap_api = get_ldap_api()
ldif_processor = FlextLdifProcessor()

# Export directory to LDIF
async with ldap_api.connection(...) as session:
    users = await ldap_api.search(session, "ou=users,dc=company,dc=com", "(objectClass=person)")
    ldif_data = ldif_processor.export_entries(users.data)

    # Backup directory data
    with open("directory_backup.ldif", "w") as f:
        f.write(ldif_data)
```

---

## 🛠️ Development

### Setup Development Environment

```bash
# Install development dependencies
make install-dev

# Setup pre-commit hooks
make setup

# Run development server with hot reload
make dev
```

### Quality Gates

```bash
# Complete validation pipeline
make validate         # lint + type + security + test

# Individual checks
make lint            # Ruff linting with FLEXT rules
make type-check      # MyPy strict type checking
make security        # Bandit + pip-audit security scans
make test            # Pytest with 90%+ coverage requirement
```

### Testing Strategy

```bash
# Run test suites
make test-unit           # Fast unit tests
make test-integration    # Integration tests with Docker LDAP
make test-e2e           # End-to-end workflow tests

# Performance testing
make test-performance    # Load testing and benchmarks

# Test with real LDAP server
make test-ldap          # Live LDAP server integration tests
```

---

## 📊 Production Usage

### Enterprise Deployments

**Currently Powers**:

- **client-a Oracle Unified Directory Migration**: Large-scale enterprise directory migration
- **client-b Identity Management**: Multi-domain LDAP authentication
- **Corporate Data Pipelines**: Directory data analytics and reporting

### Performance Characteristics

- **Connection Pooling**: Efficient LDAP connection management
- **Async Operations**: Non-blocking I/O for high-throughput scenarios
- **Type Safety**: Zero runtime type errors with strict MyPy validation
- **Error Handling**: Comprehensive error recovery and retry mechanisms

### Monitoring & Observability

```python
# Built-in monitoring integration
from flext_observability import get_metrics_client

metrics = get_metrics_client()

# LDAP operation metrics automatically collected
async with api.connection(...) as session:
    result = await api.search(session, ...)
    # Metrics: ldap_operations_total, ldap_response_time, ldap_errors_total
```

---

## 🔧 Configuration

### Environment Variables

```bash
# LDAP Server Configuration
FLEXT_LDAP_HOST=ldap.company.com
FLEXT_LDAP_PORT=636
FLEXT_LDAP_USE_SSL=true
FLEXT_LDAP_BASE_DN=dc=company,dc=com
FLEXT_LDAP_BIND_DN=cn=service,ou=accounts,dc=company,dc=com
FLEXT_LDAP_BIND_PASSWORD=secure_service_password

# Connection Management
FLEXT_LDAP_TIMEOUT=30
FLEXT_LDAP_POOL_SIZE=10
FLEXT_LDAP_RETRY_ATTEMPTS=3

# Integration Settings
FLEXT_LDAP_ENABLE_METRICS=true
FLEXT_LDAP_ENABLE_TRACING=true
FLEXT_LDAP_LOG_LEVEL=INFO
```

### Configuration Classes

```python
from flext_ldap import FlextLdapSettings

# Load configuration with validation
settings = FlextLdapSettings()

# Override for specific environments
settings.server_url = "ldaps://prod-ldap.company.com:636"
settings.enable_connection_pooling = True
```

---

## 📈 Roadmap

### Current Version: 0.9.0

- ✅ Clean Architecture implementation
- ✅ FLEXT-Core integration
- ✅ Production LDAP operations
- ✅ Type-safe error handling
- ✅ Comprehensive testing

### Upcoming: 1.0.0 (Target: Q1 2025)

- 🔄 Singer ecosystem integration (flext-tap-ldap, flext-target-ldap)
- 🔄 flext-auth authentication integration
- 🔄 flext-ldif data format support
- 🔄 Performance optimizations and caching
- 🔄 Production monitoring dashboards

### Future: 1.1.0+

- 📋 Advanced LDAP controls and extensions
- 📋 Schema validation and migration tools
- 📋 Multi-server replication support
- 📋 GraphQL API layer
- 📋 Real-time change notifications

---

## 🤝 Contributing

### FLEXT Framework Standards

This project follows **FLEXT Framework** development standards:

1. **Clean Architecture**: Domain-driven design with clear layer separation
2. **Type Safety**: 100% MyPy strict compliance required
3. **Test Coverage**: Minimum 90% coverage with comprehensive test suites
4. **Code Quality**: Zero linting errors with Ruff + security scanning
5. **Documentation**: Comprehensive API documentation and examples

### Development Workflow

```bash
# 1. Setup development environment
make setup

# 2. Implement changes following Clean Architecture
# - Domain layer: Business logic and entities
# - Application layer: Use cases and workflows
# - Infrastructure layer: External integrations
# - API layer: Interface adapters

# 3. Ensure quality gates pass
make validate

# 4. Submit pull request with:
# - Clear description of changes
# - Test coverage for new functionality
# - Documentation updates
# - Architecture Decision Records (ADR) for significant changes
```

### Code Review Process

All contributions require:

- ✅ Architecture review for Clean Architecture compliance
- ✅ Security review for LDAP operations
- ✅ Performance impact assessment
- ✅ Integration testing with FLEXT ecosystem components
- ✅ Documentation and example updates

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🔗 Related Projects

### FLEXT Ecosystem

- **[FLEXT Platform](https://github.com/flext-sh/flext)**: Complete data integration platform
- **[flext-core](../flext-core)**: Foundation library with core patterns
- **[flext-observability](../flext-observability)**: Monitoring and observability
- **[flext-meltano](../flext-meltano)**: Singer/Meltano orchestration platform

### Enterprise Deployments

- **[client-a-oud-mig](../client-a-oud-mig)**: Oracle Unified Directory migration project
- **[client-b-meltano-native](../client-b-meltano-native)**: client-b identity management

---

## 📞 Support

- **Documentation**: [FLEXT Documentation Hub](../docs/)
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext/issues)
- **Discussions**: [GitHub Discussions](https://github.com/flext-sh/flext/discussions)
- **Enterprise Support**: Contact FLEXT Team at <team@flext.sh>

---

_Part of the **FLEXT Framework** ecosystem - Enterprise-grade data integration platform_
