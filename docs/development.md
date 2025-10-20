# Development Guide

## Table of Contents

- [Development Guide](#development-guide)
  - [Development Environment Setup](#development-environment-setup)
    - [Prerequisites](#prerequisites)
- [Required system dependencies](#required-system-dependencies)
  - [Initial Setup](#initial-setup)
- [Clone and setup development environment](#clone-and-setup-development-environment)
- [Install dependencies and development tools](#install-dependencies-and-development-tools)
- [Verify installation](#verify-installation)
  - [Development Tools Installation](#development-tools-installation)
- [Install pre-commit hooks](#install-pre-commit-hooks)
- [Install development dependencies](#install-development-dependencies)
- [Verify development setup](#verify-development-setup)
  - [Development Workflow](#development-workflow)
    - [Daily Development Commands](#daily-development-commands)
- [Start development session](#start-development-session)
- [Complete validation](#complete-validation)
  - [Code Formatting](#code-formatting)
- [Automatic formatting](#automatic-formatting)
- [Manual formatting](#manual-formatting)
- [Import sorting](#import-sorting)
  - [Type Checking](#type-checking)
- [MyPy validation](#mypy-validation)
- [Manual type checking](#manual-type-checking)
  - [Testing Strategy](#testing-strategy)
    - [Test Categories](#test-categories)
- [Requires Docker LDAP server](#requires-docker-ldap-server)
  - [Docker LDAP Test Server](#docker-ldap-test-server)
- [Start test LDAP server](#start-test-ldap-server)
- [Verify server connectivity](#verify-server-connectivity)
- [Stop test server](#stop-test-server)
  - [Coverage Analysis](#coverage-analysis)
- [Generate coverage report](#generate-coverage-report)
- [Target high-impact modules first](#target-high-impact-modules-first)
  - [Architecture Guidelines](#architecture-guidelines)
    - [Clean Architecture Layers](#clean-architecture-layers)
- [src/flext_ldap/domain.py](#srcflext_ldapdomainpy)
- [src/flext_ldap/entities.py](#srcflext_ldapentitiespy)
- [src/flext_ldap/value_objects.py](#srcflext_ldapvalue_objectspy)
- [src/flext_core.py](#srcflext_corepy)
- [src/flext_ldap/api.py](#srcflext_ldapapipy)
- [src/flext_ldap/services.py](#srcflext_ldapservicespy)
- [src/flext_ldap/clients.py](#srcflext_ldapclientspy)
- [src/flext_ldap/adapters.py](#srcflext_ldapadapterspy)
- [src/flext_ldap/operations.py](#srcflext_ldapoperationspy)
- [src/flext_ldap/repositories.py](#srcflext_ldaprepositoriespy)
  - [Coding Standards](#coding-standards)
- [✅ CORRECT - Explicit error handling](#-correct---explicit-error-handling)
- [❌ WRONG - Try/catch fallbacks](#-wrong---trycatch-fallbacks)
- [✅ CORRECT - Parameter objects for complex operations](#-correct---parameter-objects-for-complex-operations)
- [❌ WRONG - Multiple parameters](#-wrong---multiple-parameters)
  - [Code Quality Standards](#code-quality-standards)
    - [Type Safety Requirements](#type-safety-requirements)
- [All public APIs must have complete type annotations](#all-public-apis-must-have-complete-type-annotations)
- [Generic types for FlextResult patterns](#generic-types-for-flextresult-patterns)
  - [Import Organization](#import-organization)
- [Standard library imports](#standard-library-imports)
- [Third-party imports](#third-party-imports)
- [FLEXT imports](#flext-imports)
- [Local imports](#local-imports)
  - [Testing Guidelines](#testing-guidelines)
    - [Unit Test Structure](#unit-test-structure)
    - [Integration Test Structure](#integration-test-structure)
    - [Test Fixtures](#test-fixtures)
- [tests/conftest.py](#testsconftestpy)
  - [Documentation Standards](#documentation-standards)
    - [Code Documentation](#code-documentation)
    - [API Documentation](#api-documentation)
  - [Performance Guidelines](#performance-guidelines)
    - [Connection Management](#connection-management)
- [Use connection pooling for high-traffic scenarios](#use-connection-pooling-for-high-traffic-scenarios)
  - [Search Optimization](#search-optimization)
- [Optimize LDAP searches](#optimize-ldap-searches)
  - [Best Practices](#best-practices)
- [Use context managers for resource management](#use-context-managers-for-resource-management)
- [Batch operations for efficiency](#batch-operations-for-efficiency)
  - [Contribution Guidelines](#contribution-guidelines)
    - [Pull Request Process](#pull-request-process)
    - [Code Review Checklist](#code-review-checklist)

**Contributing to flext-ldap - Clean Architecture and FLEXT standards**

This guide covers development setup, coding standards, and contribution guidelines for flext-ldap.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

---

## Development Environment Setup

### Prerequisites

```bash
# Required system dependencies
Python 3.13+
Poetry 1.8+
Git 2.40+
Docker 24.0+ (for LDAP testing)
Make 4.0+
```

### Initial Setup

```bash
# Clone and setup development environment
git clone <repository-url>
cd flext-ldap

# Install dependencies and development tools
make setup

# Verify installation
make validate
```

### Development Tools Installation

```bash
# Install pre-commit hooks
pre-commit install

# Install development dependencies
poetry install --with dev,test,docs

# Verify development setup
python -c "from flext_ldap import get_flext_ldap_api; print('✅ Development setup complete')"
```

---

## Development Workflow

### Daily Development Commands

```bash
# Start development session
make setup              # Ensure environment is ready
make format             # Auto-format code (ruff + black)
make lint               # Check code style and issues
make type-check         # Validate type annotations
make test               # Run test suite

# Complete validation
make validate           # Run all quality gates
```

### Code Formatting

```bash
# Automatic formatting
make format

# Manual formatting
ruff format src/ tests/
ruff check src/ tests/ --fix

# Import sorting
ruff check src/ tests/ --select I --fix
```

### Type Checking

```bash
# MyPy validation
make type-check

# Manual type checking
PYTHONPATH=src mypy src/flext_ldap --strict
PYTHONPATH=src pyright src/flext_ldap --level error
```

---

## Testing Strategy

### Test Categories

**Unit Tests** - Domain logic and value objects:

```bash
pytest tests/unit/ -v
pytest tests/unit/test_entities.py::TestFlextLdapUser -v
```

**Integration Tests** - Real LDAP operations:

```bash
# Requires Docker LDAP server
pytest tests/integration/ -v
pytest tests/integration/test_ldap_operations.py -v
```

**End-to-End Tests** - Complete workflows:

```bash
pytest tests/e2e/ -v
pytest tests/e2e/test_enterprise_workflows.py -v
```

### Docker LDAP Test Server

```bash
# Start test LDAP server
make ldap-test-server

# Verify server connectivity
docker exec -it flext-ldap-test-server ldapsearch \
  -x -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -b "dc=flext,dc=local"

# Stop test server
make ldap-test-server-stop
```

### Coverage Analysis

```bash
# Generate coverage report
pytest --cov=src/flext_ldap --cov-report=html
open htmlcov/index.html

# Target high-impact modules first
pytest --cov=src/flext_ldap --cov-report=term-missing | grep -E "operations\.py|services\.py|adapters\.py"
```

---

## Architecture Guidelines

### Clean Architecture Layers

**Domain Layer** (Business logic):

```python
# src/flext_ldap/domain.py
# src/flext_ldap/entities.py
# src/flext_ldap/value_objects.py
# src/flext_core.py
```

**Application Layer** (Use cases):

```python
# src/flext_ldap/api.py
# src/flext_ldap/services.py
```

**Infrastructure Layer** (External concerns):

```python
# src/flext_ldap/clients.py
# src/flext_ldap/adapters.py
# src/flext_ldap/operations.py
# src/flext_ldap/repositories.py
```

### Coding Standards

**1. Single Responsibility Classes**

```python
class FlextLdapUserService:
    """Single responsibility - user operations only."""

    def __init__(self) -> None:
        self._client = get_ldap_client()
        self.logger = FlextLogger(__name__)

    def authenticate_user(self, username: str, password: str) -> FlextResult[FlextLdapUser]:
        """Authenticate user with proper error handling."""
        # Implementation...
```

**2. FlextResult Pattern**

```python
# ✅ CORRECT - Explicit error handling
def create_user(self, request: CreateUserRequest) -> FlextResult[FlextLdapUser]:
    if not request.is_valid():
        return FlextResult[FlextLdapUser].fail("Invalid user data")

    result = self._client.create_entry(request.to_ldap_entry())
    if result.is_failure:
        return FlextResult[FlextLdapUser].fail(f"User creation failed: {result.error}")

    return FlextResult[FlextLdapUser].ok(FlextLdapUser.from_ldap_entry(result.unwrap()))

# ❌ WRONG - Try/catch fallbacks
def create_user(self, request: CreateUserRequest) -> FlextLdapUser | None:
    try:
        # Implementation...
        return user
    except Exception:
        return None  # FORBIDDEN
```

**3. Parameter Object Pattern**

```python
# ✅ CORRECT - Parameter objects for complex operations
@dataclass
class SearchRequest:
    base_dn: str
    filter_str: str
    scope: str
    attributes: FlextTypes.StringList
    size_limit: int = 100
    time_limit: int = 30

def search_entries(self, request: SearchRequest) -> FlextResult[List[LdapEntry]]:
    # Implementation using parameter object

# ❌ WRONG - Multiple parameters
def search_entries(self, base_dn: str, filter_str: str, scope: str,
                        attributes: FlextTypes.StringList, size_limit: int, time_limit: int):
    # FORBIDDEN - use parameter objects
```

**4. Value Object Validation**

```python
@dataclass(frozen=True)
class DistinguishedName:
    """RFC 4514 compliant Distinguished Name."""
    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn():
            raise ValueError(f"Invalid DN: {self.value}")

    def _is_valid_dn(self) -> bool:
        # DN validation logic
        return bool(self.value and "=" in self.value and "," in self.value)
```

---

## Code Quality Standards

### Type Safety Requirements

```python
# All public APIs must have complete type annotations
def authenticate_user(
    self,
    username: str,
    password: str
) -> FlextResult[FlextLdapUser]:
    """Complete type signature required."""

# Generic types for FlextResult patterns
T = TypeVar('T')

class FlextLdapService(Generic[T]):
    """Generic service with type constraints."""
```

### Import Organization

```python
# Standard library imports
from dataclasses import dataclass
from typing import List, Optional

# Third-party imports
import pydantic
from ldap3 import Connection, Server

# FLEXT imports
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities

# Local imports
from flext_ldap.entities import FlextLdapUser
from flext_ldap.value_objects import DistinguishedName
```

---

## Testing Guidelines

### Unit Test Structure

```python
import pytest
from flext_ldap.entities import FlextLdapUser, CreateUserRequest

class TestFlextLdapUser:
    """Test domain entity behavior."""

    def test_user_validation_success(self):
        """Test valid user data passes validation."""
        user = FlextLdapUser(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe"
        )

        assert user.is_valid()
        assert user.get_display_name() == "John Doe"

    def test_user_validation_failure(self):
        """Test invalid user data fails validation."""
        user = FlextLdapUser(
            dn="",  # Invalid empty DN
            uid="john.doe",
            cn="John Doe",
            sn="Doe"
        )

        assert not user.is_valid()

    @pytest.mark.parametrize("uid,expected", [
        ("john.doe", True),
        ("", False),
        ("a", False),  # Too short
    ])
    def test_uid_validation(self, uid: str, expected: bool):
        """Test UID validation with parameters."""
        user = FlextLdapUser(
            dn="cn=test,dc=example,dc=com",
            uid=uid,
            cn="Test User",
            sn="User"
        )

        assert user.is_valid() == expected
```

### Integration Test Structure

```python
import pytest
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

@pytest.mark.integration
@pytest.mark.io
class TestLdapOperations:
    """Integration tests with real LDAP server."""

    def test_user_authentication_success(self, ldap_server):
        """Test successful user authentication."""
        api = get_flext_ldap_api()

        # Create test user first
        create_request = FlextLdapEntities.CreateUserRequest(
            dn="cn=test.user,ou=users,dc=flext,dc=local",
            uid="test.user",
            cn="Test User",
            sn="User",
            password="test123"
        )

        create_result = api.create_user(create_request)
        assert create_result.is_success

        # Test authentication
        auth_result = api.authenticate_user("test.user", "test123")
        assert auth_result.is_success

        user = auth_result.unwrap()
        assert user.uid == "test.user"
        assert user.cn == "Test User"

    def test_user_search(self, ldap_server):
        """Test user search functionality."""
        api = get_flext_ldap_api()

        search_request = FlextLdapEntities.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["uid", "cn", "mail"]
        )

        result = api.search_entries(search_request)
        assert result.is_success

        entries = result.unwrap()
        assert isinstance(entries, list)
```

### Test Fixtures

```python
# tests/conftest.py
import pytest
from flext_tests import FlextTestDocker
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities
from Flext_ldap import FlextLdapConfig, set_flext_ldap_config

@pytest.fixture(scope="session")
def ldap_server():
    """Docker LDAP server for integration tests using FlextTestDocker."""
    docker_manager = FlextTestDocker()

    # Start LDAP container using FlextTestDocker
    container_result = docker_manager.run_container(
        image="osixia/openldap:1.5.0",
        name="flext-ldap-test-server",
        ports={"389/tcp": 3390},
        environment={
            "LDAP_ORGANISATION": "FLEXT Test",
            "LDAP_DOMAIN": "internal.invalid",
            "LDAP_ADMIN_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD123",
        },
        detach=True,
        remove=True,
    )

    if container_result.is_failure:
        pytest.skip(f"Failed to start LDAP container: {container_result.error}")

    container_id = container_result.unwrap()

    # Wait for server to be ready using FlextTestDocker health check
    health_result = docker_manager.wait_for_container_health(
        container_name="flext-ldap-test-server",
        health_command="ldapsearch -x -H ldap://localhost:389 -b '' -s base",
        timeout=30
    )

    if health_result.is_failure:
        pytest.skip(f"LDAP server not ready: {health_result.error}")

    # Configure flext-ldap for testing
    test_config = FlextLdapConfig(
        host="localhost",
        port=3390,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        base_dn="dc=flext,dc=local"
    )
    set_flext_ldap_config(test_config)

    yield container_id

    # Cleanup using FlextTestDocker
    docker_manager.stop_container("flext-ldap-test-server", remove=True)

@pytest.fixture
def authenticated_user():
    """Fixture for authenticated user tests."""
    api = get_flext_ldap_api()

    # Create test user
    create_request = FlextLdapEntities.CreateUserRequest(
        dn="cn=auth.test,ou=users,dc=flext,dc=local",
        uid="auth.test",
        cn="Auth Test",
        sn="Test",
        password="auth123"
    )

    create_result = api.create_user(create_request)
    assert create_result.is_success

    yield create_result.unwrap()

    # Cleanup user
    api.delete_user("cn=auth.test,ou=users,dc=flext,dc=local")
```

---

## Documentation Standards

### Code Documentation

```python
class FlextLdapClients:
    """High-level LDAP API following Clean Architecture patterns.

    This class serves as the main entry point for LDAP operations,
    providing a unified interface that abstracts infrastructure concerns.

    Examples:
        Basic usage:
        >>> api = get_flext_ldap_api()
        >>> result = api.test_connection()
        >>> if result.is_success:
        ...     print("Connected to LDAP server")

        User authentication:
        >>> auth_result = api.authenticate_user("john.doe", "password")
        >>> if auth_result.is_success:
        ...     user = auth_result.unwrap()
        ...     print(f"Welcome, {user.cn}")
    """

    def authenticate_user(
        self,
        username: str,
        password: str
    ) -> FlextResult[FlextLdapUser]:
        """Authenticate user credentials against LDAP directory.

        Args:
            username: User identifier (uid attribute)
            password: User password for authentication

        Returns:
            FlextResult containing authenticated user object on success,
            or error message on failure.

        Raises:
            No exceptions raised - all errors returned via FlextResult.

        Examples:
            >>> result = api.authenticate_user("john.doe", "secret123")
            >>> if result.is_success:
            ...     user = result.unwrap()
            ...     print(f"Authenticated: {user.cn}")
            >>> else:
            ...     print(f"Authentication failed: {result.error}")
        """
```

### API Documentation

All public APIs require comprehensive documentation including:

- Purpose and responsibility
- Parameter descriptions with types
- Return value descriptions
- FlextResult usage patterns
- Complete working examples
- Integration with Clean Architecture layers

---

## Performance Guidelines

### Connection Management

```python
# Use connection pooling for high-traffic scenarios
from Flext_ldap import FlextLdapConfig

config = FlextLdapConfig(
    host="ldap.example.com",
    pool_size=10,  # Adjust based on load
    connection_timeout=5,
    receive_timeout=15
)
```

### Search Optimization

```python
# Optimize LDAP searches
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",  # Use specific base DN
    filter_str="(&(objectClass=person)(uid=j*))",  # Indexed attributes
    scope="onelevel",  # Minimal scope needed
    attributes=["uid", "cn"],  # Only required attributes
    size_limit=50,  # Reasonable page size
    time_limit=10   # Prevent long-running searches
)
```

### Best Practices

```python
# Use context managers for resource management
with get_ldap_client() as client:
    result = client.search(search_request)
    # Client automatically closed

# Batch operations for efficiency
users_to_create = [user1, user2, user3]
results = gather(*[
    api.create_user(user) for user in users_to_create
])
```

---

## Contribution Guidelines

### Pull Request Process

1. **Create Feature Branch**

   ```bash
   git checkout -b feature/ldap-group-management
   ```

2. **Implement Changes**

   ```bash
   # Follow development workflow
   make format
   make lint
   make type-check
   make test
   ```

3. **Validate Quality**

   ```bash
   make validate  # Must pass all gates
   ```

4. **Submit Pull Request**
   - Clear description of changes
   - Reference related issues
   - Include test coverage
   - Update documentation if needed

### Code Review Checklist

- [ ] Follows Clean Architecture patterns
- [ ] Uses FlextResult for error handling
- [ ] Includes comprehensive tests
- [ ] Type annotations complete
- [ ] Documentation updated
- [ ] No infrastructure leakage into domain
- [ ] Parameter objects used for complex operations
- [ ] Integration tests pass with Docker LDAP server

---

For more development resources:

- [Architecture Guide](architecture.md) - Understanding Clean Architecture
- [API Reference](api-reference.md) - Complete API documentation
- [Examples](examples/) - Working code examples

---

**Next:** [Integration Guide](integration.md) →
