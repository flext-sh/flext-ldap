# Python Module Organization & Semantic Patterns

**FLEXT-LDAP Module Architecture & Best Practices Following FLEXT-Core Standards**

---

## 🏗️ **Module Architecture Overview**

FLEXT-LDAP implements Clean Architecture with Domain-Driven Design patterns, following the **FLEXT-Core module architecture** as the foundation template. This document defines the specific organization patterns for LDAP directory services within the FLEXT ecosystem.

### **Core Design Principles**

1. **Clean Architecture Foundation**: Domain-driven design with clear layer separation
2. **FLEXT Pattern Compliance**: Consistent with flext-core patterns across ecosystem
3. **Type-Safe LDAP Operations**: Comprehensive type hints with strict MyPy compliance
4. **Railway-Oriented Programming**: FlextResult[T] threading through all LDAP operations
5. **Domain-Rich Entities**: Business logic embedded in LDAP domain entities

---

## 📁 **FLEXT-LDAP Module Structure**

### **Foundation Layer**

```python
# FLEXT-LDAP Foundation - Built on flext-core
src/flext_ldap/
├── __init__.py              # 🎯 Public API gateway (LDAP-specific exports)
├── py.typed                 # 🎯 Type annotations marker
├── _deprecated.py           # 🎯 Legacy compatibility layer
└── constants.py             # 🎯 LDAP-specific constants
```

**Responsibility**: Establish LDAP-specific contracts extending flext-core foundation.

**Import Pattern**:

```python
# Primary FLEXT-LDAP imports
from flext_ldap import get_ldap_api, FlextLdapUser, FlextLdapCreateUserRequest

# With flext-core integration
from flext_core import FlextResult, FlextContainer
from flext_ldap import FlextLdapApi
```

### **Core API Layer**

```python
# Main API entry point
├── api.py                   # 🚀 FlextLdapApi - Unified LDAP operations
├── base.py                  # 🚀 Base LDAP functionality and mixins
└── client.py                # 🚀 LDAP client abstraction (deprecated)
```

**Responsibility**: Provide unified, type-safe LDAP operations with session management.

**Usage Pattern**:

```python
from flext_ldap.api import FlextLdapApi, get_ldap_api

# Unified API with session management
api = get_ldap_api()
async with api.connection(server_url, bind_dn, password) as session:
    result = await api.search(session, base_dn, ldap_filter)
```

### **Domain Layer (Clean Architecture)**

```python
# Domain-Driven Design implementation
├── domain/
│   ├── __init__.py          # 🏛️ Domain exports
│   ├── entities.py          # 🏛️ Domain entities (not implemented yet)
│   ├── value_objects.py     # 🏛️ Value objects (not implemented yet)
│   ├── aggregates.py        # 🏛️ Aggregate roots for LDAP operations
│   ├── repositories.py      # 🏛️ Repository interfaces (abstract)
│   ├── specifications.py    # 🏛️ Domain specifications and business rules
│   ├── events.py           # 🏛️ Domain events for LDAP operations
│   ├── exceptions.py       # 🏛️ Domain-specific exceptions
│   ├── interfaces.py       # 🏛️ Abstract interfaces and protocols
│   ├── ports.py            # 🏛️ Port definitions for Clean Architecture
│   └── security.py         # 🏛️ Domain security rules and validations
```

**Responsibility**: Pure business logic for LDAP directory operations without external dependencies.

**Domain Modeling Pattern**:

```python
from flext_ldap.domain.entities import FlextLdapUser, FlextLdapGroup
from flext_ldap.domain.value_objects import FlextLdapDistinguishedName
from flext_ldap.domain.specifications import FlextLdapUserValidator

class FlextLdapUser(FlextEntity):
    """Rich LDAP user entity with business logic."""
    dn: FlextLdapDistinguishedName
    uid: str
    cn: str
    sn: str

    def activate(self) -> FlextResult[None]:
        """Business logic for user activation."""
        if self.is_active:
            return FlextResult[None].fail("User already active")

        self.is_active = True
        self.add_domain_event(UserActivatedEvent(user_id=self.id))
        return FlextResult[None].ok(None)

class FlextLdapDistinguishedName(FlextValue):
    """Distinguished Name value object with RFC 4514 validation."""
    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn(self.value):
            raise ValueError(f"Invalid DN format: {self.value}")
```

### **Application Layer (Use Cases)**

```python
# Application services and use cases
├── application/
│   ├── __init__.py          # 📤 Application layer exports
│   ├── ldap_service.py      # 📤 Main LDAP application service
│   ├── services.py          # 📤 Additional application services (legacy)
│   ├── handlers/            # 📤 Command/Query handlers (CQRS)
│   │   ├── __init__.py
│   │   ├── user_handlers.py # 📤 User-specific command handlers
│   │   └── group_handlers.py# 📤 Group-specific command handlers
│   └── commands/            # 📤 Application commands
│       ├── __init__.py
│       ├── user_commands.py # 📤 User management commands
│       └── group_commands.py# 📤 Group management commands
```

**Responsibility**: Orchestrate domain objects and coordinate with infrastructure.

**Application Service Pattern**:

```python
from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.application.commands.user_commands import CreateUserCommand

class FlextLdapService:
    """Application service orchestrating LDAP operations."""

    def __init__(
        self,
        user_repository: FlextLdapUserRepository,
        validator: FlextLdapUserValidator
    ):
        self._user_repository = user_repository
        self._validator = validator

    async def create_user(
        self,
        command: CreateUserCommand
    ) -> FlextResult[FlextLdapUser]:
        """Create user with complete business logic."""
        return (
            self._validator.validate_user_creation(command.data)
            .flat_map(lambda data: FlextLdapUser.create(data))
            .flat_map(lambda user: self._user_repository.save(user))
        )
```

### **Infrastructure Layer (External Integrations)**

```python
# Infrastructure implementations
├── infrastructure/
│   ├── __init__.py              # ⚙️ Infrastructure exports
│   ├── repositories.py          # ⚙️ Repository implementations (concrete)
│   ├── ldap_client.py           # ⚙️ LDAP protocol client (deprecated)
│   ├── connection_manager.py    # ⚙️ Connection pool management
│   ├── certificate_validator.py # ⚙️ SSL/TLS certificate validation
│   ├── schema_discovery.py      # ⚙️ LDAP schema introspection
│   ├── security_event_logger.py # ⚙️ Security audit logging
│   ├── error_correlation.py     # ⚙️ Error tracking and correlation
│   └── adapters/                # ⚙️ External system adapters
│       ├── __init__.py
│       └── singer_adapter.py    # ⚙️ Singer/Meltano integration
```

**Responsibility**: Handle external LDAP servers, persistence, and third-party integrations.

**Infrastructure Pattern**:

```python
from flext_ldap.infrastructure.repositories import FlextLdapUserRepositoryImpl
from flext_ldap.ldap_infrastructure import FlextLdapClient

class FlextLdapUserRepositoryImpl(FlextLdapUserRepository):
    """Concrete LDAP user repository implementation."""

    def __init__(self, ldap_client: FlextLdapClient):
        self._ldap_client = ldap_client

    async def save(self, user: FlextLdapUser) -> FlextResult[FlextLdapUser]:
        """Save user to LDAP directory."""
        try:
            # Convert domain entity to LDAP entry
            entry_data = self._to_ldap_entry(user)

            # Use infrastructure client
            result = await self._ldap_client.add_entry(
                dn=user.dn.value,
                attributes=entry_data
            )

            return FlextResult[None].ok(user) if result.success else FlextResult[None].fail(result.error)
        except Exception as e:
            return FlextResult[None].fail(f"Infrastructure error: {str(e)}")
```

### **Interface Adapters Layer**

```python
# Interface adapters for external systems
├── adapters/
│   ├── __init__.py              # 🔧 Adapter exports
│   ├── directory_adapter.py     # 🔧 Directory service adapter
│   └── rest_adapter.py          # 🔧 REST API adapter (future)
```

**Responsibility**: Adapt external interfaces to domain contracts.

**Adapter Pattern**:

```python
from flext_ldap.adapters.directory_adapter import FlextLdapDirectoryAdapter

class FlextLdapDirectoryAdapter:
    """Adapter for directory service integration."""

    async def search(
        self,
        base_dn: FlextLdapDistinguishedName,
        filter_spec: FlextLdapFilter,
        scope: FlextLdapScope
    ) -> FlextResult[List[FlextLdapEntry]]:
        """Search directory with domain objects."""
        return await self._execute_search_pipeline(base_dn, filter_spec, scope)
```

### **Configuration & Settings Layer**

```python
# Configuration management
├── config.py                   # ⚙️ FlextLdapSettings - LDAP configuration
├── settings.py                 # ⚙️ Application settings (deprecated)
└── constants.py                # ⚙️ LDAP protocol constants
```

**Responsibility**: Handle LDAP-specific configuration extending flext-core patterns.

**Configuration Pattern**:

```python
from flext_core.config import FlextConfig
from flext_ldap.config import FlextLdapSettings

class FlextLdapSettings(FlextConfig):
    """LDAP configuration with environment variable support."""

    # LDAP Connection settings
    server_url: str = "ldap://localhost"
    port: int = 389
    use_ssl: bool = False
    bind_dn: str = ""
    bind_password: SecretStr = SecretStr("")

    # Search settings
    base_dn: str = "dc=example,dc=com"
    timeout: int = 30
    page_size: int = 1000

    class Config:
        env_prefix = "FLEXT_LDAP_"
        env_file = ".env"
```

### **Entity & Value Object Layer**

```python
# Domain entities and value objects (current implementation)
├── entities.py              # 🏛️ FlextLdapUser, FlextLdapGroup, FlextLdapEntry
├── values.py               # 🏛️ Value objects and DTOs
└── models.py               # 🏛️ Data models (deprecated)
```

**Responsibility**: Rich domain entities with business logic and immutable value objects.

**Entity Pattern**:

```python
from flext_ldap.entities import FlextLdapUser, FlextLdapGroup

@dataclass
class FlextLdapUser(FlextEntity):
    """LDAP user entity with business logic."""
    dn: str
    uid: str
    cn: str
    sn: str
    mail: Optional[str] = None

    def is_valid(self) -> bool:
        """Domain validation logic."""
        return bool(self.dn and self.uid and self.cn and self.sn)

    def get_display_name(self) -> str:
        """Business logic for display name."""
        return self.cn or f"{self.uid}"

    def change_email(self, new_email: str) -> FlextResult[None]:
        """Email change with validation."""
        if not "@" in new_email:
            return FlextResult[None].fail("Invalid email format")

        old_email = self.mail
        self.mail = new_email
        self.add_domain_event(EmailChangedEvent(
            user_id=self.id,
            old_email=old_email,
            new_email=new_email
        ))
        return FlextResult[None].ok(None)
```

### **Infrastructure Integration Layer**

```python
# Consolidated infrastructure (main LDAP client)
├── ldap_infrastructure.py      # 🚀 FlextLdapClient + Converters
├── services.py                 # 🚀 Service layer (legacy compatibility)
└── utils.py                    # 🚀 LDAP utility functions
```

**Responsibility**: Consolidated LDAP infrastructure with type conversion and connection management.

**Infrastructure Pattern**:

```python
from flext_ldap.ldap_infrastructure import FlextLdapClient, FlextLdapConverter

class FlextLdapClient:
    """Consolidated LDAP client with flext-core integration."""

    def __init__(self, config: FlextLdapConnectionConfig):
        self._config = config
        self._converter = FlextLdapConverter()
        self._connection: Optional[Connection] = None

    async def search(
        self,
        base_dn: str,
        filter_expr: str,
        attributes: List[str],
        scope: str = "subtree"
    ) -> FlextResult[List[Dict[str, Any]]]:
        """Search LDAP directory with type conversion."""
        try:
            # LDAP search implementation
            raw_results = self._execute_ldap_search(base_dn, filter_expr, attributes, scope)

            # Convert to typed results
            converted_results = [
                self._converter.convert_ldap_entry(entry)
                for entry in raw_results
            ]

            return FlextResult[None].ok(converted_results)
        except Exception as e:
            return FlextResult[None].fail(f"Search error: {str(e)}")
```

### **Patterns & Utilities Layer**

```python
# Reusable patterns and cross-cutting concerns
├── patterns/
│   ├── __init__.py         # 🔧 Pattern exports
│   └── auth_patterns.py    # 🔧 Authentication patterns
├── utils.py                # 🔧 LDAP utility functions
├── converters.py           # 🔧 Data type converters (deprecated)
└── mixins.py               # 🔧 Reusable behavior mixins (future)
```

**Responsibility**: Cross-cutting concerns and reusable LDAP patterns.

**Pattern Usage**:

```python
from flext_ldap.patterns.auth_patterns import FlextLdapAuthMixin
from flext_ldap.utils import parse_ldap_dn, validate_ldap_filter

class AuthenticatedLdapService(FlextLdapService, FlextLdapAuthMixin):
    """LDAP service with authentication patterns."""

    async def secure_search(
        self,
        session_id: str,
        base_dn: str,
        filter_expr: str
    ) -> FlextResult[List[FlextLdapEntry]]:
        """Search with authentication validation."""
        auth_result = await self.validate_session(session_id)
        if auth_result.is_failure:
            return FlextResult[None].fail("Authentication required")

        return await self.search(session_id, base_dn, filter_expr)
```

### **CLI Interface Layer**

```python
# Command-line interface
├── cli.py                  # 🖥️ Click-based CLI interface
└── cli/                    # 🖥️ CLI command modules (future)
    ├── __init__.py
    ├── user_commands.py    # 🖥️ User management CLI
    └── group_commands.py   # 🖥️ Group management CLI
```

**Responsibility**: Command-line interface for LDAP operations.

**CLI Pattern**:

```python
import click
from flext_ldap import get_ldap_api

@click.group()
def cli():
    """FLEXT-LDAP command-line interface."""
    pass

@cli.command()
@click.option('--server', required=True, help='LDAP server URL')
@click.option('--bind-dn', required=True, help='Bind DN')
@click.option('--password', required=True, help='Password')
@click.option('--base-dn', required=True, help='Search base DN')
@click.option('--filter', default='(objectClass=person)', help='LDAP filter')
def search(server, bind_dn, password, base_dn, filter):
    """Search LDAP directory."""
    api = get_ldap_api()

    async def run_search():
        async with api.connection(server, bind_dn, password) as session:
            result = await api.search(session, base_dn, filter)

            if result.success:
                for entry in result.data:
                    click.echo(f"DN: {entry.dn}")
            else:
                click.echo(f"Error: {result.error}")

    import asyncio
    asyncio.run(run_search())
```

---

## 🎯 **Semantic Naming Conventions**

### **FLEXT-LDAP Specific Naming**

All LDAP-specific exports use the `FlextLdap` prefix for clear namespace separation:

```python
# Core API classes
FlextLdapApi                # Main API entry point
FlextLdapClient       # Infrastructure LDAP client
FlextLdapSettings          # Configuration class
FlextLdapConnectionConfig  # Connection configuration

# Domain entities
FlextLdapUser              # LDAP user entity
FlextLdapGroup             # LDAP group entity
FlextLdapEntry             # Generic LDAP entry entity

# Value objects
FlextLdapDistinguishedName # DN value object
FlextLdapFilterValue       # LDAP filter value object
FlextLdapScopeEnum         # Search scope enumeration
FlextLdapCreateUserRequest # User creation request DTO

# Domain services
FlextLdapUserValidator     # User validation service
FlextLdapAuthenticator     # Authentication service
FlextLdapSchemaValidator   # Schema validation service

# Repository interfaces
FlextLdapUserRepository    # User repository interface
FlextLdapGroupRepository   # Group repository interface
FlextLdapConnectionRepository # Connection repository interface
```

### **Module-Level Naming Patterns**

```python
# Primary modules follow descriptive naming
api.py                     # Contains FlextLdapApi and factory functions
entities.py               # Contains domain entities
values.py                 # Contains value objects and DTOs
config.py                 # Contains configuration classes
ldap_infrastructure.py    # Contains infrastructure client and utilities

# Application layer modules
application/
├── ldap_service.py       # FlextLdapService - main application service
├── handlers/             # Command/query handlers
└── commands/             # Application commands

# Domain layer modules
domain/
├── entities.py           # Domain entities (future)
├── value_objects.py      # Value objects (future)
├── repositories.py       # Repository interfaces
├── specifications.py     # Domain specifications
└── events.py            # Domain events
```

### **Import Alias Standards**

```python
# Standard import patterns for FLEXT-LDAP
from flext_ldap import (
    FlextLdapApi,              # Never alias - ecosystem standard
    FlextLdapUser,             # Never alias - ecosystem standard
    FlextLdapCreateUserRequest,# Never alias - clear intent
    get_ldap_api               # Factory function - never alias
)

# With flext-core integration
from flext_core import FlextResult, FlextContainer  # Never alias core types
from flext_ldap import FlextLdapApi

# ❌ Forbidden aliases that break ecosystem consistency
from flext_ldap import FlextLdapApi as LdapApi      # Breaks ecosystem naming
from flext_core import FlextResult as Result       # Confusing across projects
```

---

## 📦 **Import Patterns & Dependencies**

### **Layer Dependency Rules**

```python
# ✅ Allowed dependencies (inward flow)
# API Layer → Application Layer → Domain Layer → flext-core
from flext_core import FlextResult, FlextContainer, FlextEntity
from flext_ldap.domain.entities import FlextLdapUser
from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.api import FlextLdapApi

# ✅ Infrastructure can depend on domain and flext-core
from flext_core import FlextResult
from flext_ldap.domain.repositories import FlextLdapUserRepository
from flext_ldap.infrastructure.repositories import FlextLdapUserRepositoryImpl

# ❌ Forbidden reverse dependencies
# Domain layer must NOT import from infrastructure or application
from flext_ldap.infrastructure.ldap_client import FlextLdapClient  # ❌ In domain layer
from flext_ldap.application.ldap_service import FlextLdapService   # ❌ In domain layer
```

### **Recommended Import Styles**

#### **1. Primary Pattern (Ecosystem Standard)**

```python
# Import from main package for common operations
from flext_ldap import get_ldap_api, FlextLdapUser, FlextLdapCreateUserRequest
from flext_core import FlextResult

async def create_ldap_user(user_data: dict) -> FlextResult[FlextLdapUser]:
    api = get_ldap_api()

    request = FlextLdapCreateUserRequest(
        dn=f"uid={user_data['uid']},ou=users,dc=example,dc=com",
        uid=user_data['uid'],
        cn=user_data['name'],
        sn=user_data['surname'],
        mail=user_data.get('email')
    )

    async with api.connection(server_url, bind_dn, password) as session:
        return await api.create_user(session, request)
```

#### **2. Specific Module Pattern (Advanced Usage)**

```python
# Import from specific modules for clarity in complex implementations
from flext_core.result import FlextResult
from flext_core.container import FlextContainer
from flext_ldap.api import FlextLdapApi
from flext_ldap.entities import FlextLdapUser
from flext_ldap.application.ldap_service import FlextLdapService

class CustomLdapIntegration:
    def __init__(self, container: FlextContainer):
        self._api = container.resolve(FlextLdapApi)
        self._service = container.resolve(FlextLdapService)
```

#### **3. Type Annotation Pattern**

```python
# Import types for annotations without runtime overhead
from typing import TYPE_CHECKING

from flext_ldap import FlextLdapApi, FlextLdapUser
from flext_core import FlextResult

def process_users(api: 'FlextLdapApi') -> 'FlextResult[List[FlextLdapUser]]':
    """Process users with type safety."""
    pass
```

---

## 🏛️ **Clean Architecture Implementation**

### **Layer Responsibilities & Boundaries**

```python
# Clean Architecture layers with LDAP-specific responsibilities
┌─────────────────────────────────────────────────────────────────┐
│                     API/Interface Layer                        │
│  api.py - FlextLdapApi (Unified interface)                    │
│  cli.py - Command-line interface                              │
├─────────────────────────────────────────────────────────────────┤
│                     Application Layer                          │
│  application/ldap_service.py - Use case orchestration         │
│  application/handlers/ - CQRS command/query handlers          │
├─────────────────────────────────────────────────────────────────┤
│                       Domain Layer                             │
│  domain/entities.py - Business entities (FlextLdapUser)       │
│  domain/value_objects.py - Immutable values (DN, Filter)      │
│  domain/repositories.py - Repository interfaces               │
│  domain/specifications.py - Business rules                    │
├─────────────────────────────────────────────────────────────────┤
│                   Infrastructure Layer                         │
│  infrastructure/repositories.py - Repository implementations  │
│  ldap_infrastructure.py - LDAP protocol client                │
│  infrastructure/adapters/ - External system adapters          │
├─────────────────────────────────────────────────────────────────┤
│                      FLEXT-Core Foundation                     │
│  FlextResult, FlextContainer, FlextEntity, FlextConfig   │
└─────────────────────────────────────────────────────────────────┘
```

### **Domain-Driven Design Patterns**

#### **Rich Domain Entities**

```python
from flext_core import FlextEntity, FlextResult
from flext_ldap.domain.value_objects import FlextLdapDistinguishedName
from flext_ldap.domain.events import UserActivatedEvent

class FlextLdapUser(FlextEntity):
    """Rich LDAP user entity with business logic."""
    dn: FlextLdapDistinguishedName
    uid: str
    cn: str
    sn: str
    mail: Optional[str] = None
    is_active: bool = False
    _domain_events: List[Dict[str, Any]] = field(default_factory=list, init=False)

    def activate(self) -> FlextResult[None]:
        """Business operation with domain rules."""
        if self.is_active:
            return FlextResult[None].fail("User already active")

        # Apply business rule
        if not self.mail:
            return FlextResult[None].fail("Email required for activation")

        self.is_active = True
        self.add_domain_event(UserActivatedEvent(
            user_id=self.id,
            user_dn=self.dn.value,
            timestamp=datetime.utcnow()
        ))

        return FlextResult[None].ok(None)

    def change_password(self, old_password: str, new_password: str) -> FlextResult[None]:
        """Password change with domain validation."""
        # Domain validation logic
        if len(new_password) < 8:
            return FlextResult[None].fail("Password must be at least 8 characters")

        if new_password == old_password:
            return FlextResult[None].fail("New password must be different")

        # Business logic for password change
        self.add_domain_event(PasswordChangedEvent(
            user_id=self.id,
            user_dn=self.dn.value
        ))

        return FlextResult[None].ok(None)
```

#### **Value Objects with Validation**

```python
from flext_core import FlextValue

@dataclass(frozen=True)
class FlextLdapDistinguishedName(FlextValue):
    """Distinguished Name value object with RFC 4514 validation."""
    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn(self.value):
            raise ValueError(f"Invalid DN format: {self.value}")

    def _is_valid_dn(self, dn: str) -> bool:
        """Validate DN format according to RFC 4514."""
        return bool(
            dn and
            '=' in dn and
            len(dn.strip()) > 0 and
            not dn.startswith('=') and
            not dn.endswith('=')
        )

    @property
    def rdn(self) -> str:
        """Get Relative Distinguished Name (first component)."""
        return self.value.split(',')[0].strip()

    @property
    def parent_dn(self) -> Optional[str]:
        """Get parent DN (all components except first)."""
        components = self.value.split(',')
        return ','.join(components[1:]).strip() if len(components) > 1 else None

    def is_child_of(self, parent_dn: str) -> bool:
        """Check if this DN is a child of parent DN."""
        return self.value.lower().endswith(parent_dn.lower())

@dataclass(frozen=True)
class FlextLdapFilter(FlextValue):
    """LDAP filter value object with RFC 4515 validation."""
    expression: str

    def __post_init__(self) -> None:
        if not self._is_valid_filter(self.expression):
            raise ValueError(f"Invalid LDAP filter: {self.expression}")

    def _is_valid_filter(self, filter_str: str) -> bool:
        """Basic LDAP filter validation."""
        return bool(
            filter_str and
            filter_str.startswith('(') and
            filter_str.endswith(')')
        )

    @classmethod
    def equals(cls, attribute: str, value: str) -> 'FlextLdapFilter':
        """Create equality filter."""
        return cls(f"({attribute}={value})")

    @classmethod
    def present(cls, attribute: str) -> 'FlextLdapFilter':
        """Create presence filter."""
        return cls(f"({attribute}=*)")

    @classmethod
    def and_filters(cls, *filters: 'FlextLdapFilter') -> 'FlextLdapFilter':
        """Combine filters with AND logic."""
        expressions = [f.expression for f in filters]
        return cls(f"(&{''.join(expressions)})")
```

#### **Aggregate Root Pattern**

```python
from flext_core import FlextAggregateRoot
from flext_ldap.domain.entities import FlextLdapUser

class FlextLdapUserAggregate(FlextAggregateRoot):
    """User aggregate managing user lifecycle and group membership."""
    user: FlextLdapUser
    group_memberships: List[str] = field(default_factory=list)

    def add_to_group(self, group_dn: str) -> FlextResult[None]:
        """Add user to group with business rules."""
        if not self.user.is_active:
            return FlextResult[None].fail("Cannot add inactive user to group")

        if group_dn in self.group_memberships:
            return FlextResult[None].fail("User already member of group")

        self.group_memberships.append(group_dn)
        self.add_domain_event(UserAddedToGroupEvent(
            user_id=self.user.id,
            user_dn=self.user.dn.value,
            group_dn=group_dn
        ))

        return FlextResult[None].ok(None)

    def remove_from_group(self, group_dn: str) -> FlextResult[None]:
        """Remove user from group with business rules."""
        if group_dn not in self.group_memberships:
            return FlextResult[None].fail("User not member of group")

        self.group_memberships.remove(group_dn)
        self.add_domain_event(UserRemovedFromGroupEvent(
            user_id=self.user.id,
            user_dn=self.user.dn.value,
            group_dn=group_dn
        ))

        return FlextResult[None].ok(None)
```

---

## 🔄 **Railway-Oriented Programming with LDAP**

### **FlextResult Chains for LDAP Operations**

```python
from flext_core import FlextResult
from flext_ldap import get_ldap_api, FlextLdapCreateUserRequest

async def create_user_pipeline(user_data: dict) -> FlextResult[FlextLdapUser]:
    """Complete user creation pipeline with error handling."""
    api = get_ldap_api()

    return (
        validate_user_data(user_data)
        .map(create_user_request)
        .flat_map_async(lambda request: create_ldap_connection(api)
            .flat_map_async(lambda session: create_user_in_ldap(api, session, request))
        )
        .flat_map_async(send_welcome_email)
        .map(log_user_creation)
    )

def validate_user_data(data: dict) -> FlextResult[dict]:
    """Validate user data with business rules."""
    errors = []

    if not data.get('uid'):
        errors.append("UID is required")
    if not data.get('cn'):
        errors.append("Common name is required")
    if not data.get('sn'):
        errors.append("Surname is required")
    if data.get('mail') and '@' not in data['mail']:
        errors.append("Invalid email format")

    return FlextResult[None].fail(errors) if errors else FlextResult[None].ok(data)

def create_user_request(data: dict) -> FlextLdapCreateUserRequest:
    """Create user request from validated data."""
    return FlextLdapCreateUserRequest(
        dn=f"uid={data['uid']},ou=users,dc=example,dc=com",
        uid=data['uid'],
        cn=data['cn'],
        sn=data['sn'],
        mail=data.get('mail')
    )

async def create_ldap_connection(api: FlextLdapApi) -> FlextResult[str]:
    """Create LDAP connection with error handling."""
    return await api.connect(
        "ldap://directory.company.com",
        "cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        "REDACTED_LDAP_BIND_PASSWORD_password"
    )

async def create_user_in_ldap(
    api: FlextLdapApi,
    session: str,
    request: FlextLdapCreateUserRequest
) -> FlextResult[FlextLdapUser]:
    """Create user in LDAP directory."""
    return await api.create_user(session, request)
```

### **Error Aggregation Patterns**

```python
async def bulk_user_creation(user_data_list: List[dict]) -> FlextResult[List[FlextLdapUser]]:
    """Create multiple users with error aggregation."""
    api = get_ldap_api()
    results = []
    errors = []

    async with api.connection(server_url, bind_dn, password) as session:
        for user_data in user_data_list:
            result = await create_user_pipeline_with_session(api, session, user_data)

            if result.success:
                results.append(result.data)
            else:
                errors.append(f"User {user_data.get('uid', 'unknown')}: {result.error}")

    if errors:
        return FlextResult[None].fail(f"Errors in bulk creation: {'; '.join(errors)}")

    return FlextResult[None].ok(results)

async def create_user_pipeline_with_session(
    api: FlextLdapApi,
    session: str,
    user_data: dict
) -> FlextResult[FlextLdapUser]:
    """User creation pipeline with existing session."""
    return (
        validate_user_data(user_data)
        .map(create_user_request)
        .flat_map_async(lambda request: api.create_user(session, request))
    )
```

---

## 🔧 **Configuration Patterns**

### **Hierarchical LDAP Configuration**

```python
from flext_core import FlextConfig
from pydantic import SecretStr, Field

class FlextLdapConnectionSettings(FlextConfig):
    """LDAP connection configuration."""
    host: str = "localhost"
    port: int = 389
    use_ssl: bool = False
    use_tls: bool = False
    timeout: int = 30

    class Config:
        env_prefix = "FLEXT_LDAP_CONN_"

class FlextLdapAuthSettings(FlextConfig):
    """LDAP authentication configuration."""
    bind_dn: str = ""
    bind_password: SecretStr = SecretStr("")
    auth_method: str = "simple"

    class Config:
        env_prefix = "FLEXT_LDAP_AUTH_"

class FlextLdapSearchSettings(FlextConfig):
    """LDAP search configuration."""
    base_dn: str = "dc=example,dc=com"
    default_filter: str = "(objectClass=*)"
    page_size: int = 1000
    size_limit: int = 0
    time_limit: int = 0

    class Config:
        env_prefix = "FLEXT_LDAP_SEARCH_"

class FlextLdapSettings(FlextConfig):
    """Complete LDAP configuration composition."""
    connection: FlextLdapConnectionSettings = Field(default_factory=FlextLdapConnectionSettings)
    authentication: FlextLdapAuthSettings = Field(default_factory=FlextLdapAuthSettings)
    search: FlextLdapSearchSettings = Field(default_factory=FlextLdapSearchSettings)

    # Integration settings
    enable_connection_pooling: bool = True
    pool_size: int = 10
    enable_metrics: bool = True
    enable_tracing: bool = True

    class Config:
        env_prefix = "FLEXT_LDAP_"
        env_nested_delimiter = "__"
        # Environment variables:
        # FLEXT_LDAP_CONNECTION__HOST=ldap.company.com
        # FLEXT_LDAP_AUTH__BIND_DN=cn=service,dc=company,dc=com
        # FLEXT_LDAP_SEARCH__BASE_DN=ou=users,dc=company,dc=com
```

### **Environment-Specific Configuration**

```python
from enum import Enum

class FlextLdapEnvironment(str, Enum):
    """FLEXT-LDAP deployment environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

class FlextLdapEnvironmentSettings(FlextConfig):
    """Environment-specific LDAP settings."""
    environment: FlextLdapEnvironment = FlextLdapEnvironment.DEVELOPMENT

    @property
    def ldap_settings(self) -> FlextLdapSettings:
        """Get environment-specific LDAP settings."""
        if self.environment == FlextLdapEnvironment.PRODUCTION:
            return FlextLdapSettings(
                connection=FlextLdapConnectionSettings(
                    host="ldap-prod.company.com",
                    port=636,
                    use_ssl=True,
                    timeout=60
                ),
                authentication=FlextLdapAuthSettings(
                    bind_dn="cn=prod-service,ou=applications,dc=company,dc=com",
                    auth_method="sasl"
                )
            )
        elif self.environment == FlextLdapEnvironment.TESTING:
            return FlextLdapSettings(
                connection=FlextLdapConnectionSettings(
                    host="localhost",
                    port=3389,
                    use_ssl=False
                ),
                search=FlextLdapSearchSettings(
                    base_dn="dc=flext,dc=local"
                )
            )
        # ... other environments
```

---

## 🧪 **Testing Patterns**

### **Test Module Organization**

```python
# Test structure mirrors source structure exactly
tests/
├── unit/                        # Unit tests (domain + application)
│   ├── domain/
│   │   ├── test_entities.py     # FlextLdapUser, FlextLdapGroup tests
│   │   ├── test_value_objects.py# DN, Filter validation tests
│   │   └── test_specifications.py# Business rule tests
│   ├── application/
│   │   ├── test_ldap_service.py # Application service tests
│   │   └── test_handlers.py     # Command/query handler tests
│   └── test_api.py              # API layer unit tests
├── integration/                 # Integration tests (infrastructure)
│   ├── test_ldap_client.py      # LDAP client integration
│   ├── test_repositories.py     # Repository integration
│   └── test_docker_ldap.py      # Docker LDAP server tests
├── e2e/                         # End-to-end tests
│   ├── test_user_workflows.py   # Complete user management workflows
│   └── test_group_workflows.py  # Complete group management workflows
├── fixtures/                    # Test data and fixtures
│   ├── ldap_test_data.ldif      # LDAP test data
│   └── user_factory.py          # Test entity factories
└── conftest.py                  # Test configuration and fixtures
```

### **Domain Entity Testing Patterns**

```python
import pytest
from flext_ldap.domain.entities import FlextLdapUser
from flext_ldap.domain.value_objects import FlextLdapDistinguishedName

class TestFlextLdapUser:
    """Test LDAP user domain entity behavior."""

    def test_user_creation_with_valid_data(self):
        """Test successful user creation with valid data."""
        dn = FlextLdapDistinguishedName("uid=john,ou=users,dc=example,dc=com")
        user = FlextLdapUser(
            id="user-123",
            dn=dn,
            uid="john",
            cn="John Doe",
            sn="Doe",
            mail="john@example.com"
        )

        assert user.is_valid()
        assert user.get_display_name() == "John Doe"
        assert user.email == "john@example.com"

    def test_user_activation_success(self):
        """Test successful user activation."""
        user = FlextLdapUser(
            id="user-123",
            dn=FlextLdapDistinguishedName("uid=john,ou=users,dc=example,dc=com"),
            uid="john",
            cn="John Doe",
            sn="Doe",
            mail="john@example.com"
        )

        result = user.activate()

        assert result.success
        assert user.is_active
        assert len(user.domain_events) == 1
        assert user.domain_events[0]["type"] == "UserActivated"

    def test_user_activation_already_active(self):
        """Test activation of already active user."""
        user = FlextLdapUser(
            id="user-123",
            dn=FlextLdapDistinguishedName("uid=john,ou=users,dc=example,dc=com"),
            uid="john",
            cn="John Doe",
            sn="Doe",
            is_active=True
        )

        result = user.activate()

        assert result.is_failure
        assert result.error == "User already active"
        assert len(user.domain_events) == 0

    def test_user_activation_requires_email(self):
        """Test activation requires email address."""
        user = FlextLdapUser(
            id="user-123",
            dn=FlextLdapDistinguishedName("uid=john,ou=users,dc=example,dc=com"),
            uid="john",
            cn="John Doe",
            sn="Doe",
            mail=None  # No email
        )

        result = user.activate()

        assert result.is_failure
        assert result.error == "Email required for activation"
```

### **Value Object Testing Patterns**

```python
import pytest
from flext_ldap.domain.value_objects import FlextLdapDistinguishedName, FlextLdapFilter

class TestFlextLdapDistinguishedName:
    """Test DN value object validation and behavior."""

    def test_valid_dn_creation(self):
        """Test creation with valid DN."""
        dn = FlextLdapDistinguishedName("uid=john,ou=users,dc=example,dc=com")

        assert dn.value == "uid=john,ou=users,dc=example,dc=com"
        assert dn.rdn == "uid=john"
        assert dn.parent_dn == "ou=users,dc=example,dc=com"

    def test_invalid_dn_creation(self):
        """Test creation with invalid DN."""
        with pytest.raises(ValueError, match="Invalid DN format"):
            FlextLdapDistinguishedName("invalid-dn-format")

        with pytest.raises(ValueError, match="Invalid DN format"):
            FlextLdapDistinguishedName("=invalid")

        with pytest.raises(ValueError, match="Invalid DN format"):
            FlextLdapDistinguishedName("")

    def test_dn_hierarchy_checking(self):
        """Test DN hierarchy checking."""
        child_dn = FlextLdapDistinguishedName("uid=john,ou=users,dc=example,dc=com")

        assert child_dn.is_child_of("ou=users,dc=example,dc=com")
        assert child_dn.is_child_of("dc=example,dc=com")
        assert child_dn.is_child_of("dc=com")
        assert not child_dn.is_child_of("ou=groups,dc=example,dc=com")

class TestFlextLdapFilter:
    """Test LDAP filter value object validation."""

    def test_valid_filter_creation(self):
        """Test creation with valid filter."""
        filter_obj = FlextLdapFilter("(uid=john)")
        assert filter_obj.expression == "(uid=john)"

    def test_invalid_filter_creation(self):
        """Test creation with invalid filter."""
        with pytest.raises(ValueError, match="Invalid LDAP filter"):
            FlextLdapFilter("invalid-filter")

        with pytest.raises(ValueError, match="Invalid LDAP filter"):
            FlextLdapFilter("(incomplete")

    def test_filter_factory_methods(self):
        """Test filter factory methods."""
        equals_filter = FlextLdapFilter.equals("uid", "john")
        assert equals_filter.expression == "(uid=john)"

        present_filter = FlextLdapFilter.present("mail")
        assert present_filter.expression == "(mail=*)"

        and_filter = FlextLdapFilter.and_filters(
            FlextLdapFilter.equals("uid", "john"),
            FlextLdapFilter.present("mail")
        )
        assert and_filter.expression == "(&(uid=john)(mail=*))"
```

### **Railway-Oriented Testing Patterns**

```python
import pytest
from flext_core import FlextResult
from flext_ldap import get_ldap_api

@pytest.mark.asyncio
class TestLdapPipelines:
    """Test LDAP operation pipelines with FlextResult chains."""

    async def test_successful_user_creation_pipeline(self, mock_ldap_api):
        """Test successful user creation pipeline."""
        user_data = {
            "uid": "john",
            "cn": "John Doe",
            "sn": "Doe",
            "mail": "john@example.com"
        }

        result = await create_user_pipeline(user_data)

        assert result.success
        assert result.data.uid == "john"
        assert result.data.cn == "John Doe"

    async def test_user_creation_pipeline_validation_failure(self):
        """Test user creation pipeline with validation failure."""
        invalid_user_data = {
            "uid": "",  # Invalid: empty UID
            "cn": "John Doe",
            "sn": "Doe"
        }

        result = await create_user_pipeline(invalid_user_data)

        assert result.is_failure
        assert "UID is required" in result.error

    async def test_user_creation_pipeline_ldap_failure(self, mock_failing_ldap_api):
        """Test user creation pipeline with LDAP failure."""
        user_data = {
            "uid": "john",
            "cn": "John Doe",
            "sn": "Doe",
            "mail": "john@example.com"
        }

        result = await create_user_pipeline(user_data)

        assert result.is_failure
        assert "LDAP" in result.error

    async def test_bulk_user_creation_partial_success(self, mock_ldap_api):
        """Test bulk user creation with partial success."""
        user_data_list = [
            {"uid": "john", "cn": "John Doe", "sn": "Doe"},
            {"uid": "", "cn": "Invalid User", "sn": "User"},  # Invalid
            {"uid": "jane", "cn": "Jane Doe", "sn": "Doe"}
        ]

        result = await bulk_user_creation(user_data_list)

        assert result.is_failure
        assert "UID is required" in result.error
        # Should contain error for invalid user but processing should continue
```

---

## 📋 **Module Creation Checklist**

### **New Module Standards**

- [ ] **Naming**: Follows `FlextLdap` prefix convention for public exports
- [ ] **Layer Placement**: Correctly positioned in Clean Architecture layers
- [ ] **Dependencies**: Only imports from same or lower layers + flext-core
- [ ] **Types**: 100% type annotation coverage with strict MyPy compliance
- [ ] **Error Handling**: All operations return `FlextResult[T]` for consistency
- [ ] **Documentation**: Comprehensive docstrings with business context
- [ ] **Tests**: 95%+ coverage with unit, integration, and e2e tests
- [ ] **Domain Logic**: Business rules implemented in domain entities
- [ ] **Railway Pattern**: Proper FlextResult chaining for error handling
- [ ] **FLEXT Integration**: Uses flext-core patterns (DI, config, logging)

### **Code Quality Gates**

- [ ] **Linting**: `make lint` passes with zero Ruff violations
- [ ] **Type Safety**: `make type-check` passes with strict MyPy validation
- [ ] **Security**: `make security` passes Bandit + pip-audit scans
- [ ] **Testing**: `make test` passes with 95%+ coverage minimum
- [ ] **Performance**: No performance regressions in LDAP operations
- [ ] **Documentation**: All public APIs documented with examples
- [ ] **Integration**: Compatible with existing FLEXT ecosystem projects
- [ ] **Backward Compatibility**: Maintains API compatibility where possible

### **LDAP-Specific Requirements**

- [ ] **RFC Compliance**: LDAP operations follow RFC 4510-4519 standards
- [ ] **DN Validation**: Distinguished Names validated per RFC 4514
- [ ] **Filter Validation**: Search filters validated per RFC 4515
- [ ] **Schema Awareness**: Proper LDAP schema handling and validation
- [ ] **Security**: TLS/SSL support and secure credential handling
- [ ] **Connection Management**: Proper connection pooling and cleanup
- [ ] **Error Mapping**: LDAP protocol errors mapped to domain errors
- [ ] **Performance**: Efficient search operations with pagination support

---

## 🌐 **FLEXT Ecosystem Integration Guidelines**

### **Cross-Project Import Standards**

```python
# ✅ Standard ecosystem imports for LDAP integration
from flext_core import FlextResult, FlextContainer, get_logger
from flext_ldap import get_ldap_api, FlextLdapUser, FlextLdapGroup
from flext_auth import FlextAuthService
from flext_meltano import FlextMeltanoOrchestrator

# ✅ LDAP-Auth integration pattern
class FlextLdapAuthIntegration:
    def __init__(self, container: FlextContainer):
        self._ldap_api = container.resolve("ldap_api")
        self._auth_service = container.resolve("auth_service")

    async def authenticate_user(
        self,
        username: str,
        password: str
    ) -> FlextResult[FlextLdapUser]:
        """Authenticate user against LDAP directory."""
        return (
            self._auth_service.validate_credentials(username, password)
            .flat_map_async(lambda creds: self._ldap_api.find_user_by_uid(creds.username))
            .flat_map(lambda user: self._validate_user_permissions(user))
        )

# ✅ LDAP-Meltano Singer integration pattern
from flext_tap_ldap import FlextLdapTap
from flext_target_ldap import FlextLdapTarget

class FlextLdapMeltanoIntegration:
    def __init__(self, ldap_api: FlextLdapApi):
        self._ldap_api = ldap_api

    def create_ldap_tap(self, config: dict) -> FlextLdapTap:
        """Create LDAP tap with API integration."""
        tap = FlextLdapTap(config)
        tap.set_ldap_provider(self._ldap_api)  # Inject LDAP API
        return tap

    def create_ldap_target(self, config: dict) -> FlextLdapTarget:
        """Create LDAP target with API integration."""
        target = FlextLdapTarget(config)
        target.set_ldap_provider(self._ldap_api)  # Inject LDAP API
        return target
```

### **Configuration Integration Patterns**

```python
# ✅ FLEXT ecosystem configuration composition
from flext_core import FlextConfig
from flext_ldap import FlextLdapSettings
from flext_auth import FlextAuthSettings
from flext_observability import FlextObservabilitySettings

class FlextEcosystemSettings(FlextConfig):
    """Complete FLEXT ecosystem configuration."""

    # Core components
    ldap: FlextLdapSettings = Field(default_factory=FlextLdapSettings)
    auth: FlextAuthSettings = Field(default_factory=FlextAuthSettings)
    observability: FlextObservabilitySettings = Field(default_factory=FlextObservabilitySettings)

    # Integration settings
    enable_ldap_auth: bool = True
    enable_ldap_metrics: bool = True
    enable_singer_integration: bool = True

    class Config:
        env_prefix = "FLEXT_"
        env_nested_delimiter = "__"
        # Environment variables:
        # FLEXT_LDAP__CONNECTION__HOST=ldap.company.com
        # FLEXT_AUTH__LDAP_PROVIDER_ENABLED=true
        # FLEXT_OBSERVABILITY__ENABLE_TRACING=true

    @property
    def ldap_auth_enabled(self) -> bool:
        """Check if LDAP authentication is enabled."""
        return self.enable_ldap_auth and self.auth.ldap_provider_enabled
```

---

## 🔄 **Migration & Evolution Patterns**

### **Module Evolution Strategy**

```python
# Current module organization (0.9.0)
src/flext_ldap/
├── api.py                    # ✅ Stable - main API
├── entities.py              # ✅ Stable - domain entities
├── values.py                # ✅ Stable - value objects
├── config.py                # ✅ Stable - configuration
├── ldap_infrastructure.py   # ✅ Stable - infrastructure client
├── application/             # 🔄 Evolving - application layer
└── domain/                  # 🚧 Under development - pure domain

# Target module organization (0.9.0)
src/flext_ldap/
├── api.py                    # ✅ Mature - unified API
├── domain/                   # ✅ Complete - rich domain model
│   ├── entities.py          # ✅ Moved from root
│   ├── value_objects.py     # ✅ Moved from values.py
│   ├── aggregates.py        # 🆕 New - aggregate roots
│   ├── specifications.py    # 🆕 New - business rules
│   └── events.py           # 🆕 New - domain events
├── application/             # ✅ Complete - CQRS + handlers
├── infrastructure/          # ✅ Mature - repository implementations
└── adapters/               # 🆕 New - external system adapters
```

### **Backward Compatibility Strategy**

```python
# Legacy compatibility layer in __init__.py
from __future__ import annotations

import warnings
from typing import Any

# Modern imports (primary)
from flext_ldap.api import FlextLdapApi, get_ldap_api
from flext_ldap.entities import FlextLdapUser, FlextLdapGroup, FlextLdapEntry
from flext_ldap.values import FlextLdapDistinguishedName, FlextLdapCreateUserRequest

# Legacy import handling with deprecation warnings
def __getattr__(name: str) -> Any:
    """Handle legacy imports with deprecation warnings."""

    # Legacy API mappings (deprecated in 0.9.0, removed in 0.9.0)
    legacy_api_mappings = {
        "FlextLdapClient": "FlextLdapApi",
        "LDAPClient": "FlextLdapApi",
        "SimpleAPI": "FlextLdapApi",
        "LDAPService": "FlextLdapApi"
    }

    if name in legacy_api_mappings:
        warnings.warn(
            f"Importing {name} is deprecated since 0.9.0. "
            f"Use 'from flext_ldap import {legacy_api_mappings[name]}' instead. "
            f"This will be removed in version 0.9.0.",
            DeprecationWarning,
            stacklevel=2
        )
        return FlextLdapApi

    # Legacy entity mappings (deprecated in 0.9.0, removed in 0.9.0)
    legacy_entity_mappings = {
        "LDAPUser": FlextLdapUser,
        "LDAPGroup": FlextLdapGroup,
        "LDAPEntry": FlextLdapEntry,
        "CreateUserRequest": FlextLdapCreateUserRequest
    }

    if name in legacy_entity_mappings:
        warnings.warn(
            f"Importing {name} from root is deprecated since 0.9.0. "
            f"Use 'from flext_ldap import Flext{name}' instead. "
            f"This will be removed in version 0.9.0.",
            DeprecationWarning,
            stacklevel=2
        )
        return legacy_entity_mappings[name]

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

# Clean public API (current and future)
__all__: list[str] = [
    # Core API (stable)
    "FlextLdapApi",
    "get_ldap_api",

    # Domain entities (stable)
    "FlextLdapUser",
    "FlextLdapGroup",
    "FlextLdapEntry",

    # Value objects (stable)
    "FlextLdapDistinguishedName",
    "FlextLdapCreateUserRequest",

    # Configuration (stable)
    "FlextLdapSettings",

    # Infrastructure (advanced usage)
    "FlextLdapClient"
]
```

---

**Last Updated**: August 3, 2025
**Target Audience**: FLEXT-LDAP developers and FLEXT ecosystem contributors
**Scope**: Python module organization for LDAP directory services integration
**Version**: 0.9.0 → 0.9.0 development guidelines
**Compliance**: FLEXT-Core architectural standards and Clean Architecture principles
