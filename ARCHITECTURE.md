# FLEXT LDAP - Architecture & Migration Guide

🏗️ **Clean Architecture Implementation**  
🔄 **Semantic Reorganization in Progress**

## Overview

FLEXT LDAP has been completely reorganized following **Clean Architecture** and **Domain-Driven Design** patterns, built on top of the `flext-core` foundation. This document outlines the new architecture and provides migration guidance.

## Architecture Layers

### 🎯 Domain Layer (Pure Business Logic)

The domain layer contains pure business logic with no external dependencies:

```
src/flext_ldap/domain/
├── aggregates.py      # DirectoryAggregate, LDAPDirectory
├── entities.py        # LDAPEntry, LDAPUser, LDAPGroup  
├── events.py          # Domain events (LDAPConnectionEstablished, etc.)
├── interfaces.py      # Abstract contracts (LDAPConnectionManager, etc.)
├── specifications.py  # Business rules (LDAPEntrySpecification, etc.)
└── values.py          # Immutable values (DistinguishedName, LDAPFilter, etc.)
```

#### Key Domain Patterns

- **Aggregates**: Consistency boundaries (DirectoryAggregate)
- **Entities**: Objects with identity (LDAPUser, LDAPGroup)
- **Value Objects**: Immutable concepts (DistinguishedName, LDAPFilter)
- **Events**: Business occurrences (LDAPConnectionEstablished)
- **Specifications**: Reusable business rules
- **Interfaces**: Contracts for infrastructure

### 🎯 Application Layer (Use Cases)

*To be implemented* - Application services, commands, queries, and handlers.

```
src/flext_ldap/application/
├── services/          # Application services
├── commands/          # Commands and command handlers
├── queries/           # Queries and query handlers
└── handlers/          # Event handlers
```

### 🎯 Infrastructure Layer (External Concerns)

*To be implemented* - Concrete implementations of domain interfaces.

```
src/flext_ldap/infrastructure/
├── clients/           # LDAP client implementations
├── repositories/      # Repository implementations
├── validators/        # Schema validators
└── adapters/          # External service adapters
```

### 🎯 Interface Layer (Adapters)

*To be implemented* - Controllers, presenters, and adapters.

```
src/flext_ldap/interfaces/
├── controllers/       # Request handlers
├── presenters/        # Response formatters
└── mappers/           # Data transformation
```

## Foundation Integration

FLEXT LDAP is built on `flext-core` foundation patterns:

### Core Dependencies

```python
from flext_core.foundation import (
    AbstractEntity,
    AbstractRepository,
    AbstractValueObject,
    SpecificationPattern,
)
from flext_core.domain.pydantic_base import (
    DomainAggregateRoot,
    DomainEntity,
    DomainEvent,
    DomainValueObject,
)
from flext_core.domain.types import ServiceResult
```

### Key Patterns Used

- **ServiceResult**: Type-safe error handling without exceptions
- **Specification Pattern**: Composable business rules
- **Domain Events**: Decoupled communication
- **Repository Pattern**: Data access abstraction

## Migration Guide

### 🚨 Deprecation Strategy

Old code continues to work with deprecation warnings:

```python
# ❌ DEPRECATED (shows warning)
from flext_ldap import LDAPClient, LDAPConfig

# ✅ NEW APPROACH (recommended)
from flext_ldap.domain.interfaces import LDAPConnectionManager
from flext_ldap.domain.values import LDAPUri, DistinguishedName
```

### Migration Steps

1. **Update Imports** - Use new semantic structure
2. **Adopt ServiceResult** - Replace exception handling with ServiceResult
3. **Use Value Objects** - Replace strings with typed value objects
4. **Apply Specifications** - Use business rules instead of ad-hoc validation

### Example Migration

#### Before (Deprecated)
```python
from flext_ldap import LDAPClient, LDAPConfig

config = LDAPConfig(server="ldap.example.com")
client = LDAPClient(config)

try:
    client.connect()
    entries = client.search("dc=example,dc=com", "(objectClass=person)")
except LDAPException as e:
    print(f"Error: {e}")
```

#### After (New Architecture)
```python
from flext_ldap.domain.interfaces import LDAPConnectionManager
from flext_ldap.domain.values import DistinguishedName, LDAPFilter, LDAPScope
from flext_ldap.domain.specifications import ValidLDAPEntrySpecification

# Use dependency injection (configured elsewhere)
connection_manager: LDAPConnectionManager = get_connection_manager()

# Type-safe value objects
base_dn = DistinguishedName(value="dc=example,dc=com")
search_filter = LDAPFilter.equals("objectClass", "person")

# ServiceResult pattern
result = await connection_manager.connect("ldap://ldap.example.com")
if result.is_success:
    connection_id = result.data
    search_result = await repository.search(
        connection_id=connection_id,
        base_dn=base_dn,
        search_filter=search_filter,
        scope=LDAPScope.SUBTREE
    )
    
    if search_result.is_success:
        entries = search_result.data
        # Apply business rules
        spec = ValidLDAPEntrySpecification()
        valid_entries = [e for e in entries if spec.is_satisfied_by(e)]
```

## Value Objects Reference

### DistinguishedName
```python
from flext_ldap.domain.values import DistinguishedName

dn = DistinguishedName(value="cn=john,ou=users,dc=example,dc=com")
print(dn.get_rdn())  # "cn=john"
print(dn.get_parent_dn())  # "ou=users,dc=example,dc=com"
```

### LDAPFilter
```python
from flext_ldap.domain.values import LDAPFilter

# Factory methods
filter1 = LDAPFilter.equals("uid", "john")
filter2 = LDAPFilter.present("mail")
combined = LDAPFilter.and_filters(filter1, filter2)
```

### LDAPAttributes
```python
from flext_ldap.domain.values import LDAPAttributes

attrs = LDAPAttributes(attributes={
    "cn": ["John Doe"],
    "mail": ["john@example.com"],
    "objectClass": ["person", "inetOrgPerson"]
})

email = attrs.get_single_value("mail")  # "john@example.com"
classes = attrs.get_values("objectClass")  # ["person", "inetOrgPerson"]
```

## Specifications Reference

### Composable Business Rules
```python
from flext_ldap.domain.specifications import (
    ValidLDAPEntrySpecification,
    ActiveLDAPUserSpecification,
    NonEmptyGroupSpecification
)

# Combine specifications
valid_spec = ValidLDAPEntrySpecification()
active_spec = ActiveLDAPUserSpecification()

# Use with entities
if valid_spec.is_satisfied_by(entry) and active_spec.is_satisfied_by(user):
    # Process valid, active user
    pass
```

## Events Reference

### Domain Events
```python
from flext_ldap.domain.events import LDAPConnectionEstablished

# Events are raised automatically by aggregates
event = LDAPConnectionEstablished(
    aggregate_id="dir-123",
    connection_id="conn-456",
    base_dn="dc=example,dc=com"
)
```

## Quality Standards

- **Zero Tolerance**: All quality gates must pass
- **Type Safety**: 100% MyPy compliance in strict mode
- **Test Coverage**: 90%+ coverage requirement
- **Clean Architecture**: Strict dependency rules enforced
- **SOLID Principles**: Single responsibility, dependency inversion

## Best Practices

1. **Use Value Objects** - Always use typed value objects instead of primitives
2. **Apply Specifications** - Encapsulate business rules in specifications
3. **Handle Results** - Use ServiceResult pattern for error handling
4. **Depend on Abstractions** - Program against interfaces, not implementations
5. **Raise Events** - Use domain events for cross-boundary communication

## Testing Strategy

```python
# Domain layer tests - pure unit tests
def test_distinguished_name_validation():
    with pytest.raises(ValueError):
        DistinguishedName(value="invalid-dn")

# Specification tests
def test_valid_ldap_entry_specification():
    spec = ValidLDAPEntrySpecification()
    assert spec.is_satisfied_by(valid_entry)
    assert not spec.is_satisfied_by(invalid_entry)

# Integration tests with ServiceResult
async def test_ldap_connection():
    result = await connection_manager.connect("ldap://test.example.com")
    assert result.is_success
    assert result.data is not None
```

## Performance Considerations

- **Immutable Objects**: Value objects are immutable and safe to cache
- **Lazy Loading**: Aggregates load data only when needed
- **Event Sourcing**: Events can be replayed for audit and debugging
- **Connection Pooling**: Infrastructure layer handles connection management

## Security

- **Input Validation**: All value objects validate input
- **LDAP Injection**: Filters are properly escaped
- **Authentication**: Secure credential handling
- **Authorization**: Role-based access control

---

**Status**: ✅ Domain layer complete, Application layer in progress  
**Migration**: Backward compatibility maintained with deprecation warnings  
**Quality**: Zero tolerance for lint/type/test failures