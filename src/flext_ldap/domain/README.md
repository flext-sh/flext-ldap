# Domain Layer - FLEXT-LDAP

The domain layer contains pure business logic for LDAP directory operations, implementing Domain-Driven Design principles without external dependencies.

## Architecture Principles

This layer follows strict Clean Architecture rules:

- **No external dependencies**: Only imports from the same layer or flext-core
- **Business logic focus**: Rich domain entities with embedded business rules
- **Immutable value objects**: Type-safe data structures with validation
- **Domain events**: Business event modeling for cross-aggregate communication

## Module Structure

### Core Domain Components

```
domain/
├── __init__.py           # Domain layer exports
├── repositories.py       # Repository interfaces (abstract contracts)
├── specifications.py     # Business rule specifications
├── exceptions.py         # Domain-specific exception types
├── events.py            # Domain event definitions
├── interfaces.py        # Domain service interfaces
├── ports.py             # Port definitions for Clean Architecture
├── security.py          # Domain security rules and validations
└── aggregates.py        # Aggregate root definitions
```

### Entity Definitions (Root Level)

- **entities.py**: Rich domain entities (FlextLdapUser, FlextLdapGroup, FlextLdapEntry)
- **values.py**: Value objects and immutable data structures

## Domain Entities

Domain entities contain business logic and maintain consistency boundaries:

### FlextLdapUser

Rich user entity with business operations:

- User activation/deactivation logic
- Email change validation
- Group membership management
- Business rule enforcement

### FlextLdapGroup

Group entity managing membership:

- Member addition/removal
- Permission validation
- Group hierarchy management

### FlextLdapEntry

Generic LDAP entry with:

- Attribute validation
- Schema compliance checking
- DN hierarchy management

## Value Objects

Immutable value objects ensure data integrity:

### FlextLdapDistinguishedName

- RFC 4514 DN format validation
- Hierarchy navigation (parent/child relationships)
- RDN extraction utilities

### FlextLdapFilter

- RFC 4515 filter syntax validation
- Filter composition operations
- Search optimization hints

## Repository Interfaces

Abstract contracts for data access:

```python
class FlextLdapUserRepository(ABC):
    """Domain repository contract for user operations."""

    @abstractmethod
    async def save(self, user: FlextLdapUser) -> FlextResult[FlextLdapUser]:
        """Save user to directory."""

    @abstractmethod
    async def find_by_dn(self, dn: str) -> FlextResult[Optional[FlextLdapUser]]:
        """Find user by distinguished name."""
```

## Domain Specifications

Business rule specifications using the Specification pattern:

```python
class ActiveUserSpecification(FlextLdapSpecification[FlextLdapUser]):
    """Specification for active user validation."""

    def is_satisfied_by(self, user: FlextLdapUser) -> bool:
        return user.is_active and user.mail is not None
```

## Domain Events

Events representing business occurrences:

```python
@dataclass
class UserActivatedEvent(FlextLdapDomainEvent):
    """Event raised when user is activated."""
    user_id: str
    user_dn: str
    activated_at: datetime
```

## Usage Guidelines

### Business Logic Placement

- Put business rules in domain entities
- Use specifications for complex validation logic
- Implement domain services for multi-entity operations
- Raise domain events for significant business occurrences

### External Dependencies

- Never import from infrastructure or application layers
- Only use flext-core foundation types
- Maintain pure business logic without framework coupling

### Testing Strategy

- Test business logic in isolation
- Use test doubles for repository interfaces
- Validate domain events are raised correctly
- Test business rule violations and edge cases

## Integration with Application Layer

The domain layer provides contracts that the application layer implements:

- Repository interfaces → Infrastructure implementations
- Domain services → Application service coordination
- Domain events → Event handlers and side effects

This ensures business logic remains isolated and testable while providing clear contracts for external integration.
