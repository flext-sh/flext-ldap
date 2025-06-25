"""Advanced type system for LDAP Core Shared.

This module provides a comprehensive type system that serves as the foundation
for all other modules, ensuring type safety and eliminating code duplication
through well-defined protocols and type aliases.

Following SOLID principles:
- Single Responsibility: Each type serves one specific purpose
- Open/Closed: Types are open for extension via protocols
- Liskov Substitution: All implementations honor their contracts
- Interface Segregation: Small, focused protocols
- Dependency Inversion: Depend on abstractions, not concretions

Key design principles:
- DRY: Zero code duplication through generic base types
- KISS: Simple, focused type definitions
- Type Safety: 100% typed with strict mypy compliance
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ldap_core_shared.types.aliases import *  # noqa: F403
from ldap_core_shared.types.aliases import (
    DN,
    Attributes,
    FilterExpression,
    OperationResult,
    SearchScope,
)

# Re-export all types for convenient imports
from ldap_core_shared.types.base import *  # noqa: F403
from ldap_core_shared.types.base import (
    BaseEntity,
    BaseModel,
    BaseRepository,
    BaseService,
    BaseValueObject,
)
from ldap_core_shared.types.generics import *  # noqa: F403
from ldap_core_shared.types.generics import (
    Entity,
    Repository,
    Result,
    Service,
    ValueObject,
)
from ldap_core_shared.types.protocols import *  # noqa: F403
from ldap_core_shared.types.protocols import (
    Cacheable,
    Connectable,
    Searchable,
    Serializable,
    Validatable,
)

# Type checking imports for better IDE support

__all__ = [
    # Type aliases
    "DN",
    "Attributes",
    "BaseEntity",
    # Base classes
    "BaseModel",
    "BaseRepository",
    "BaseService",
    "BaseValueObject",
    "Cacheable",
    # Protocols
    "Connectable",
    "Entity",
    "FilterExpression",
    "OperationResult",
    # Generic types
    "Repository",
    "Result",
    "SearchScope",
    "Searchable",
    "Serializable",
    "Service",
    "Validatable",
    "ValueObject",
]
