"""Advanced type system for LDAP Core Shared.

CLEAN IMPORTS - No wildcards, explicit exports only.
This module provides type definitions for enterprise LDAP operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Import specific types only - NO WILDCARDS
from ldap_core_shared.types.aliases import (
    DN,
    Attributes,
    FilterExpression,
    OperationResult,
    SearchScope,
)
from ldap_core_shared.types.base import (
    BaseEntity,
    BaseModel,
    BaseRepository,
    BaseService,
    BaseValueObject,
)
from ldap_core_shared.types.generics import (
    Repository,
    Result,
    Service,
)
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
]
