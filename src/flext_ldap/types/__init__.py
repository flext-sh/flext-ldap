"""Advanced type system for LDAP Core Shared.

CLEAN IMPORTS - No wildcards, explicit exports only.
This module provides type definitions for enterprise LDAP operations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldapcols import (
    Cacheable,
    Connectable,
    Searchable,
    Serializable,
    Validatable,
)
from flext_ldapics import (
    Repository,
    Result,
    Service,
)

from flext_ldap import (
    BaseEntity,
    BaseModel,
    BaseRepository,
    BaseService,
    BaseValueObject,
)

# Import specific types only - NO WILDCARDS
from flext_ldap.types.aliases import (
    DN,
    Attributes,
    FilterExpression,
    OperationResult,
    SearchScope,
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
