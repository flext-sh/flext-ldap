"""LDAP Type Definitions - Type System for FLEXT LDAP Operations.

Python 3.13+ strict: Uses PEP 695 type aliases (type keyword) exclusively.
No backward compatibility with Python < 3.13.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from flext_core import FlextTypes
from flext_ldif import FlextLdifTypes

__all__ = [
    "FlextLdapTypes",
]


class FlextLdapTypes(FlextTypes):
    """LDAP-specific type definitions extending FlextTypes.

    Domain-specific type system for LDAP operations.
    Minimal types - reuses FlextLdifTypes when possible.

    Uses Python 3.13+ strict best practices:
    - PEP 695 type aliases (type keyword) - no TypeAlias
    - collections.ABC types (Mapping, Sequence) for read-only semantics
    - Proper type annotations following Pydantic 2 patterns
    - No backward compatibility with Python < 3.13
    """

    # =========================================================================
    # LDAP SEARCH RESULT TYPES (Python 3.13+ collections.ABC)
    # =========================================================================

    # Using Sequence for read-only list semantics (Python 3.13 best practice)
    type SearchResult = Sequence[FlextLdifTypes.ModelInstance]
    """Read-only sequence of LDAP entries from search operation."""

    # =========================================================================
    # LDAP OPERATION DATA TYPES
    # =========================================================================
    # Note: LdapModifyChanges, LdapAttributes, LdapAttributeValues remain as dict
    # for compatibility with ldap3 library's native format (mutable dict required)
    # Use FlextLdapModels.LdapOperationResult and FlextLdapModels.LdapBatchStats
    # directly for model-based operations

    type LdapModifyChanges = dict[str, list[tuple[str, list[str]]]]
    """LDAP modify changes format (mutable dict for ldap3 compatibility).

    Format: {attribute_name: [(operation, [values])]}
    Operations: 'add', 'delete', 'replace'
    """

    type LdapAttributeValues = dict[str, list[str]]
    """LDAP attribute values (mutable dict for ldap3 compatibility).

    Format: {attribute_name: [value1, value2, ...]}
    """

    type LdapAttributes = dict[str, list[str]]
    """LDAP attributes dictionary (mutable dict for ldap3 compatibility).

    Format: {attribute_name: [value1, value2, ...]}
    """

    # Read-only version for type hints where mutation is not needed
    # Using Mapping and Sequence from collections.ABC (Python 3.13 best practice)
    type LdapAttributesReadOnly = Mapping[str, Sequence[str]]
    """Read-only LDAP attributes mapping (Python 3.13+ collections.ABC).

    Use this for function parameters where attributes should not be modified.
    Format: {attribute_name: [value1, value2, ...]}
    """

    # =========================================================================
    # LDAP OPERATION CALLABLES (Python 3.13+ collections.ABC.Callable)
    # =========================================================================

    type LdapAddCallable = Callable[
        [str, str | None, LdapAttributeValues | None],
        bool,
    ]
    """Callable for LDAP add operation.

    Signature: (dn, controls, attributes) -> bool
    """

    type LdapModifyCallable = Callable[[str, LdapModifyChanges], bool]
    """Callable for LDAP modify operation.

    Signature: (dn, changes) -> bool
    """

    type LdapDeleteCallable = Callable[[str], bool]
    """Callable for LDAP delete operation.

    Signature: (dn) -> bool
    """

    type LdapSearchCallable = Callable[
        [
            str,  # base_dn
            str,  # filter_str
            int,  # scope
            Sequence[str] | None,  # attributes
            bool,  # dereference_aliases
            Mapping[str, str] | None,  # controls
            int | None,  # size_limit
            int | None,  # time_limit
            bool,  # types_only
            Mapping[str, str] | None,  # extended_attributes
        ],
        tuple[bool, Mapping[str, Sequence[Mapping[str, Sequence[str]]]]],
    ]
    """Callable for LDAP search operation.

    Returns:
        (success: bool, results: Mapping[str, Sequence[Mapping[str, Sequence[str]]]])
    Results format: {dn: [{attribute: [values]}]}
    """

    # Note: LdapProgressCallback moved to models.py to avoid circular import
    # Import from models: from flext_ldap.models import FlextLdapModels
    # Use: FlextLdapModels.LdapProgressCallback
