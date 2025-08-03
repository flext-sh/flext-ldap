"""LDAP Domain Layer - Pure Business Logic.

🏗️ CLEAN ARCHITECTURE: Domain Layer
Built on flext-core foundation patterns.

🚨 MIGRATION NOTICE:
Old imports are deprecated. Use new semantic structure:
- entities.* → domain.aggregates.*
- value_objects.* → domain.values.*
- ports.* → domain.interfaces.*

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings

from flext_ldap.domain.aggregates import (
    FlextLdapDirectory,
    FlextLdapDirectoryAggregate,
)
from flext_ldap.domain.events import (
    FlextLdapAuthenticationFailed,
    FlextLdapConnectionEstablished,
    FlextLdapConnectionLost,
    FlextLdapEntryCreated,
    FlextLdapEntryDeleted,
    FlextLdapEntryModified,
    FlextLdapGroupMemberAdded,
    FlextLdapGroupMemberRemoved,
    FlextLdapUserAuthenticated,
)
from flext_ldap.domain.exceptions import LDAPDomainError
from flext_ldap.domain.interfaces import (
    FlextLdapConnectionManager,
    FlextLdapDirectoryRepository,
    FlextLdapGroupRepository,
    FlextLdapSchemaValidator,
)
from flext_ldap.domain.repositories import (
    FlextLdapUserRepository,
)
from flext_ldap.domain.specifications import (
    FlextLdapEntrySpecification,
    FlextLdapUserSpecification,
)
from flext_ldap.entities import (
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)
from flext_ldap.values import (
    FlextLdapAttributesValue as LDAPAttributes,
    FlextLdapDistinguishedName,
    FlextLdapFilterValue as LDAPFilter,
    FlextLdapObjectClass as LDAPObjectClass,
    FlextLdapScopeEnum as LDAPScope,
    FlextLdapUri as LDAPUri,
)


# DEPRECATED IMPORTS (backward compatibility)
def _warn_deprecated_import(old_item: str, new_path: str) -> None:
    """Issue deprecation warning for old imports."""
    warnings.warn(
        f"Importing '{old_item}' from flext_ldap.domain is deprecated. "
        f"Use 'from flext_ldap.{new_path}' instead. "
        f"This will be removed in version 1.0.0.",
        DeprecationWarning,
        stacklevel=3,
    )


# Legacy compatibility - use proper modules

# Create simple aliases for backward compatibility
LDAPError = LDAPDomainError

# Legacy aliases (avoid redefinition)
LDAPEntry = FlextLdapEntry
LDAPUser = FlextLdapUser
LDAPGroup = FlextLdapGroup
LDAPConnection = FlextLdapDirectoryAggregate
LDAPDirectory = FlextLdapDirectory
LDAPAttribute = LDAPAttributes
LDAPConnectionRepository = FlextLdapConnectionManager
LDAPUserRepository = FlextLdapDirectoryRepository
LDAPEntrySpecification = FlextLdapEntrySpecification
LDAPUserSpecification = FlextLdapUserSpecification


# Backward compatibility classes (deprecated - use proper modules)
class LDAPSecurityContext:
    """Deprecated: Use flext_ldap.domain.security module instead."""

    def __init__(self) -> None:
        warnings.warn(
            "LDAPSecurityContext is deprecated. Use flext_ldap.domain.security module.",
            DeprecationWarning,
            stacklevel=2,
        )


class LDAPOperation:
    """Deprecated: Use flext_ldap.application.ldap_service module instead."""

    def __init__(self) -> None:
        warnings.warn(
            "LDAPOperation is deprecated. "
            "Use flext_ldap.application.ldap_service module.",
            DeprecationWarning,
            stacklevel=2,
        )


__all__ = [
    # Aggregates
    "DirectoryAggregate",
    "FlextLdapAuthenticationFailed",
    "FlextLdapConnectionEstablished",
    "FlextLdapConnectionLost",
    # Values
    "FlextLdapDistinguishedName",
    "FlextLdapEntryCreated",
    "FlextLdapEntryDeleted",
    "FlextLdapEntryModified",
    "FlextLdapEntrySpecification",
    "FlextLdapGroupMemberAdded",
    "FlextLdapGroupMemberRemoved",
    "FlextLdapGroupRepository",
    "FlextLdapSchemaValidator",
    "FlextLdapUserAuthenticated",
    "FlextLdapUserRepository",
    "FlextLdapUserSpecification",
    # Entities
    "LDAPAttribute",  # → LDAPAttributes
    "LDAPAttributes",
    "LDAPConnection",  # → DirectoryAggregate
    "LDAPConnectionEstablished",
    "LDAPConnectionManager",
    "LDAPConnectionRepository",  # → LDAPConnectionManager
    "LDAPDirectory",
    "LDAPDirectoryRepository",
    "LDAPEntry",
    "LDAPEntryCreated",
    "LDAPEntryDeleted",
    "LDAPEntryModified",
    "LDAPError",  # → Domain exceptions
    "LDAPFilter",
    "LDAPGroup",
    "LDAPObjectClass",
    "LDAPOperation",  # → Commands
    "LDAPScope",
    "LDAPSecurityContext",  # → Security
    "LDAPUri",
    "LDAPUser",
    "LDAPUserRepository",  # → Interfaces
]
