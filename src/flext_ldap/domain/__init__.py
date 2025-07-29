"""LDAP Domain Layer - Pure Business Logic.

🏗️ CLEAN ARCHITECTURE: Domain Layer
Built on flext-core foundation patterns.

🚨 MIGRATION NOTICE:
Old imports are deprecated. Use new semantic structure:
- entities.* → domain.aggregates.*
- value_objects.* → domain.values.*
- ports.* → domain.interfaces.*
"""

from __future__ import annotations

import warnings

# NEW SEMANTIC STRUCTURE - Import all real implementations (NO FALLBACKS)
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
    FlextLdapDistinguishedName as DistinguishedName,
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


# Simple placeholders for backward compatibility
class LDAPSecurityContext:
    """LDAP security context placeholder - use security module instead."""


class LDAPOperation:
    """LDAP operation placeholder - use commands in application layer instead."""


__all__ = [
    # Aggregates
    "DirectoryAggregate",
    # Values
    "DistinguishedName",
    "FlextLdapEntrySpecification",
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
