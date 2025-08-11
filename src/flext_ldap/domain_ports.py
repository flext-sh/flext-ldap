"""Legacy facade for domain ports.

This module re-exports centralized abstractions from `flext_ldap.abstracts`
to maintain backward compatibility while enforcing a single source of truth.

Rules applied:
- No duplication of functionalities or modules
- Import from flext_* libraries by their root
- Prefer the newest, centralized interfaces

Concrete implementations must import from `flext_ldap.abstracts` and
`flext_ldap.protocols`. This module only exists for legacy imports.
"""

from __future__ import annotations

# Public re-exports from the centralized abstracts module
from flext_ldap.abstracts import (
    FlextLdapConnectionService,
    FlextLdapGroupService,
    FlextLdapMigrationService,
    FlextLdapSchemaService,
    FlextLdapService,
    FlextLdapUserService,
)

__all__ = [
    "FlextLdapConnectionService",
    "FlextLdapGroupService",
    "FlextLdapMigrationService",
    "FlextLdapSchemaService",
    "FlextLdapService",
    "FlextLdapUserService",
]
