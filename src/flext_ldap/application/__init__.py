"""Application layer for FLEXT-LDAP v0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

REFACTORED:
            Using flext-core application patterns - NO duplication.
"""

from __future__ import annotations

from flext_ldap.domain.ports import (
    FlextLdapMigrationService,
    FlextLdapSchemaService,
    FlextLdapSearchService,
    FlextLdapUserService,
)

# Import specialized services from root (services moved to root)
from flext_ldap.services import (
    FlextLdapConnectionApplicationService,
    FlextLdapGroupService,
    FlextLdapOperationService,
    FlextLdapUserApplicationService,
)

__all__ = [
    # Domain ports
    "FlextLdapMigrationService",
    "FlextLdapSchemaService",
    "FlextLdapSearchService",
    "FlextLdapUserService",
    # Application services (consolidated - no more wrapper service)
    "FlextLdapConnectionApplicationService",
    "FlextLdapGroupService",
    "FlextLdapOperationService",
    "FlextLdapUserApplicationService",
]

# Note: FlextLdapService wrapper eliminated per user requirements to reduce modules
# Use specialized services directly or the unified FlextLdapApi from root
