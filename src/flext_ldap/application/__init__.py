"""Application layer for FLEXT-LDAP.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.domain.ports import (
    FlextLdapMigrationService,
    FlextLdapSchemaService,
    FlextLdapSearchService,
    FlextLdapUserService,
)

# Import specialized services from root (services moved to root)
# TEMPORARILY COMMENTED to avoid circular import with services.py
# from flext_ldap.services import (
#     FlextLdapConnectionApplicationService,
#     FlextLdapGroupService,
#     FlextLdapOperationService,
#     FlextLdapUserApplicationService,
# )

__all__ = [
    # Domain ports
    "FlextLdapMigrationService",
    "FlextLdapSchemaService",
    "FlextLdapSearchService",
    "FlextLdapService",  # Main application service
    "FlextLdapUserService",
    # NOTE: Other services moved to root services.py to avoid circular imports
]

# Note: FlextLdapService wrapper eliminated per user requirements to reduce modules
# Use specialized services directly or the unified FlextLdapApi from root
