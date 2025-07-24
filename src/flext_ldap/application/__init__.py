"""Application layer for FLEXT-LDAP v0.7.0.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

REFACTORED:
            Using flext-core application patterns - NO duplication.
"""

from __future__ import annotations

from flext_ldap.application.ldap_service import FlextLdapService
from flext_ldap.domain.ports import (
    FlextLdapMigrationService,
    FlextLdapSchemaService,
    FlextLdapSearchService,
    FlextLdapUserService,
)

__all__ = [
    "FlextLdapMigrationService",
    "FlextLdapSchemaService",
    "FlextLdapSearchService",
    "FlextLdapService",
    "FlextLdapUserService",
    # Legacy aliases
    "LDAPService",
]

# Backward compatibility
LDAPService = FlextLdapService
