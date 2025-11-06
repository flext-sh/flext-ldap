"""FLEXT-LDAP - LDAP operations library.

Consolidated LDAP operations in FlextLdap main class following
single-class-per-project pattern.

Single Entry Point Architecture:
    This module enforces a single entry point pattern. ALL LDAP operations must
    go through the FlextLdap class. Internal modules (quirks_integration, servers,
    search, services) are NOT part of the public API and should not be imported
    directly by consumers.

    Correct usage:
        from flext_ldap import FlextLdap
        ldap = FlextLdap(config)
        result = ldap.search(filter)

    Incorrect usage (bypasses single entry point):
        from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration  # ❌ WRONG
        from flext_ldap.servers import FlextLdapServers  # ❌ WRONG

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

from flext_ldap.__version__ import __version__, __version_info__
from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.servers import FlextLdapServers
from flext_ldap.services.clients import FlextLdapClients
from flext_ldap.services.repository import LdapEntryRepository, RepositoryBase
from flext_ldap.services.schema import FlextLdapSchema
from flext_ldap.services.upsert import FlextLdapUpsertService

__all__ = [
    "FlextExceptions",
    "FlextLdap",
    "FlextLdapClients",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapSchema",
    "FlextLdapServers",
    "FlextLdapUpsertService",
    "LdapEntryRepository",
    "RepositoryBase",
    "__version__",
    "__version_info__",
]
