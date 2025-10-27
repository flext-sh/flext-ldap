"""FLEXT-LDAP - LDAP operations library.

Consolidated LDAP operations in FlextLdap main class following
single-class-per-project pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextExceptions

from flext_ldap.__version__ import __version__, __version_info__
from flext_ldap.api import FlextLdap
from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.quirks_integration import FlextLdapQuirksIntegration
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.search import FlextLdapSearch
from flext_ldap.servers import FlextLdapServers
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.upsert_service import FlextLdapUpsertService

__all__ = [
    "FlextExceptions",
    "FlextLdap",
    "FlextLdapAuthentication",
    "FlextLdapClients",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapDomain",
    "FlextLdapEntryAdapter",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapQuirksIntegration",
    "FlextLdapSchema",
    "FlextLdapSearch",
    "FlextLdapServers",
    "FlextLdapTypes",
    "FlextLdapUpsertService",
    "__version__",
    "__version_info__",
]
