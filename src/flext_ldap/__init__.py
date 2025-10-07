"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

OPTIMIZED: Reduced from 49 exports to 13 core facade classes for cleaner API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.api import FlextLdap
from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.handlers import FlextLdapHandlers
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.quirks_integration import FlextLdapQuirksIntegration
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.search import FlextLdapSearch
from flext_ldap.servers import FlextLdapServers
from flext_ldap.services import FlextLdapServices
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations

# Use centralized constants - no module-level constants
__version__: str = FlextLdapConstants.Version.get_version()
__version_info__: tuple[int | str, ...] = FlextLdapConstants.Version.get_version_info()

__all__ = [
    "FlextLdap",
    "FlextLdapAuthentication",
    "FlextLdapClients",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapDomain",
    "FlextLdapEntryAdapter",
    "FlextLdapExceptions",
    "FlextLdapHandlers",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapQuirksIntegration",
    "FlextLdapRepositories",
    "FlextLdapSchema",
    "FlextLdapSearch",
    "FlextLdapServers",
    "FlextLdapServices",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
    "__version__",
    "__version_info__",
]
