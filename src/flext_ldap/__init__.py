"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

OPTIMIZED: Reduced from 49 exports to 13 core facade classes for cleaner API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

# Core facade - MAIN ENTRY POINT for flext-ldap
from flext_ldap.api import FlextLdap, FlextLdapAPI

# Core supporting classes - essential for domain functionality
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations

# Consolidated namespace classes - domain organization
from flext_ldap.handlers import FlextLdapHandlers
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.services import FlextLdapServices

# BACKWARD COMPATIBILITY ALIASES - Maintain existing API
# These imports maintain backward compatibility while encouraging use of consolidated classes
from flext_ldap.repositories import (
    LdapRepository,
    UserRepository,
    GroupRepository,
    EntryRepository,
)
from flext_ldap.handlers import (
    LdapCommandHandler,
    LdapQueryHandler,
    CreateUserCommandHandler,
    UpdateUserCommandHandler,
    DeleteUserCommandHandler,
    GetUserQueryHandler,
    ListUsersQueryHandler,
    GetGroupQueryHandler,
    LdapHandlerRegistry,
)
from flext_ldap.servers import (
    ActiveDirectoryOperations,
    BaseServerOperations,
    GenericServerOperations,
    OpenLDAP1Operations,
    OpenLDAP2Operations,
    OracleOIDOperations,
    OracleOUDOperations,
    ServerOperationsFactory,
)

# Additional backward compatibility imports
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.search import FlextLdapSearch
from flext_ldap.searcher import FlextLdapSearcher
from flext_ldap.connection import FlextLdapConnection
from flext_ldap.connection_manager import FlextLdapConnectionManager
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.operations import FlextLdapOperations
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.authenticator import FlextLdapAuthenticator
from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.entities import FlextLdapEntities
from flext_ldap.value_objects import FlextLdapValueObjects
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.adapters import FlextLdapAdapters

# Version information
from flext_ldap.version import VERSION, FlextLdapVersion

PROJECT_VERSION: Final[FlextLdapVersion] = VERSION

__version__: str = VERSION.version
__version_info__: tuple[int | str, ...] = VERSION.version_info

__all__ = [
    # Core facade - PRIMARY API
    "FlextLdap",
    "FlextLdapAPI",
    # Core supporting classes
    "FlextLdapClient",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapExceptions",
    "FlextLdapModels",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
    # Consolidated namespace classes
    "FlextLdapHandlers",
    "FlextLdapRepositories",
    "FlextLdapServices",
    # BACKWARD COMPATIBILITY - Legacy individual classes
    "LdapRepository",
    "UserRepository",
    "GroupRepository",
    "EntryRepository",
    "LdapCommandHandler",
    "LdapQueryHandler",
    "CreateUserCommandHandler",
    "UpdateUserCommandHandler",
    "DeleteUserCommandHandler",
    "GetUserQueryHandler",
    "ListUsersQueryHandler",
    "GetGroupQueryHandler",
    "LdapHandlerRegistry",
    "ActiveDirectoryOperations",
    "BaseServerOperations",
    "GenericServerOperations",
    "OpenLDAP1Operations",
    "OpenLDAP2Operations",
    "OracleOIDOperations",
    "OracleOUDOperations",
    "ServerOperationsFactory",
    # Version information
    "PROJECT_VERSION",
    "VERSION",
    "FlextLdapVersion",
    "__version__",
    "__version_info__",
    "FlextLdapSchema",
    "FlextLdapSearch",
    "FlextLdapSearcher",
    "FlextLdapConnection",
    "FlextLdapConnectionManager",
    "FlextLdapEntryAdapter",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapQuirksAdapter",
    "FlextLdapAuthenticator",
    "FlextLdapAuthentication",
    "FlextLdapEntities",
    "FlextLdapValueObjects",
    "FlextLdapDomain",
    "FlextLdapAdapters",
]
