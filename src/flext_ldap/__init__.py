"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

# Clean Architecture modules (new unified structure)
from flext_ldap.api import FlextLdap, FlextLdapAPI
from flext_ldap.entities import FlextLdapEntities
from flext_ldap.value_objects import FlextLdapValueObjects
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.services import FlextLdapServices
from flext_ldap.adapters import FlextLdapAdapters

# Legacy modules (being consolidated - maintain for compatibility)
from flext_ldap.acl import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclModels,
    FlextLdapAclParsers,
)
from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig
from flext_ldap.connection import FlextLdapConnection
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.operations import FlextLdapOperations
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.search import FlextLdapSearch
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
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations
from flext_ldap.version import VERSION, FlextLdapVersion

PROJECT_VERSION: Final[FlextLdapVersion] = VERSION

__version__: str = VERSION.version
__version_info__: tuple[int | str, ...] = VERSION.version_info

__all__ = [
    # Clean Architecture modules
    "FlextLdap",
    "FlextLdapAPI",
    "FlextLdapEntities",
    "FlextLdapValueObjects",
    "FlextLdapDomain",
    "FlextLdapServices",
    "FlextLdapAdapters",

    # Version info
    "PROJECT_VERSION",
    "VERSION",
    "ActiveDirectoryOperations",
    "BaseServerOperations",
    "FlextLdapAclConstants",
    "FlextLdapAclConverters",
    "FlextLdapAclManager",
    "FlextLdapAclModels",
    "FlextLdapAclParsers",
    "FlextLdapAuthentication",
    "FlextLdapClient",
    "FlextLdapConfig",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapExceptions",
    "FlextLdapModels",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapQuirksAdapter",
    "FlextLdapSchema",
    "FlextLdapSearch",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
    "FlextLdapVersion",
    "GenericServerOperations",
    "OpenLDAP1Operations",
    "OpenLDAP2Operations",
    "OracleOIDOperations",
    "OracleOUDOperations",
    "ServerOperationsFactory",
    "__version__",
    "__version_info__",
]
