"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_ldap.acl import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclModels,
    FlextLdapAclParsers,
)
from flext_ldap.api import FlextLdap, FlextLdapAPI
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.schema import FlextLdapSchema
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
    "FlextLdap",
    "FlextLdapAPI",
    "FlextLdapAclConstants",
    "FlextLdapAclConverters",
    "FlextLdapAclManager",
    "FlextLdapAclModels",
    "FlextLdapAclParsers",
    "FlextLdapClient",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
    "FlextLdapExceptions",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapQuirksAdapter",
    "FlextLdapSchema",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
    "BaseServerOperations",
    "ServerOperationsFactory",
    "OpenLDAP1Operations",
    "OpenLDAP2Operations",
    "OracleOIDOperations",
    "OracleOUDOperations",
    "ActiveDirectoryOperations",
    "GenericServerOperations",
    "__version__",
    "__version_info__",
    "FlextLdapVersion",
    "VERSION",
    "PROJECT_VERSION",
]
