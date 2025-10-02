"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __branch__,
    __build__,
    __commit__,
    __copyright__,
    __description__,
    __email__,
    __license__,
    __maintainer__,
    __maintainer_email__,
    __project__,
    __version__,
    __version_info__,
    __version_tuple__,
)
from flext_ldap.acl import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclModels,
    FlextLdapAclParsers,
)

# Main domain API - primary entry point
from flext_ldap.api import FlextLdap, FlextLdapAPI

# Core domain components
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig

# Entry adapter and quirks integration (NEW - Universal LDAP support)
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter

# Server-specific operations (NEW - Universal server support)
from flext_ldap.servers import (
    BaseServerOperations,
    ServerOperationsFactory,
    OpenLDAP1Operations,
    OpenLDAP2Operations,
    OracleOIDOperations,
    OracleOUDOperations,
    ActiveDirectoryOperations,
    GenericServerOperations,
)

# Constants and models
from flext_ldap.constants import FlextLdapConstants

# Advanced service components
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels

# Type system and protocols
from flext_ldap.protocols import FlextLdapProtocols

# Generic universal compatibility components
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations

# Advanced domain services

# Main domain exports following FLEXT standards
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
    "FlextLdapEntryAdapter",  # NEW: Universal entry conversion
    "FlextLdapExceptions",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapQuirksAdapter",  # NEW: Server-specific handling
    "FlextLdapSchema",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
    # Server-specific operations (NEW)
    "BaseServerOperations",
    "ServerOperationsFactory",  # NEW: Factory for server operations
    "OpenLDAP1Operations",
    "OpenLDAP2Operations",
    "OracleOIDOperations",
    "OracleOUDOperations",
    "ActiveDirectoryOperations",
    "GenericServerOperations",
    "__author__",
    "__author_email__",
    "__branch__",
    "__build__",
    "__commit__",
    "__copyright__",
    "__description__",
    "__email__",
    "__license__",
    "__maintainer__",
    "__maintainer_email__",
    "__project__",
    "__version__",
    "__version_info__",
    "__version_tuple__",
]
