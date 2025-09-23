"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Direct access to exceptions through flext-core
from flext_core import FlextExceptions

# Main domain API - primary entry point
from flext_ldap.api import FlextLdapAPI

# Core domain components
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfigs

# Constants and exceptions (re-exported from their respective modules)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

# Type system and protocols
from flext_ldap.protocols import FlextLdapProtocols

# Domain utilities
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.type_guards import FlextLdapTypeGuards
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

# Rebuild models after all definitions are complete
FlextLdapModels.LdapUser.model_rebuild()
FlextLdapModels.Entry.model_rebuild()
FlextLdapModels.Group.model_rebuild()
FlextLdapModels.SearchRequest.model_rebuild()
FlextLdapModels.SearchResponse.model_rebuild()
FlextLdapModels.CreateUserRequest.model_rebuild()
FlextLdapModels.CreateGroupRequest.model_rebuild()

# Main domain exports following FLEXT standards
__all__ = [
    # Exceptions (from flext-core)
    "FlextExceptions",
    # Primary API - main entry point
    "FlextLdapAPI",
    # Core domain components
    "FlextLdapClient",
    "FlextLdapConfigs",
    "FlextLdapConstants",
    "FlextLdapModels",
    "FlextLdapProtocols",
    # Domain utilities
    "FlextLdapRepositories",
    "FlextLdapTypeGuards",
    # Type system
    "FlextLdapTypes",
    "FlextLdapValidations",
]
