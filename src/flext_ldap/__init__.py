"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Main domain API - primary entry point
from flext_ldap.api import FlextLdapAPI

# Core domain components
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfigs

# Constants and models
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

# Type system and protocols
from flext_ldap.protocols import FlextLdapProtocols

# Domain utilities
from flext_ldap.repositories import FlextLdapRepositories

# Generic universal compatibility components
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations

# Main domain exports following FLEXT standards
__all__ = [
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
    # Generic universal compatibility components
    "FlextLdapSchema",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
]
