"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

OPTIMIZED: Reduced from 49 exports to 13 core facade classes for cleaner API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Core facade - MAIN ENTRY POINT for flext-ldap
from flext_ldap.api import FlextLdap

# Core domain classes - REQUIRED for tests and external usage
from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.servers import FlextLdapServers
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

# Version information
from flext_ldap.version import VERSION, FlextLdapVersion


# Factory function for API access
def get_flext_ldap_api() -> FlextLdap:
    """Get the main FLEXT LDAP API instance.

    Returns:
        FlextLdap: The unified LDAP API instance

    """
    return FlextLdap()


# Use centralized constants - no module-level constants
__version__: str = FlextLdapConstants.Version.get_version()
__version_info__: tuple[int | str, ...] = FlextLdapConstants.Version.get_version_info()

__all__ = [
    # Version information
    "VERSION",
    # Core facade - PRIMARY API
    "FlextLdap",
    # Core domain classes - REQUIRED for tests
    "FlextLdapClients",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapExceptions",
    "FlextLdapModels",
    "FlextLdapSchema",
    "FlextLdapServers",
    "FlextLdapTypes",
    "FlextLdapValidations",
    "FlextLdapVersion",
    "__version__",
    "__version_info__",
    "get_flext_ldap_api",
]
