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
from flext_ldap.api import FlextLDAP

# Core domain classes - REQUIRED for tests and external usage
from flext_ldap.clients import FlextLDAPClients
from flext_ldap.config import FlextLDAPConfig
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.models import FlextLDAPModels
from flext_ldap.servers import FlextLDAPServers
from flext_ldap.validations import FlextLDAPValidations
from flext_ldap.exceptions import FlextLDAPExceptions

# Version information
from flext_ldap.version import VERSION, FlextLDAPVersion

# Use centralized constants - no module-level constants
__version__: str = FlextLDAPConstants.Version.get_version()
__version_info__: tuple[int | str, ...] = FlextLDAPConstants.Version.get_version_info()

__all__ = [
    # Core facade - PRIMARY API
    "FlextLDAP",
    # Core domain classes - REQUIRED for tests
    "FlextLDAPClients",
    "FlextLDAPConfig",
    "FlextLDAPConstants",
    "FlextLDAPModels",
    "FlextLDAPServers",
    "FlextLDAPValidations",
    "FlextLDAPExceptions",
    # Version information
    "VERSION",
    "FlextLDAPVersion",
    "__version__",
    "__version_info__",
]
