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
from flext_ldap.clients import FlextLDAPClient
from flext_ldap.config import FlextLDAPConfig
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.models import FlextLDAPModels
from flext_ldap.servers import FlextLDAPServers
from flext_ldap.validations import FlextLDAPValidations
from flext_ldap.exceptions import FlextLDAPExceptions

# Version information
from flext_ldap.version import VERSION, FlextLDAPVersion

PROJECT_VERSION: Final[FlextLDAPVersion] = VERSION

__version__: str = VERSION.version
__version_info__: tuple[int | str, ...] = VERSION.version_info

__all__ = [
    # Core facade - PRIMARY API
    "FlextLDAP",
    # Core domain classes - REQUIRED for tests
    "FlextLDAPClient",
    "FlextLDAPConfig",
    "FlextLDAPConstants",
    "FlextLDAPModels",
    "FlextLDAPServers",
    "FlextLDAPValidations",
    "FlextLDAPExceptions",
    # Version information
    "PROJECT_VERSION",
    "VERSION",
    "FlextLDAPVersion",
    "__version__",
    "__version_info__",
]
