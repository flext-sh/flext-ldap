"""FLEXT-LDAP - LDAP Client Library.

LDAP client library with RFC compliance and server-specific quirks
for the FLEXT ecosystem. Reuses flext-ldif for Entry models and parsing.

Single Entry Point Architecture:
    This module enforces a single entry point pattern. ALL LDAP operations must
    go through the FlextLdap class. Internal modules (adapters, services) are
    NOT part of the public API and should not be imported directly by consumers.

    Correct usage:
        from flext_ldap import FlextLdap
        ldap = FlextLdap()
        result = ldap.search(options)

    Incorrect usage (bypasses single entry point):
        from flext_ldap.services.connection import FlextLdapConnection  # ❌ WRONG
        from flext_ldap.adapters import Ldap3Adapter  # ❌ WRONG

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes

__email__ = "dev@flext.com"

__all__ = [
    "FlextLdap",  # ✅ Facade (single entry point)
    "FlextLdapConfig",  # ✅ Configuration
    "FlextLdapConstants",  # ✅ Constants
    "FlextLdapModels",  # ✅ Domain models
    "FlextLdapTypes",  # ✅ Type definitions
]
