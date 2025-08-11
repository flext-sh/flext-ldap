"""FLEXT-LDAP API - Compatibility Facade.

⚠️  DEPRECATED MODULE - Compatibility facade for migration

    MIGRATE TO: flext_ldap.api module
    REASON: SOLID refactoring - consolidated to single canonical API

    NEW SOLID ARCHITECTURE:
    - Single source of truth: api.py with modern FlextLdapClient
    - Full SOLID compliance: SRP, OCP, LSP, ISP, DIP
    - Complete API compatibility maintained via this facade

    OLD: from flext_ldap.ldap_api import FlextLdapApi, get_ldap_api
    NEW: from flext_ldap.api import FlextLdapApi, get_ldap_api

This module provides backward compatibility during the SOLID refactoring transition.
All functionality has been consolidated into the canonical api.py with modern SOLID architecture.

The new implementation uses FlextLdapClient (SOLID-compliant) instead of the legacy
FlextLdapClient, providing better separation of concerns and dependency injection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, cast

# Import the canonical SOLID implementation from api.py
from flext_ldap.api import FlextLdapApi as _FlextLdapApi, get_ldap_api as _get_ldap_api

if TYPE_CHECKING:
    from flext_ldap.config import FlextLdapSettings

# Issue deprecation warning
warnings.warn(
    "🚨 DEPRECATED MODULE: ldap_api.py is deprecated.\n"
    "✅ USE INSTEAD: flext_ldap.api module (SOLID-compliant implementation)\n"
    "\n"
    "MIGRATION GUIDE:\n"
    "  OLD: from flext_ldap.ldap_api import FlextLdapApi, get_ldap_api\n"
    "  NEW: from flext_ldap.api import FlextLdapApi, get_ldap_api\n"
    "\n"
    "BENEFITS OF NEW API:\n"
    "  - SOLID principles compliance (SRP, OCP, LSP, ISP, DIP)\n"
    "  - Modern FlextLdapClient architecture\n"
    "  - Better separation of concerns\n"
    "  - Enhanced dependency injection\n"
    "  - Single canonical API source\n",
    DeprecationWarning,
    stacklevel=2,
)


class FlextLdapApi(_FlextLdapApi):
    """Compatibility facade for FlextLdapApi.

    ⚠️  DEPRECATED: Use FlextLdapApi from flext_ldap.api module instead.

    This class provides backward compatibility while the codebase migrates to the new
    SOLID-compliant API architecture. All functionality is provided by the modern
    implementation in api.py.

    Migration:
        OLD: FlextLdapApi() from flext_ldap.ldap_api
        NEW: FlextLdapApi() from flext_ldap.api
    """

    def __init__(self, config: FlextLdapSettings | None = None) -> None:
        """Initialize compatibility facade with deprecation warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapApi from ldap_api.py is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapApi from flext_ldap.api\n"
            "\n"
            "Benefits: SOLID compliance, modern architecture, single source of truth",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(config)


def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    """Get LDAP API instance - Compatibility facade.

    ⚠️  DEPRECATED: Use get_ldap_api from flext_ldap.api module instead.

    Args:
        config: Optional LDAP configuration

    Returns:
        FlextLdapApi: LDAP API instance (via compatibility facade)

    Migration:
        OLD: from flext_ldap.ldap_api import get_ldap_api
        NEW: from flext_ldap.api import get_ldap_api

    """
    warnings.warn(
        "🚨 DEPRECATED FUNCTION: get_ldap_api from ldap_api.py is deprecated.\n"
        "✅ USE INSTEAD: get_ldap_api from flext_ldap.api\n"
        "\n"
        "Same interface, modern SOLID architecture",
        DeprecationWarning,
        stacklevel=2,
    )
    # Use the modern canonical implementation directly - cast for compatibility
    return cast("FlextLdapApi", _get_ldap_api(config))


# Maintain backward compatibility exports
__all__ = [
    "FlextLdapApi",
    "get_ldap_api",
]
