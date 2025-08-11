"""FLEXT-LDAP Service Layer - CLEAN ARCHITECTURE CONSOLIDATION.

Consolidates service layer functionality eliminating wrapper duplication.
Direct imports from application layer following Clean Architecture patterns.

REFACTORED: Eliminates unnecessary wrapper classes and delegation patterns.
All services now import directly from application layer.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings

# CLEAN CONSOLIDATION: Direct imports from application layer
from flext_ldap.abstracts import FlextLdapService

# BACKWARD COMPATIBILITY: Legacy aliases with deprecation warnings


def __getattr__(name: str) -> object:
    """Provide backward compatibility for legacy service classes."""
    legacy_services = {
        "FlextLdapUserApplicationService": FlextLdapService,
        "FlextLdapUserService": FlextLdapService,
        "FlextLdapGroupService": FlextLdapService,
        "FlextLdapOperationService": FlextLdapService,
        "FlextLdapConnectionApplicationService": FlextLdapService,
        "FlextLdapConnectionService": FlextLdapService,
    }

    if name in legacy_services:
        warnings.warn(
            f"🚨 DEPRECATED SERVICE: {name} is deprecated.\n"
            f"✅ MODERN SOLUTION: Use FlextLdapService from application layer\n"
            f"💡 Import: from flext_ldap.abstracts import FlextLdapService\n"
            f"🏗️ This wrapper layer adds no value and will be removed in v1.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        return legacy_services[name]

    msg = f"module 'flext_ldap.services' has no attribute '{name}'"
    raise AttributeError(msg)
