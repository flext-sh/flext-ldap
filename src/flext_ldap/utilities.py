"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend or compose with
FlextUtilities from flext-core. All generic utilities (Enum, Collection, Args, Model)
are delegated to FlextUtilities to avoid duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextUtilities

# ═══════════════════════════════════════════════════════════════════
# FLEXT_LDAP UTILITIES - Pure delegation to FlextUtilities
# ═══════════════════════════════════════════════════════════════════
# All generic utilities delegate to flext-core to avoid duplication.
# Only LDAP-specific utilities should be added here if needed.


class FlextLdapUtilities:
    """FlextLdap utilities - delegates to FlextUtilities from flext-core.

    ARCHITECTURE:
    ────────────
    - Pure delegation to FlextUtilities (no duplication)
    - All generic utilities (Enum, Collection, Args, Model) use flext-core
    - Only LDAP-specific utilities should be added here

    USAGE:
    ──────
    Use FlextLdapUtilities exactly like FlextUtilities:
        from flext_ldap.utilities import FlextLdapUtilities

        # Enum utilities
        result = FlextLdapUtilities.Enum.parse(Status, "active")
        if FlextLdapUtilities.Enum.is_member(Status, value):
            ...

        # Args utilities
        @FlextLdapUtilities.Args.validated_with_result
        def method(...) -> FlextResult[T]:
            ...

        # Model utilities
        result = FlextLdapUtilities.Model.from_dict(Model, data)
        result = FlextLdapUtilities.Model.merge_defaults(Model, defaults, overrides)

        # Collection utilities
        validator = FlextLdapUtilities.Collection.coerce_list_validator(Status)
    """

    # Pure delegation to FlextUtilities - no wrapper logic
    Enum = FlextUtilities.Enum
    Collection = FlextUtilities.Collection
    Args = FlextUtilities.Args
    Model = FlextUtilities.Model
