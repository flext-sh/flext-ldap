"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend FlextUtilities from flext-core.
All generic utilities are inherited from FlextUtilities for convenience.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextUtilities

# ═══════════════════════════════════════════════════════════════════
# FLEXT_LDAP UTILITIES - Extends FlextUtilities
# ═══════════════════════════════════════════════════════════════════
# All generic utilities inherited from flext-core.
# Only LDAP-specific utilities should be added here if needed.


class FlextLdapUtilities(FlextUtilities):
    """FlextLdap utilities - extends FlextUtilities.

    ARCHITECTURE:
    ────────────
    - Extends FlextUtilities methods
    - All generic utilities (Enum, Collection, Args, Model) inherited from flext-core
    - Only LDAP-specific utilities should be added here

    USAGE:
    ──────
    Use FlextLdapUtilities exactly like FlextUtilities
        from flext_ldap.utilities import FlextLdapUtilities as u

        # Generic utilities (inherited)
        result = u.filter(items, predicate=lambda x: x > 0)
        normalized = u.normalize("Hello", case="lower")
        found = u.find(items, predicate=lambda x: x == target)
        processed = u.process(items, processor=lambda x: x * 2)

        # Enum utilities
        result = u.Enum.parse(Status, "active")
        if u.Enum.is_member(Status, value):
            ...

        # Args utilities
        @u.Args.validated_with_result
        def method(...) -> r[T]:
            ...

        # Model utilities
        result = u.Model.from_dict(Model, data)
        result = u.Model.merge_defaults(Model, defaults, overrides)

        # Collection utilities
        validator = u.Collection.coerce_list_validator(Status)
    """

    # All methods inherited from FlextUtilities


# Convenience alias for common usage pattern
u = FlextLdapUtilities
