"""LDAP exceptions using FlextExceptions - NO DUPLICATION.

Uses FlextExceptions from flext-core directly with simple aliases.
ELIMINATES MASSIVE code duplication following SOURCE OF TRUTH pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import final

from flext_core import FlextExceptions


@final
class FlextLDAPExceptions:
    """LDAP exceptions using FlextExceptions - ELIMINATES MASSIVE DUPLICATION.

    Simple aliases to FlextExceptions following SOURCE OF TRUTH pattern.
    NO custom exception classes - uses flext-core exceptions directly.
    """

    # =========================================================================
    # DIRECT ALIASES TO FlextExceptions - NO DUPLICATION
    # =========================================================================

    # Base exception types from FlextExceptions
    Error = FlextExceptions.BaseError
    OperationError = FlextExceptions.OperationError
    UserError = FlextExceptions.UserError
    ValidationError = FlextExceptions.ValidationError
    ConfigurationError = FlextExceptions.ConfigurationError
    TypeError = FlextExceptions.TypeError

    # LDAP-specific aliases using FlextExceptions patterns
    LdapConnectionError = FlextExceptions.ConnectionError
    AuthenticationError = FlextExceptions.AuthenticationError
    SearchError = FlextExceptions.OperationError
    GroupError = FlextExceptions.OperationError
    LdapTypeError = FlextExceptions.TypeError


__all__ = [
    "FlextLDAPExceptions",
]
