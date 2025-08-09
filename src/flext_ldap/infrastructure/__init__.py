"""LDAP Infrastructure Layer - External System Integration.

Infrastructure implementations following Clean Architecture patterns.
Handles external LDAP systems, connection management, and technical concerns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.infrastructure.ldap_client import FlextLdapClient

__all__ = [
    "FlextLdapClient",
]
