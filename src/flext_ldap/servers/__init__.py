"""Server-specific LDAP operations.

This module provides server-specific implementations for different LDAP servers
while maintaining a generic interface that works with any LDAP server.

All operations are generic and work with any LDAP server by leveraging
flext-ldif's quirks system for server-specific handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.servers.factory import FlextLdapServersFactory
from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations

__all__ = [
    "FlextLdapServersBaseOperations",
    "FlextLdapServersFactory",
    "FlextLdapServersGenericOperations",
]
