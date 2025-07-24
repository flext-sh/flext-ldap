"""Adapters for FLEXT LDAP - Implements core domain interfaces.

This module provides concrete implementations of flext-core interfaces
using FLEXT LDAP infrastructure.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.adapters.directory_adapter import FlextLdapDirectoryAdapter

__all__ = [
    "FlextLdapDirectoryAdapter",
]
