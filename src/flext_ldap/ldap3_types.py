"""Type definitions for ldap3 to provide proper type safety.

This module provides proper type definitions for ldap3 Connection methods
that are not properly typed in the official types-ldap3 package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from ldap3 import Connection as _Connection

# Export Connection for use in other modules
Connection = _Connection

__all__ = ["Connection"]
