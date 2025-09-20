"""LDAP exceptions module - Direct FlextExceptions usage (ZERO aliases).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Direct imports from FlextExceptions - NO wrapper classes or aliases
from flext_core import FlextExceptions

# Export FlextExceptions directly - ELIMINATES wrapper pattern
__all__ = [
    "FlextExceptions",
]
