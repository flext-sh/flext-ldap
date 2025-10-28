"""Backward compatibility module for FLEXT-LDAP UPSERT service.

This module provides backward compatibility for code importing FlextLdapUpsertService
from its original location (src/flext_ldap/upsert_service.py).

DEPRECATED: Import from flext_ldap.services instead:
    from flext_ldap.services import FlextLdapUpsertService

This module will remain for backward compatibility with existing code.
New code should import from flext_ldap.services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Re-export from new location for backward compatibility
from flext_ldap.services.upsert_service import FlextLdapUpsertService

__all__ = [
    "FlextLdapUpsertService",
]
