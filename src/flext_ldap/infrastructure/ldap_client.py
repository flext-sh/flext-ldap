"""LDAP Infrastructure Client - Clean Architecture Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Refactored from 1,282 lines to minimal infrastructure client.
Eliminates architectural violation of mixing domain logic with infrastructure.
Domain operations moved to application services.
"""

from __future__ import annotations

# Re-export the clean implementation
from flext_ldap.infrastructure.ldap_simple_client import (
    FlextLdapSimpleClient as FlextLdapInfrastructureClient,
)

__all__ = ["FlextLdapInfrastructureClient"]
