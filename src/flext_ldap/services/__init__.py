"""FLEXT-LDAP Services - Organized service layer.

This module contains all service classes for FLEXT-LDAP operations, organized
by functional domain. Services provide high-level, reusable business logic
for LDAP operations using the FlextService pattern from flext-core.

Services in this module:
- FlextLdapUpsertService: Intelligent entry creation/update operations
- DomainServices: Domain-specific business logic and specifications

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.services.domain_service import DomainServices
from flext_ldap.services.upsert_service import FlextLdapUpsertService

__all__ = [
    "DomainServices",
    "FlextLdapUpsertService",
]
