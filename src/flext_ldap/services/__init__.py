"""FLEXT-LDAP Services - Organized service layer.

This module contains all service classes for FLEXT-LDAP operations, organized
by functional domain. Services provide high-level, reusable business logic
for LDAP operations using the FlextService pattern from flext-core.

Core Services:
- FlextLdapServersService: LDAP server type operations and capabilities
- FlextLdapAclService: Access Control List operations
- FlextLdapUpsertService: Intelligent entry creation/update operations
- DomainServices: Domain-specific business logic and specifications
- FlextLdapSchema: Schema discovery and operations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.services.acl import FlextLdapAclService
from flext_ldap.services.domain import DomainServices
from flext_ldap.services.repository import LdapEntryRepository, RepositoryBase
from flext_ldap.services.schema import FlextLdapSchema
from flext_ldap.services.servers import FlextLdapServersService
from flext_ldap.services.upsert import FlextLdapUpsertService

__all__ = [
    "DomainServices",
    "FlextLdapAclService",
    "FlextLdapSchema",
    "FlextLdapServersService",
    "FlextLdapUpsertService",
    "LdapEntryRepository",
    "RepositoryBase",
]
