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

# Lazy imports to avoid circular dependencies during module initialization
# These are imported on-demand rather than at module load time

__all__ = [
    "DomainServices",
    "FlextLdapAclService",
    "FlextLdapSchema",
    "FlextLdapServersService",
    "FlextLdapUpsertService",
    "LdapEntryRepository",
    "RepositoryBase",
]


def __getattr__(name: str) -> object:
    """Lazy load service classes and repository classes to avoid circular imports."""
    if name == "DomainServices":
        from flext_ldap.services.domain import DomainServices

        return DomainServices
    if name == "FlextLdapAclService":
        from flext_ldap.services.acl import FlextLdapAclService

        return FlextLdapAclService
    if name == "FlextLdapSchema":
        from flext_ldap.services.schema import FlextLdapSchema

        return FlextLdapSchema
    if name == "FlextLdapServersService":
        from flext_ldap.services.servers import FlextLdapServersService

        return FlextLdapServersService
    if name == "FlextLdapUpsertService":
        from flext_ldap.services.upsert import FlextLdapUpsertService

        return FlextLdapUpsertService
    if name == "LdapEntryRepository":
        from flext_ldap.services.repository import LdapEntryRepository

        return LdapEntryRepository
    if name == "RepositoryBase":
        from flext_ldap.services.repository import RepositoryBase

        return RepositoryBase
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
