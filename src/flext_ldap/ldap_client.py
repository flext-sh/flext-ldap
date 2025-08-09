"""LDAP Client - Compatibility Facade.

⚠️  DEPRECATED MODULE - Compatibility facade for migration

    MIGRATE TO: flext_ldap.infrastructure.ldap_client module
    REASON: SOLID refactoring - Clean Architecture implementation

    NEW SOLID ARCHITECTURE:
    - LdapConnectionService: Connection management only (SRP)
    - LdapSearchService: Search operations only (SRP)
    - LdapWriteService: Write operations only (SRP)
    - FlextLdapClient: Composite client (DIP)

    OLD: from flext_ldap.ldap_client import FlextLdapClient
    NEW: from flext_ldap.infrastructure.ldap_client import FlextLdapClient

This module provides backward compatibility during the SOLID refactoring transition.
All functionality has been migrated to the new SOLID-compliant architecture in infrastructure/ldap_client.py.

The new architecture follows SOLID principles:
- Single Responsibility: Each service has one clear purpose
- Open/Closed: Extensible through composition, not modification
- Liskov Substitution: Perfect substitutability of implementations
- Interface Segregation: Focused protocols, no fat interfaces
- Dependency Inversion: High-level modules depend on abstractions

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_core import FlextContainer

# Import the new SOLID implementation
from flext_ldap.infrastructure.ldap_client import (
    FlextLdapClient,
    FlextLdapSimpleClient as _FlextLdapSimpleClient,
    LdapConnectionService,
    LdapSearchService,
    LdapWriteService,
    create_ldap_client,
)

# Issue deprecation warning
warnings.warn(
    "🚨 DEPRECATED MODULE: ldap_client.py is deprecated.\n"
    "✅ MIGRATE TO: flext_ldap.infrastructure.ldap_client module\n"
    "🏗️ NEW ARCHITECTURE: SOLID-compliant services with clear separation\n"
    "📖 Migration guide available in module documentation\n"
    "⏰ This compatibility layer will be removed in v2.0.0",
    DeprecationWarning,
    stacklevel=2,
)


class FlextLdapSimpleClient(_FlextLdapSimpleClient):
    """Compatibility facade for FlextLdapSimpleClient.

    ⚠️  DEPRECATED: Use FlextLdapClient from infrastructure.ldap_client module instead.

    This class provides backward compatibility for existing code that uses
    FlextLdapSimpleClient. All functionality has been migrated to the new
    SOLID-compliant architecture.

    Migration Path:
        OLD: FlextLdapSimpleClient() from flext_ldap.ldap_client
        NEW: FlextLdapClient() from flext_ldap.infrastructure.ldap_client

    The new client provides the same interface but with better:
        - Testability (protocol-based design)
        - Maintainability (single responsibility services)
        - Extensibility (composition over inheritance)
        - Type safety (strict protocol contracts)
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize with backward compatibility warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapSimpleClient is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapClient from flext_ldap.infrastructure.ldap_client\n"
            "🏗️ BENEFITS: SOLID principles, better testability, cleaner architecture\n"
            "📖 Same interface, improved implementation\n"
            "⏰ Will be removed in v2.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(container)


# Backward compatibility exports
__all__ = [
    "FlextLdapClient",  # Re-export new implementation
    "FlextLdapSimpleClient",  # Deprecated compatibility class
    "LdapConnectionService",  # Re-export service for advanced usage
    "LdapSearchService",  # Re-export service for advanced usage
    "LdapWriteService",  # Re-export service for advanced usage
    "create_ldap_client",  # Re-export factory function
]
