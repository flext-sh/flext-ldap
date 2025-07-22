"""FLEXT LDAP - Enterprise LDAP Operations Library.

🎯 SIMPLE IMPORTS - Use these direct imports for ALL new code:

✅ SIMPLE WAY (RECOMMENDED):
from flext_ldap import LDAPUser, LDAPGroup, LDAPEntry, DistinguishedName

❌ COMPLEX WAY (DEPRECATED):
from flext_ldap.domain.entities import LDAPUser, LDAPGroup
from flext_ldap.domain.values import DistinguishedName, LDAPFilter

🚀 USAGE EXAMPLES:
```python
# Easy imports - everything you need from the root
from flext_ldap import LDAPUser, LDAPGroup, LDAPEntry, DistinguishedName

# Work with users and groups
user = LDAPUser(dn="cn=john.doe,ou=users,dc=example,dc=com", uid="john.doe")
group = LDAPGroup(dn="cn=developers,ou=groups,dc=example,dc=com", cn="developers")
```

🏗️ INTERNAL STRUCTURE:
This module follows Clean Architecture internally but exposes a simple public API.
All complex paths still work but show deprecation warnings pointing to simple imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

# Import FlextDeprecationWarning from flext-core for consistency - NO FALLBACKS
from flext_core import FlextDeprecationWarning

if TYPE_CHECKING:
    from flext_core.domain.shared_types import ServiceResult
# ═══════════════════════════════════════════════════════════════════════════════
# 🎯 SIMPLIFIED PUBLIC API - Use these imports for ALL new code
# ═══════════════════════════════════════════════════════════════════════════════

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🏢 CORE ENTITIES - Simple direct imports                                   │
# └─────────────────────────────────────────────────────────────────────────────┘

# Import entities directly to root level for simple access
# Import client implementation
from flext_ldap.client import LDAPClient

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🏗️ AGGREGATES & EVENTS - Advanced domain concepts                         │
# └─────────────────────────────────────────────────────────────────────────────┘
# Import real domain implementations for aggregates and events
from flext_ldap.domain.aggregates import DirectoryAggregate, LDAPDirectory
from flext_ldap.domain.entities import LDAPEntry, LDAPGroup, LDAPUser
from flext_ldap.domain.events import (
    LDAPConnectionEstablished,
    LDAPEntryCreated,
    LDAPEntryModified,
)

# Import protocols and interfaces from real infrastructure
from flext_ldap.domain.interfaces import (
    LDAPConnectionManager,
    LDAPDirectoryRepository,
    LDAPGroupRepository,
    LDAPUserRepository,
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 💎 VALUE OBJECTS & INTERFACES - Direct access                            │
# └─────────────────────────────────────────────────────────────────────────────┘
# Import value objects from real domain implementations
from flext_ldap.domain.values import (
    DistinguishedName,
    LDAPAttributes,
    LDAPFilter,
    LDAPScope,
    LDAPUri,
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🚨 DEPRECATION WARNINGS - Clear migration guidance                        │
# └─────────────────────────────────────────────────────────────────────────────┘


def _deprecation_warning(
    old_path: str, new_import: str, removal_version: str = "1.0.0",
) -> None:
    """Issue comprehensive deprecation warning with clear migration path."""
    warnings.warn(
        f"\\n\\n🚨 DEPRECATED IMPORT PATH:\\n"
        f"Importing from '{old_path}' is deprecated.\\n\\n"
        f"🎯 NEW SIMPLE PATH:\\n"
        f"Use 'from flext_ldap import {new_import}' instead.\\n\\n"
        f"🔄 MIGRATION GUIDE:\\n"
        f"This import will be removed in version {removal_version}.\\n"
        f"Update your imports to use the simplified root-level imports.\\n\\n"
        f"📚 For details, see: https://docs.flext.dev/migration/ldap\\n",
        category=FlextDeprecationWarning,
        stacklevel=3,
    )


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 📦 DYNAMIC IMPORT HANDLER - Legacy path resolution                        │
# └─────────────────────────────────────────────────────────────────────────────┘


def __getattr__(name: str) -> Any:
    """Handle legacy imports with automatic deprecation warnings and migration guidance."""
    # Legacy import mapping with migration paths
    legacy_mapping = {
        # Application services
        "LDAPService": ("application.services.ldap_service", "LDAPService"),
        "LDAPDirectoryService": (
            "application.services.directory_service",
            "LDAPDirectoryService",
        ),
        "LDAPAuthenticationService": (
            "application.services.auth_service",
            "LDAPAuthenticationService",
        ),
        # Infrastructure components
        "LDAPClient": ("infrastructure.client.ldap_client", "LDAPClient"),
        "LDAPConnectionPool": ("infrastructure.connection.pool", "LDAPConnectionPool"),
        # Configuration and utilities
        "LDAPConfig": ("configuration.ldap_config", "LDAPConfig"),
        "LDAPValidator": ("infrastructure.validation.validator", "LDAPValidator"),
        # Specifications
        "LDAPUserSpecification": ("domain.specifications", "LDAPUserSpecification"),
        "LDAPGroupSpecification": ("domain.specifications", "LDAPGroupSpecification"),
        # Legacy aliases
        "LDAPSchemaValidator": ("domain.interfaces", "LDAPSchemaValidator"),
    }

    if name in legacy_mapping:
        old_module, new_import = legacy_mapping[name]

        _deprecation_warning(f"flext_ldap.{old_module}.{name}", new_import)

        # NO FALLBACKS - SEMPRE usar implementações originais conforme instrução
        # Import from legacy location directly without fallback
        module = __import__(f"flext_ldap.{old_module}", fromlist=[name])
        return getattr(module, name)

    # If completely unknown attribute
    msg = (
        f"\\n❌ module 'flext_ldap' has no attribute '{name}'\\n"
        f"✅ Available imports: {', '.join(sorted(__all__))}\\n"
        f"📖 See: https://docs.flext.dev/flext-ldap/api\\n"
    )
    raise AttributeError(
        msg,
    )


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 📋 SIMPLIFIED PUBLIC API - Direct imports without complex paths           │
# └─────────────────────────────────────────────────────────────────────────────┘


__all__ = [
    # Advanced Domain Concepts (aggregates & events)
    "DirectoryAggregate",  # from flext_ldap import DirectoryAggregate
    # Value Objects (domain types)
    "DistinguishedName",  # from flext_ldap import DistinguishedName
    "LDAPAttributes",  # from flext_ldap import LDAPAttributes
    "LDAPClient",  # from flext_ldap import LDAPClient
    "LDAPConnectionEstablished",  # from flext_ldap import LDAPConnectionEstablished
    "LDAPConnectionManager",  # from flext_ldap import LDAPConnectionManager
    "LDAPDirectory",  # from flext_ldap import LDAPDirectory
    "LDAPDirectoryRepository",  # from flext_ldap import LDAPDirectoryRepository
    # ═══════════════════════════════════════════════════════════════════════════════
    # ✅ RECOMMENDED - SIMPLE DIRECT IMPORTS
    # ═══════════════════════════════════════════════════════════════════════════════
    # Core Domain Entities (data models)
    "LDAPEntry",  # from flext_ldap import LDAPEntry
    "LDAPEntryCreated",  # from flext_ldap import LDAPEntryCreated
    "LDAPEntryModified",  # from flext_ldap import LDAPEntryModified
    "LDAPFilter",  # from flext_ldap import LDAPFilter
    "LDAPGroup",  # from flext_ldap import LDAPGroup
    "LDAPGroupRepository",  # from flext_ldap import LDAPGroupRepository
    "LDAPScope",  # from flext_ldap import LDAPScope
    "LDAPUri",  # from flext_ldap import LDAPUri
    "LDAPUser",  # from flext_ldap import LDAPUser
    "LDAPUserRepository",  # from flext_ldap import LDAPUserRepository
]

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 📋 MODULE METADATA AND UTILITIES                                          │
# └─────────────────────────────────────────────────────────────────────────────┘

__version__ = "0.7.0"
__architecture__ = "Clean Architecture + DDD"
__migration_guide__ = "https://docs.flext.dev/migration/ldap"

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🛠️ MIGRATION UTILITIES                                                    │
# └─────────────────────────────────────────────────────────────────────────────┘


def get_migration_path(deprecated_import: str) -> str:
    """Get the migration path for a deprecated import."""
    migrations = {
        "flext_ldap.domain.entities.LDAPUser": "from flext_ldap import LDAPUser",
        "flext_ldap.domain.entities.LDAPGroup": "from flext_ldap import LDAPGroup",
        "flext_ldap.domain.entities.LDAPEntry": "from flext_ldap import LDAPEntry",
        "flext_ldap.domain.values.DistinguishedName": "from flext_ldap import DistinguishedName",
        "flext_ldap.domain.values.LDAPFilter": "from flext_ldap import LDAPFilter",
        "flext_ldap.domain.interfaces.LDAPConnectionManager": "from flext_ldap import LDAPConnectionManager",
        "flext_ldap.domain.interfaces.LDAPDirectoryRepository": "from flext_ldap import LDAPDirectoryRepository",
    }
    return migrations.get(
        deprecated_import, f"from flext_ldap import {deprecated_import.split('.')[-1]}",
    )


def show_available_imports() -> None:
    """Show all available public imports."""
    categories = [
        ("Domain Entities", ["LDAPEntry", "LDAPUser", "LDAPGroup"]),
        (
            "Value Objects",
            [
                "DistinguishedName",
                "LDAPAttributes",
                "LDAPFilter",
                "LDAPScope",
                "LDAPUri",
            ],
        ),
        (
            "Protocols",
            [
                "LDAPConnectionManager",
                "LDAPDirectoryRepository",
                "LDAPUserRepository",
                "LDAPGroupRepository",
            ],
        ),
        (
            "Aggregates & Events",
            [
                "DirectoryAggregate",
                "LDAPDirectory",
                "LDAPConnectionEstablished",
                "LDAPEntryCreated",
                "LDAPEntryModified",
            ],
        ),
    ]

    # Print categories and items (dummy implementation)
    for _category, _items in categories:
        pass
