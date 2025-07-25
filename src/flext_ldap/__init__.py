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
from typing import Any

# Import base services
from flext_ldap.application.base import (
    FlextLdapBaseService,
    FlextLdapConnectionBaseService,
    FlextLdapGroupBaseService,
    FlextLdapOperationBaseService,
    FlextLdapUserBaseService,
)

# Import application services
from flext_ldap.application.services import (
    FlextLdapGroupService,
    FlextLdapUserApplicationService as FlextLdapUserService,
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 💎 VALUE OBJECTS & INTERFACES - Direct access                            │
# └─────────────────────────────────────────────────────────────────────────────┘
# Import value objects from real domain implementations
# ═══════════════════════════════════════════════════════════════════════════════
# 🎯 SIMPLIFIED PUBLIC API - Use these imports for ALL new code
# ═══════════════════════════════════════════════════════════════════════════════
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🏢 CORE ENTITIES - Simple direct imports                                   │
# └─────────────────────────────────────────────────────────────────────────────┘
# Import client implementation with new name
from flext_ldap.client import FlextLdapClient

# Import configuration classes
from flext_ldap.config import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapSettings,
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🏗️ AGGREGATES & EVENTS - Advanced domain concepts                         │
# └─────────────────────────────────────────────────────────────────────────────┘
# Import real domain implementations for aggregates and events with new prefixes
from flext_ldap.domain.aggregates import (
    FlextLdapDirectory,
    FlextLdapDirectoryAggregate,
)
from flext_ldap.domain.entities import (
    FlextLdapConnection,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapOperation,
    FlextLdapUser,
)
from flext_ldap.domain.events import (
    FlextLdapAuthenticationFailed,
    FlextLdapConnectionEstablished,
    FlextLdapConnectionLost,
    FlextLdapEntryCreated,
    FlextLdapEntryDeleted,
    FlextLdapEntryModified,
    FlextLdapGroupMemberAdded,
    FlextLdapGroupMemberRemoved,
    FlextLdapUserAuthenticated,
)

# Import protocols and interfaces from real infrastructure
from flext_ldap.domain.interfaces import (
    FlextLdapConnectionManager,
    FlextLdapDirectoryRepository,
    FlextLdapGroupRepository,
)

# Import domain services and repositories
from flext_ldap.domain.ports import (
    FlextLdapMigrationService,
    FlextLdapSchemaService,
    FlextLdapSearchService,
    FlextLdapUserService as FlextLdapUserPortService,
)
from flext_ldap.domain.repositories import (
    FlextLdapConnectionRepository,
    FlextLdapUserRepository as FlextLdapUserRepositoryImpl,
)

# Import specifications
from flext_ldap.domain.specifications import (
    FlextLdapActiveUserSpecification,
    FlextLdapDistinguishedNameSpecification,
    FlextLdapEntrySpecification,
    FlextLdapFilterSpecification,
    FlextLdapGroupSpecification,
    FlextLdapNonEmptyGroupSpecification,
    FlextLdapUserSpecification,
    FlextLdapValidEntrySpecification,
    FlextLdapValidPasswordSpecification,
)

# Import value objects
from flext_ldap.domain.value_objects import (
    FlextLdapAttribute,
    FlextLdapCreateUserRequest,
)
from flext_ldap.domain.values import (
    DistinguishedName,
    FlextLdapFilterValue,
    LDAPAttributes,
    LDAPFilter,
    LDAPScope,
    LDAPUri,
)

# Import models classes
from flext_ldap.models import (
    FlextLdapFilter,
    FlextLdapScope,
)

# Import simple API
from flext_ldap.simple_api import FlextLdapAPI

# Import API with new name
# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🛠️ HELPER FUNCTIONS - LDAP utilities with proper prefixes                │
# └─────────────────────────────────────────────────────────────────────────────┘
from flext_ldap.utils import (
    flext_ldap_build_dn,
    flext_ldap_build_filter,
    flext_ldap_compare_dns,
    flext_ldap_escape_filter_chars,
    flext_ldap_escape_filter_value,
    flext_ldap_format_generalized_time,
    flext_ldap_format_timestamp,
    flext_ldap_is_valid_url,
    flext_ldap_normalize_attribute_name,
    flext_ldap_normalize_dn,
    flext_ldap_parse_dn,
    flext_ldap_parse_generalized_time,
    flext_ldap_parse_url,
    flext_ldap_split_dn,
    flext_ldap_validate_dn,
)

# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🔄 BACKWARD COMPATIBILITY - Legacy class names                            │
# └─────────────────────────────────────────────────────────────────────────────┘
# Maintain backward compatibility with old names
LDAPClient = FlextLdapClient
LDAPAPI = FlextLdapAPI
LDAPEntry = FlextLdapEntry
LDAPUser = FlextLdapUser
LDAPGroup = FlextLdapGroup
LDAPConnection = FlextLdapConnection
LDAPOperation = FlextLdapOperation
DirectoryAggregate = FlextLdapDirectoryAggregate
LDAPDirectory = FlextLdapDirectory
LDAPConnectionEstablished = FlextLdapConnectionEstablished
LDAPConnectionLost = FlextLdapConnectionLost
LDAPEntryCreated = FlextLdapEntryCreated
LDAPEntryDeleted = FlextLdapEntryDeleted
LDAPEntryModified = FlextLdapEntryModified
LDAPUserAuthenticated = FlextLdapUserAuthenticated
LDAPAuthenticationFailed = FlextLdapAuthenticationFailed
LDAPGroupMemberAdded = FlextLdapGroupMemberAdded
LDAPGroupMemberRemoved = FlextLdapGroupMemberRemoved

# Interface compatibility
LDAPConnectionManager = FlextLdapConnectionManager
LDAPDirectoryRepository = FlextLdapDirectoryRepository
LDAPGroupRepository = FlextLdapGroupRepository
LDAPUserRepository = FlextLdapUserRepositoryImpl
FlextLdapUserRepositoryAlias = FlextLdapUserRepositoryImpl

# Service compatibility
LDAPSchemaService = FlextLdapSchemaService
LDAPMigrationService = FlextLdapMigrationService

# Helper function compatibility
escape_filter_chars = flext_ldap_escape_filter_chars
escape_filter_value = flext_ldap_escape_filter_value
parse_generalized_time = flext_ldap_parse_generalized_time
format_generalized_time = flext_ldap_format_generalized_time
validate_dn = flext_ldap_validate_dn
normalize_dn = flext_ldap_normalize_dn
split_dn = flext_ldap_split_dn
compare_dns = flext_ldap_compare_dns
build_filter = flext_ldap_build_filter
is_valid_ldap_url = flext_ldap_is_valid_url
parse_ldap_url = flext_ldap_parse_url
parse_dn = flext_ldap_parse_dn
build_dn = flext_ldap_build_dn
normalize_attribute_name = flext_ldap_normalize_attribute_name
format_ldap_timestamp = flext_ldap_format_timestamp


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 🚨 DEPRECATION WARNINGS - Clear migration guidance                        │
# └─────────────────────────────────────────────────────────────────────────────┘
def _deprecation_warning(
    old_path: str,
    new_import: str,
    removal_version: str = "1.0.0",
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
        category=DeprecationWarning,
        stacklevel=3,
    )


# ┌─────────────────────────────────────────────────────────────────────────────┐
# │ 📦 DYNAMIC IMPORT HANDLER - Legacy path resolution                        │
# └─────────────────────────────────────────────────────────────────────────────┘
def __getattr__(name: str) -> Any:
    """Handle legacy imports with automatic deprecation warnings and guidance."""
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
    "LDAPAPI",  # from flext_ldap import LDAPAPI (LEGACY)
    # ═══════════════════════════════════════════════════════════════════════════════
    # 🚨 LEGACY COMPATIBILITY - Will be deprecated
    # ═══════════════════════════════════════════════════════════════════════════════
    # Advanced Domain Concepts (aggregates & events)
    "DirectoryAggregate",  # from flext_ldap import DirectoryAggregate
    # Value Objects (domain types)
    "DistinguishedName",  # from flext_ldap import DistinguishedName
    # ═══════════════════════════════════════════════════════════════════════════════
    # ✅ NEW FLEXT CLASSES - RECOMMENDED IMPORTS
    # ═══════════════════════════════════════════════════════════════════════════════
    "FlextLdapAPI",  # from flext_ldap import FlextLdapAPI
    "FlextLdapActiveUserSpecification",  # FlextLdapActiveUserSpecification
    # ═══════════════════════════════════════════════════════════════════════════════
    # 🆕 NEW VALUE OBJECTS - FLEXT STANDARD
    # ═══════════════════════════════════════════════════════════════════════════════
    "FlextLdapAttribute",  # from flext_ldap import FlextLdapAttribute
    "FlextLdapAuthConfig",  # from flext_ldap import FlextLdapAuthConfig
    "FlextLdapBaseService",  # from flext_ldap import FlextLdapBaseService
    "FlextLdapClient",  # from flext_ldap import FlextLdapClient
    "FlextLdapConnection",  # from flext_ldap import FlextLdapConnection
    "FlextLdapConnectionBaseService",  # FlextLdapConnectionBaseService
    "FlextLdapConnectionConfig",  # from flext_ldap import FlextLdapConnectionConfig
    "FlextLdapConnectionRepository",  # FlextLdapConnectionRepository
    "FlextLdapCreateUserRequest",  # from flext_ldap import FlextLdapCreateUserRequest
    "FlextLdapDistinguishedNameSpecification",  # FlextLdapDNSpec
    "FlextLdapEntry",  # from flext_ldap import FlextLdapEntry
    # ═══════════════════════════════════════════════════════════════════════════════
    # 🆕 NEW SPECIFICATIONS - FLEXT STANDARD
    # ═══════════════════════════════════════════════════════════════════════════════
    "FlextLdapEntrySpecification",  # from flext_ldap import FlextLdapEntrySpecification
    "FlextLdapFilter",  # from flext_ldap import FlextLdapFilter
    "FlextLdapFilterSpecification",  # FlextLdapFilterSpec
    "FlextLdapFilterValue",  # from flext_ldap import FlextLdapFilterValue
    "FlextLdapGroup",  # from flext_ldap import FlextLdapGroup
    "FlextLdapGroupBaseService",  # from flext_ldap import FlextLdapGroupBaseService
    "FlextLdapGroupService",  # from flext_ldap import FlextLdapGroupService
    "FlextLdapGroupSpecification",  # from flext_ldap import FlextLdapGroupSpecification
    "FlextLdapMigrationService",  # from flext_ldap import FlextLdapMigrationService
    "FlextLdapNonEmptyGroupSpecification",  # FlextLdapNonEmptyGroupSpec
    "FlextLdapOperationBaseService",  # FlextLdapOperationBaseService
    "FlextLdapSchemaService",  # from flext_ldap import FlextLdapSchemaService
    "FlextLdapScope",  # from flext_ldap import FlextLdapScope
    # ═══════════════════════════════════════════════════════════════════════════════
    # 🆕 NEW DOMAIN SERVICES - FLEXT STANDARD
    # ═══════════════════════════════════════════════════════════════════════════════
    "FlextLdapSearchService",  # from flext_ldap import FlextLdapSearchService
    "FlextLdapSettings",  # from flext_ldap import FlextLdapSettings
    "FlextLdapUser",  # from flext_ldap import FlextLdapUser
    "FlextLdapUserBaseService",  # from flext_ldap import FlextLdapUserBaseService
    "FlextLdapUserPortService",  # from flext_ldap import FlextLdapUserPortService
    "FlextLdapUserRepositoryImpl",  # from flext_ldap import FlextLdapUserRepositoryImpl
    # ═══════════════════════════════════════════════════════════════════════════════
    # 🆕 NEW APPLICATION SERVICES - FLEXT STANDARD
    # ═══════════════════════════════════════════════════════════════════════════════
    "FlextLdapUserService",  # from flext_ldap import FlextLdapUserService
    "FlextLdapUserSpecification",  # from flext_ldap import FlextLdapUserSpecification
    "FlextLdapValidEntrySpecification",  # FlextLdapValidEntrySpec
    "FlextLdapValidPasswordSpecification",  # FlextLdapValidPasswordSpec
    "LDAPAttributes",  # from flext_ldap import LDAPAttributes
    "LDAPClient",  # from flext_ldap import LDAPClient (LEGACY)
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
    "LDAPMigrationService",  # from flext_ldap import LDAPMigrationService
    "LDAPSchemaService",  # from flext_ldap import LDAPSchemaService
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
        "flext_ldap.domain.values.DistinguishedName": (
            "from flext_ldap import DistinguishedName"
        ),
        "flext_ldap.domain.values.LDAPFilter": "from flext_ldap import LDAPFilter",
        "flext_ldap.domain.interfaces.LDAPConnectionManager": (
            "from flext_ldap import LDAPConnectionManager"
        ),
        "flext_ldap.domain.interfaces.LDAPDirectoryRepository": (
            "from flext_ldap import LDAPDirectoryRepository"
        ),
    }
    return migrations.get(
        deprecated_import,
        f"from flext_ldap import {deprecated_import.split('.')[-1]}",
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
