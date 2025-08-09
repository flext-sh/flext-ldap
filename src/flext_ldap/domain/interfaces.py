"""LDAP Domain Interfaces - COMPATIBILITY FACADE.

⚠️ DEPRECATED MODULE - Compatibility facade for SOLID consolidation migration

    MIGRATE TO: flext_ldap.abstracts module
    REASON: SOLID refactoring - consolidated abstract patterns to eliminate duplications

    MASSIVE DUPLICATIONS ELIMINATED:
    - FlextLdapDirectoryRepository → FlextLdapRepository (abstracts.py)
    - FlextLdapGroupRepository → FlextLdapRepository (abstracts.py)
    - FlextLdapConnectionManager → FlextLdapConnectionService (abstracts.py)
    - FlextLdapSchemaValidator → FlextLdapSchemaService (abstracts.py)

    OLD: from flext_ldap.domain.interfaces import FlextLdapDirectoryRepository
    NEW: from flext_ldap.abstracts import FlextLdapRepository

This module provides backward compatibility during SOLID refactoring transition.
All abstract patterns have been consolidated into abstracts.py following flext-core
foundation patterns with proper extension instead of duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from flext_core import FlextResult

# Import consolidated abstractions from centralized module
from flext_ldap.abstracts import (
    FlextLdapConnectionService,
    FlextLdapRepository,
    FlextLdapSchemaService,
)

if TYPE_CHECKING:

    from flext_ldap.entities import FlextLdapEntry
    from flext_ldap.value_objects import (
        FlextLdapDistinguishedName,
    )

# Issue module-level deprecation warning
warnings.warn(
    "🚨 DEPRECATED MODULE: domain.interfaces is deprecated.\n"
    "✅ USE INSTEAD: flext_ldap.abstracts module (SOLID-consolidated abstractions)\n"
    "\n"
    "MIGRATION GUIDE:\n"
    "  OLD: from flext_ldap.domain.interfaces import FlextLdapDirectoryRepository\n"
    "  NEW: from flext_ldap.abstracts import FlextLdapRepository\n"
    "  OLD: from flext_ldap.domain.interfaces import FlextLdapGroupRepository\n"
    "  NEW: from flext_ldap.abstracts import FlextLdapRepository\n"
    "\n"
    "BENEFITS OF CENTRALIZED ABSTRACTIONS:\n"
    "  - Single source of truth eliminating duplications\n"
    "  - Proper flext-core foundation pattern extensions\n"
    "  - SOLID compliance with DRY principle\n"
    "  - Unified abstract contracts across ecosystem\n",
    DeprecationWarning,
    stacklevel=2,
)


class FlextLdapConnectionManager(FlextLdapConnectionService):
    """Compatibility facade for FlextLdapConnectionManager.

    ⚠️ DEPRECATED: Use FlextLdapConnectionService from flext_ldap.abstracts instead.

    This class provides backward compatibility while the codebase migrates to the
    centralized abstract patterns. All functionality is provided by the SOLID-compliant
    implementation in abstracts.py.

    Migration:
        OLD: FlextLdapConnectionManager from flext_ldap.domain.interfaces
        NEW: FlextLdapConnectionService from flext_ldap.abstracts
    """

    def __init__(self) -> None:
        """Initialize compatibility facade with deprecation warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapConnectionManager is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapConnectionService from flext_ldap.abstracts\n"
            "\n"
            "Benefits: SOLID compliance, centralized abstractions, flext-core extension\n",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__()

    async def ping(self, connection_id: str) -> FlextResult[object]:
        """Test connection health - compatibility method.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult indicating connection health

        """
        # Delegate to modern test_connection method and convert bool to object
        result = await self.test_connection(connection_id)
        if result.is_success:
            return FlextResult.ok(bool(result.data))  # Convert bool to object
        return FlextResult.fail(result.error or "Connection test failed")


class FlextLdapDirectoryRepository(FlextLdapRepository):
    """Compatibility facade for FlextLdapDirectoryRepository.

    ⚠️ DEPRECATED: Use FlextLdapRepository from flext_ldap.abstracts instead.

    This class provides backward compatibility while the codebase migrates to the
    centralized abstract patterns. All functionality is provided by the SOLID-compliant
    implementation in abstracts.py.

    Migration:
        OLD: FlextLdapDirectoryRepository from flext_ldap.domain.interfaces
        NEW: FlextLdapRepository from flext_ldap.abstracts
    """

    def __init__(self) -> None:
        """Initialize compatibility facade with deprecation warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapDirectoryRepository is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapRepository from flext_ldap.abstracts\n"
            "\n"
            "Benefits: SOLID compliance, flext-core extension, centralized abstractions\n",
            DeprecationWarning,
            stacklevel=2,
        )


class FlextLdapSchemaValidator(FlextLdapSchemaService):
    """Compatibility facade for FlextLdapSchemaValidator.

    ⚠️ DEPRECATED: Use FlextLdapSchemaService from flext_ldap.abstracts instead.

    This class provides backward compatibility while the codebase migrates to the
    centralized abstract patterns. All functionality is provided by the SOLID-compliant
    implementation in abstracts.py.

    Migration:
        OLD: FlextLdapSchemaValidator from flext_ldap.domain.interfaces
        NEW: FlextLdapSchemaService from flext_ldap.abstracts
    """

    def __init__(self) -> None:
        """Initialize compatibility facade with deprecation warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapSchemaValidator is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapSchemaService from flext_ldap.abstracts\n"
            "\n"
            "Benefits: SOLID compliance, flext-core extension, centralized abstractions\n",
            DeprecationWarning,
            stacklevel=2,
        )

    def validate_entry(self, _entry: FlextLdapEntry) -> FlextResult[object]:
        """Validate LDAP entry against schema - compatibility method.

        Args:
            entry: LDAP entry to validate

        Returns:
            FlextResult indicating validation result

        """
        # This is a synchronous compatibility method
        # Real implementations should override with async validation
        return FlextResult.fail(
            "Schema validation not implemented - use async validate_entry_schema",
        )

    def get_required_attributes(self, _object_class: str) -> list[str]:
        """Get required attributes for object class - compatibility method.

        Args:
            object_class: LDAP object class name

        Returns:
            List of required attribute names

        """
        # This is a synchronous compatibility method
        # Real implementations should integrate with async get_schema
        return []

    def validate_attribute_syntax(
        self,
        _attribute_name: str,
        _value: str,
    ) -> FlextResult[object]:
        """Validate attribute value syntax - compatibility method.

        Args:
            attribute_name: Name of the attribute
            value: Value to validate

        Returns:
            FlextResult indicating validation result

        """
        # This is a synchronous compatibility method
        # Real implementations should integrate with async validation
        return FlextResult.ok(data=True)


class FlextLdapGroupRepository(FlextLdapRepository):
    """Compatibility facade for FlextLdapGroupRepository.

    ⚠️ DEPRECATED: Use FlextLdapRepository from flext_ldap.abstracts instead.

    This class provides backward compatibility while the codebase migrates to the
    centralized abstract patterns. All functionality is provided by the SOLID-compliant
    implementation in abstracts.py which includes group-specific operations.

    Migration:
        OLD: FlextLdapGroupRepository from flext_ldap.domain.interfaces
        NEW: FlextLdapRepository from flext_ldap.abstracts (includes group operations)
    """

    def __init__(self) -> None:
        """Initialize compatibility facade with deprecation warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapGroupRepository is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapRepository from flext_ldap.abstracts\n"
            "\n"
            "Benefits: Unified repository with group operations, SOLID compliance, centralized\n",
            DeprecationWarning,
            stacklevel=2,
        )

    async def find_group_by_dn(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
    ) -> FlextResult[object]:
        """Find group by distinguished name - compatibility method.

        Args:
            connection_id: Active connection identifier
            dn: Group distinguished name

        Returns:
            FlextResult containing group if found

        """
        # Delegate to modern find_group_by_cn method (requires extracting CN from DN)
        cn = dn.get_rdn_value("cn") if hasattr(dn, "get_rdn_value") else "unknown"

        # Handle parent DN safely
        parent_dn = dn.get_parent_dn() if hasattr(dn, "get_parent_dn") else None
        base_dn = parent_dn if parent_dn is not None else dn

        result = await self.find_group_by_cn(connection_id, base_dn, cn)
        # Convert the result type from dict | None to object
        if result.is_success:
            return FlextResult.ok(result.data)  # dict | None -> object
        return FlextResult.fail(result.error or "Group search failed")

    async def add_member_to_group(
        self,
        connection_id: str,
        group_dn: FlextLdapDistinguishedName,
        member_dn: FlextLdapDistinguishedName,
    ) -> FlextResult[object]:
        """Add member to group - compatibility method.

        Args:
            connection_id: Active connection identifier
            group_dn: Group distinguished name
            member_dn: Member distinguished name

        Returns:
            FlextResult indicating success

        """
        # Use modify_entry to add member to group - type-safe changes dict
        changes: dict[str, object] = {
            "add": {
                "member": [str(member_dn)],
            },
        }
        result = await self.modify_entry(connection_id, group_dn, changes)
        # Convert FlextResult[None] to FlextResult[object]
        if result.is_success:
            return FlextResult.ok(data=True)  # None -> object (success indicator)
        return FlextResult.fail(result.error or "Failed to add member to group")
