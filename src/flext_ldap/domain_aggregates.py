"""LDAP Domain Aggregates - Business Boundaries.

🏗️ CLEAN ARCHITECTURE: Domain Aggregates
Built on flext-core foundation patterns.

Aggregates define consistency boundaries in the LDAP domain.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import FlextAggregateRoot, FlextEntity

if TYPE_CHECKING:
    from flext_ldap.entities import FlextLdapEntry
    from flext_ldap.values import FlextLdapDistinguishedName


class FlextLdapDirectoryAggregate(FlextAggregateRoot):
    """LDAP Directory Aggregate Root.

    Manages the consistency boundary for LDAP directory operations.
    Coordinates between entries, users, groups, and connections.
    """

    base_dn: FlextLdapDistinguishedName
    connection_id: str | None = None
    is_connected: bool = False

    def establish_connection(self, connection_id: str) -> FlextLdapDirectoryAggregate:
        """Establish LDAP connection.

        Args:
            connection_id: Unique connection identifier

        Returns:
            New aggregate instance with connection established

        """
        # Create new aggregate state with connection
        aggregate_data = self.model_dump()
        aggregate_data.update(
            {
                "connection_id": connection_id,
                "is_connected": True,
                "version": self.version + 1,
            },
        )

        return self.__class__(**aggregate_data)

        # Note: Event raising would be handled by domain event system
        # For now, return the new state

    def disconnect(self) -> FlextLdapDirectoryAggregate:
        """Disconnect from LDAP directory.

        Returns:
            New aggregate instance with connection closed

        """
        aggregate_data = self.model_dump()
        aggregate_data.update(
            {
                "connection_id": None,
                "is_connected": False,
                "version": self.version + 1,
            },
        )

        return self.__class__(**aggregate_data)

    def can_perform_operation(self) -> bool:
        """Check if operations can be performed.

        Returns:
            True if connected and can perform operations

        """
        return self.is_connected and self.connection_id is not None


class FlextLdapDirectory(FlextEntity):
    """LDAP Directory Entity.

    Represents a logical LDAP directory structure with schema validation.
    """

    schema_version: str
    object_classes: list[str]
    attributes: dict[str, str]

    @staticmethod
    def validate_entry(entry: FlextLdapEntry) -> bool:
        """Validate entry against directory schema.

        Args:
            entry: LDAP entry to validate

        Returns:
            True if entry is valid for this directory

        """
        # Basic validation - can be extended with schema rules
        return bool(entry.dn and entry.attributes)

    @staticmethod
    def get_required_attributes(object_class: str) -> list[str]:
        """Get required attributes for object class.

        Args:
            object_class: LDAP object class name

        Returns:
            List of required attribute names

        """
        # This would typically come from schema
        required_attrs = {
            "person": ["cn", "sn"],
            "organizationalPerson": ["cn", "sn"],
            "inetOrgPerson": ["cn", "sn"],
            "groupOfNames": ["cn", "member"],
            "organizationalUnit": ["ou"],
        }
        return required_attrs.get(object_class, [])
