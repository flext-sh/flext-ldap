"""LDAP Domain Aggregates - Business Boundaries.

🏗️ CLEAN ARCHITECTURE: Domain Aggregates
Built on flext-core foundation patterns.

Aggregates define consistency boundaries in the LDAP domain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import AbstractEntity, DomainAggregateRoot

from flext_ldap.domain.events import LDAPConnectionEstablished

if TYPE_CHECKING:
    from flext_ldap.domain.entities import LDAPEntry
    from flext_ldap.domain.values import DistinguishedName


class DirectoryAggregate(DomainAggregateRoot):
    """LDAP Directory Aggregate Root.

    Manages the consistency boundary for LDAP directory operations.
    Coordinates between entries, users, groups, and connections.
    """

    base_dn: DistinguishedName
    connection_id: str | None = None
    is_connected: bool = False

    def establish_connection(self, connection_id: str) -> None:
        """Establish LDAP connection.

        Args:
            connection_id: Unique connection identifier

        """
        self.connection_id = connection_id
        self.is_connected = True

        # Raise domain event
        event = LDAPConnectionEstablished(
            aggregate_id=str(self.id),
            connection_id=connection_id,
            base_dn=str(self.base_dn),
        )
        self.add_event(event)

    def disconnect(self) -> None:
        """Disconnect from LDAP directory."""
        self.connection_id = None
        self.is_connected = False

    def can_perform_operation(self) -> bool:
        """Check if operations can be performed.

        Returns:
            True if connected and can perform operations

        """
        return self.is_connected and self.connection_id is not None


class LDAPDirectory(AbstractEntity[str]):
    """LDAP Directory Entity.

    Represents a logical LDAP directory structure with schema validation.
    """

    schema_version: str
    object_classes: list[str]
    attributes: dict[str, str]

    def validate_entry(self, entry: LDAPEntry) -> bool:
        """Validate entry against directory schema.

        Args:
            entry: LDAP entry to validate

        Returns:
            True if entry is valid for this directory

        """
        # Basic validation - can be extended with schema rules
        return bool(entry.dn and entry.attributes)

    def get_required_attributes(self, object_class: str) -> list[str]:
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
