"""Base server operations abstract class for LDAP servers.

This module provides the abstract base class that all server-specific
LDAP operations implementations must extend.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_core import FlextResult, FlextService, FlextTypes
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.models import FlextLdapModels


class FlextLdapServersBaseOperations(FlextService[None], ABC):
    """Abstract base class for server-specific LDAP operations.

    All server implementations (OpenLDAP, OID, OUD, AD, etc.) must extend
    this class and implement the required methods for:
    - Connection handling
    - Schema operations
    - ACL operations
    - Entry operations
    - Search operations
    """

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize base server operations.

        Args:
            server_type: LDAP server type identifier (optional, child classes may hardcode)

        """
        super().__init__()
        # logger inherited from FlextService
        self._server_type = server_type or "generic"

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService."""
        return FlextResult[None].ok(None)

    @property
    def server_type(self) -> str:
        """Get server type identifier."""
        return self._server_type

    # =========================================================================
    # CONNECTION OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for this server type.

        Args:
            use_ssl: Whether SSL is used

        Returns:
            Default port number

        """

    @abstractmethod
    def supports_start_tls(self) -> bool:
        """Check if server supports START_TLS."""

    @abstractmethod
    def get_bind_mechanisms(self) -> FlextTypes.StringList:
        """Get supported BIND mechanisms (SIMPLE, SASL, etc.)."""

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_schema_dn(self) -> str:
        """Get schema subentry DN for this server type.

        Returns:
            Schema DN (e.g., 'cn=subschema', 'cn=schema')

        """

    @abstractmethod
    def discover_schema(self, connection: Connection) -> FlextResult[FlextTypes.Dict]:
        """Discover schema from server.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing schema information

        """

    @abstractmethod
    def parse_object_class(self, object_class_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse objectClass definition from schema.

        Args:
            object_class_def: ObjectClass definition string

        Returns:
            FlextResult containing parsed objectClass information

        """

    @abstractmethod
    def parse_attribute_type(self, attribute_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse attributeType definition from schema.

        Args:
            attribute_def: AttributeType definition string

        Returns:
            FlextResult containing parsed attribute information

        """

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_acl_attribute_name(self) -> str:
        """Get ACL attribute name for this server type.

        Returns:
            ACL attribute name (e.g., 'olcAccess', 'aci', 'orclaci')

        """

    @abstractmethod
    def get_acl_format(self) -> str:
        """Get ACL format identifier.

        Returns:
            ACL format (e.g., 'openldap2', 'oracle', '389ds')

        """

    @abstractmethod
    def get_acls(
        self, connection: Connection, dn: str
    ) -> FlextResult[list[FlextTypes.Dict]]:
        """Get ACLs for a given DN.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name

        Returns:
            FlextResult containing list of ACL entries

        """

    @abstractmethod
    def set_acls(
        self, connection: Connection, dn: str, acls: list[FlextTypes.Dict]
    ) -> FlextResult[bool]:
        """Set ACLs for a given DN.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name
            acls: List of ACL entries to set

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    def parse_acl(self, acl_string: str) -> FlextResult[FlextTypes.Dict]:
        """Parse ACL string to structured format.

        Args:
            acl_string: ACL string in server-specific format

        Returns:
            FlextResult containing parsed ACL structure

        """

    @abstractmethod
    def format_acl(self, acl_dict: FlextTypes.Dict) -> FlextResult[str]:
        """Format ACL structure to server-specific string.

        Args:
            acl_dict: ACL dictionary structure

        Returns:
            FlextResult containing formatted ACL string

        """

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @abstractmethod
    def add_entry(
        self, connection: Connection, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Add entry to LDAP server.

        Args:
            connection: Active LDAP connection
            entry: FlextLdif Entry to add

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    def modify_entry(
        self, connection: Connection, dn: str, modifications: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Modify existing entry.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name of entry to modify
            modifications: Modifications to apply

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    def delete_entry(self, connection: Connection, dn: str) -> FlextResult[bool]:
        """Delete entry from LDAP server.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name of entry to delete

        Returns:
            FlextResult indicating success

        """

    @abstractmethod
    def normalize_entry(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for this server type.

        Args:
            entry: FlextLdif Entry to normalize

        Returns:
            FlextResult containing normalized entry

        """

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_max_page_size(self) -> int:
        """Get maximum page size for paged searches."""

    @abstractmethod
    def supports_paged_results(self) -> bool:
        """Check if server supports paged result control."""

    @abstractmethod
    def supports_vlv(self) -> bool:
        """Check if server supports Virtual List View control."""

    @abstractmethod
    @abstractmethod
    def search_with_paging(
        self,
        connection: Connection,
        base_dn: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
        scope: str = "subtree",
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute paged search.

        Args:
            connection: Active LDAP connection
            base_dn: Search base DN
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            scope: Search scope ("base", "level", or "subtree")
            page_size: Page size for results

        Returns:
            FlextResult containing list of entries

        """

    @abstractmethod
    def get_root_dse_attributes(
        self, connection: Connection
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing Root DSE attributes

        """

    @abstractmethod
    def detect_server_type_from_root_dse(self, root_dse: dict[str, object]) -> str:
        """Detect server type from Root DSE.

        Args:
            root_dse: Root DSE attributes

        Returns:
            Detected server type

        """

    @abstractmethod
    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported LDAP controls.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing list of supported control OIDs

        """

    @abstractmethod
    def normalize_entry_for_server(
        self, entry: FlextLdifModels.Entry, target_server_type: str | None = None
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Normalize entry for this server type.

        Args:
            entry: Entry to normalize

        Returns:
            FlextResult containing normalized entry

        """

    def normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize LDAP attribute name according to server-specific conventions.

        Args:
            attribute_name: Attribute name to normalize

        Returns:
            Normalized attribute name (default: lowercase)

        """
        return attribute_name.lower()

    def normalize_object_class(self, object_class: str) -> str:
        """Normalize LDAP object class name according to server-specific conventions.

        Args:
            object_class: Object class name to normalize

        Returns:
            Normalized object class name (default: lowercase)

        """
        return object_class.lower()

    def normalize_dn(self, dn: str) -> str:
        """Normalize distinguished name according to server-specific conventions.

        Args:
            dn: DN to normalize

        Returns:
            Normalized DN (default: as-is)

        """
        return dn

    @abstractmethod
    def validate_entry_for_server(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[bool]:
        """Validate entry for this server type.

        Args:
            entry: Entry to validate

        Returns:
            FlextResult indicating validation success or failure

        """
