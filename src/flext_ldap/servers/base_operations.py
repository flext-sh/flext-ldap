"""Base server operations abstract class for LDAP servers.

This module provides the abstract base class that all server-specific
LDAP operations implementations must extend.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes
from flext_ldif import FlextLdifModels


class BaseServerOperations(FlextService[None], ABC):
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
        self._logger = FlextLogger(__name__)
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
    def get_default_port(self, use_ssl: bool = False) -> int:
        """Get default port for this server type.

        Args:
            use_ssl: Whether SSL is used

        Returns:
            Default port number
        """
        pass

    @abstractmethod
    def supports_start_tls(self) -> bool:
        """Check if server supports START_TLS."""
        pass

    @abstractmethod
    def get_bind_mechanisms(self) -> FlextTypes.StringList:
        """Get supported BIND mechanisms (SIMPLE, SASL, etc.)."""
        pass

    # =========================================================================
    # SCHEMA OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_schema_dn(self) -> str:
        """Get schema subentry DN for this server type.

        Returns:
            Schema DN (e.g., 'cn=subschema', 'cn=schema')
        """
        pass

    @abstractmethod
    def discover_schema(self, connection: object) -> FlextResult[FlextTypes.Dict]:
        """Discover schema from server.

        Args:
            connection: Active LDAP connection

        Returns:
            FlextResult containing schema information
        """
        pass

    @abstractmethod
    def parse_object_class(self, object_class_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse objectClass definition from schema.

        Args:
            object_class_def: ObjectClass definition string

        Returns:
            FlextResult containing parsed objectClass information
        """
        pass

    @abstractmethod
    def parse_attribute_type(self, attribute_def: str) -> FlextResult[FlextTypes.Dict]:
        """Parse attributeType definition from schema.

        Args:
            attribute_def: AttributeType definition string

        Returns:
            FlextResult containing parsed attribute information
        """
        pass

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_acl_attribute_name(self) -> str:
        """Get ACL attribute name for this server type.

        Returns:
            ACL attribute name (e.g., 'olcAccess', 'aci', 'orclaci')
        """
        pass

    @abstractmethod
    def get_acl_format(self) -> str:
        """Get ACL format identifier.

        Returns:
            ACL format (e.g., 'openldap2', 'oracle', '389ds')
        """
        pass

    @abstractmethod
    def get_acls(
        self, connection: object, dn: str
    ) -> FlextResult[list[FlextTypes.Dict]]:
        """Get ACLs for a given DN.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name

        Returns:
            FlextResult containing list of ACL entries
        """
        pass

    @abstractmethod
    def set_acls(
        self, connection: object, dn: str, acls: list[FlextTypes.Dict]
    ) -> FlextResult[bool]:
        """Set ACLs for a given DN.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name
            acls: List of ACL entries to set

        Returns:
            FlextResult indicating success
        """
        pass

    @abstractmethod
    def parse_acl(self, acl_string: str) -> FlextResult[FlextTypes.Dict]:
        """Parse ACL string to structured format.

        Args:
            acl_string: ACL string in server-specific format

        Returns:
            FlextResult containing parsed ACL structure
        """
        pass

    @abstractmethod
    def format_acl(self, acl_dict: FlextTypes.Dict) -> FlextResult[str]:
        """Format ACL structure to server-specific string.

        Args:
            acl_dict: ACL dictionary structure

        Returns:
            FlextResult containing formatted ACL string
        """
        pass

    # =========================================================================
    # ENTRY OPERATIONS
    # =========================================================================

    @abstractmethod
    def add_entry(
        self, connection: object, entry: FlextLdifModels.Entry
    ) -> FlextResult[bool]:
        """Add entry to LDAP server.

        Args:
            connection: Active LDAP connection
            entry: FlextLdif Entry to add

        Returns:
            FlextResult indicating success
        """
        pass

    @abstractmethod
    def modify_entry(
        self, connection: object, dn: str, modifications: FlextTypes.Dict
    ) -> FlextResult[bool]:
        """Modify existing entry.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name of entry to modify
            modifications: Modifications to apply

        Returns:
            FlextResult indicating success
        """
        pass

    @abstractmethod
    def delete_entry(self, connection: object, dn: str) -> FlextResult[bool]:
        """Delete entry from LDAP server.

        Args:
            connection: Active LDAP connection
            dn: Distinguished Name of entry to delete

        Returns:
            FlextResult indicating success
        """
        pass

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
        pass

    # =========================================================================
    # SEARCH OPERATIONS
    # =========================================================================

    @abstractmethod
    def get_max_page_size(self) -> int:
        """Get maximum page size for paged searches."""
        pass

    @abstractmethod
    def supports_paged_results(self) -> bool:
        """Check if server supports paged result control."""
        pass

    @abstractmethod
    def supports_vlv(self) -> bool:
        """Check if server supports Virtual List View control."""
        pass

    @abstractmethod
    def search_with_paging(
        self,
        connection: object,
        base_dn: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
        page_size: int = 100,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute paged search.

        Args:
            connection: Active LDAP connection
            base_dn: Search base DN
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            page_size: Page size for results

        Returns:
            FlextResult containing list of entries
        """
        pass
