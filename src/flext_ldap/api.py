"""FlextLdap - Thin facade for LDAP operations with FLEXT integration.

Enterprise LDAP operations facade following FLEXT Clean Architecture patterns.
Provides unified access to LDAP domain functionality with proper delegation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Self, override

from flext_core import (
    FlextResult,
    FlextService,
    FlextTypes,
)
from flext_ldif import FlextLdif

from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.servers import FlextLdapServers
from flext_ldap.services import FlextLdapServices


class FlextLdap(FlextService[None]):
    """Thin facade for LDAP operations with FLEXT ecosystem integration.

    Provides unified access to LDAP domain functionality through proper delegation
    to specialized services and infrastructure components.

    **THIN FACADE PATTERN**: Minimal orchestration, delegates to domain services:
    - FlextLdapServices: Application services for LDAP operations
    - FlextLdapClients: Infrastructure LDAP client operations
    - FlextLdapValidations: Domain validation logic

    **USAGE**:
    - Use FlextLdap for core LDAP orchestration
    - Import specialized services directly for advanced operations
    - Import FlextLdapModels, FlextLdapConstants directly for domain access
    """

    @override
    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize LDAP facade with configuration."""
        super().__init__()
        self._config: FlextLdapConfig = config or FlextLdapConfig()
        self._services: FlextLdapServices | None = None
        self._client: FlextLdapClients | None = None
        self._ldif: FlextLdif | None = None

    @classmethod
    def create(cls, config: FlextLdapConfig | None = None) -> Self:
        """Factory method to create FlextLdap instance."""
        return cls(config=config)

    @override
    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # CORE FACADE METHODS - Thin delegation layer
    # =========================================================================

    @property
    def services(self) -> FlextLdapServices:
        """Get the LDAP services instance."""
        if self._services is None:
            self._services = FlextLdapServices()
        return self._services

    @property
    def client(self) -> FlextLdapClients:
        """Get the LDAP client instance."""
        if self._client is None:
            self._client = FlextLdapClients()
        return self._client

    @property
    def config(self) -> FlextLdapConfig:
        """Get the LDAP configuration."""
        return self._config

    @property
    def servers(self) -> FlextLdapServers:
        """Get LDAP server operations."""
        return FlextLdapServers()

    # =========================================================================
    # CONNECTION MANAGEMENT - Delegate to client
    # =========================================================================

    def is_connected(self) -> bool:
        """Check if LDAP client is connected."""
        return self.client.is_connected()

    def connect(
        self,
        server: str | None = None,
        port: int | None = None,
        *,
        use_ssl: bool = False,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[bool]:
        """Connect to LDAP server."""
        # Construct server URI from components
        if server is None:
            server = "localhost"
        if port is None:
            port = 636 if use_ssl else 389

        protocol = "ldaps" if use_ssl else "ldap"
        server_uri = f"{protocol}://{server}:{port}"

        # Validate required parameters
        if bind_dn is None or bind_password is None:
            return FlextResult[bool].fail("bind_dn and bind_password are required")

        return self.client.connect(server_uri, bind_dn, bind_password)

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection."""
        return self.client.test_connection()

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server."""
        return self.client.unbind()

    # =========================================================================
    # CORE LDAP OPERATIONS - Consolidated facade methods
    # =========================================================================

    def search(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation.

        Args:
            search_request: Search request model with parameters

        Returns:
            FlextResult containing list of entries

        """
        return self.client.search_with_request(search_request).map(
            lambda response: response.entries,
        )

    def add_entry(
        self,
        dn: str,
        attributes: dict[str, str | FlextTypes.StringList],
    ) -> FlextResult[bool]:
        """Add new LDAP entry.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult indicating success

        """
        return self.client.add_entry(dn, attributes)

    def modify_entry(self, dn: str, changes: FlextTypes.Dict) -> FlextResult[bool]:
        """Modify existing LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextResult indicating success

        """
        return self.client.modify_entry(dn, changes)

    def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success

        """
        return self.client.delete_entry(dn)

    def authenticate_user(self, username: str, password: str) -> FlextResult[bool]:
        """Authenticate user against LDAP.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            FlextResult indicating success

        """
        auth_result = self.client.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextResult[bool].fail(auth_result.error or "Authentication failed")
        return FlextResult[bool].ok(True)

    # =========================================================================
    # LDIF INTEGRATION - Delegate to flext-ldif
    # =========================================================================

    @property
    def ldif(self) -> FlextLdif:
        """Get LDIF processing instance."""
        if self._ldif is None:
            self._ldif = FlextLdif()
        return self._ldif

    def import_from_ldif(self, path: Path) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Import entries from LDIF file.

        Args:
            path: Path to LDIF file

        Returns:
            FlextResult containing list of entries

        """
        result = self.ldif.parse(path)
        if result.is_failure:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"LDIF parsing failed: {result.error}",
            )

        ldif_entries = result.unwrap() or []
        ldap_entries = [
            FlextLdapModels.Entry.from_ldif(ldif_entry) for ldif_entry in ldif_entries
        ]

        return FlextResult[list[FlextLdapModels.Entry]].ok(ldap_entries)

    def export_to_ldif(
        self,
        entries: list[FlextLdapModels.Entry],
        path: Path,
    ) -> FlextResult[bool]:
        """Export entries to LDIF file.

        Args:
            entries: List of LDAP entries to export
            path: Path to output LDIF file

        Returns:
            FlextResult indicating success

        """
        ldif_entries = [entry.to_ldif() for entry in entries]
        result = self.ldif.write(ldif_entries, path)
        if result.is_failure:
            return FlextResult[bool].fail(f"LDIF writing failed: {result.error}")

        return FlextResult[bool].ok(True)

    # =========================================================================
    # ADDITIONAL FACADE METHODS - Complete API surface
    # =========================================================================

    def search_one(
        self,
        base_dn_or_request: str | FlextLdapModels.SearchRequest,
        filter_str: str | None = None,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search for a single LDAP entry.

        Args:
            base_dn_or_request: Base DN for search OR SearchRequest object
            filter_str: LDAP filter string (ignored if SearchRequest provided)
            scope: Search scope (base, onelevel, subtree) (ignored if SearchRequest provided)
            attributes: List of attributes to retrieve (ignored if SearchRequest provided)

        Returns:
            FlextResult containing single entry or None

        """
        if isinstance(base_dn_or_request, FlextLdapModels.SearchRequest):
            # SearchRequest provided
            search_request = base_dn_or_request.model_copy()
            search_request.size_limit = 1  # Ensure only one result
        else:
            # Individual parameters provided
            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn_or_request,
                filter_str=filter_str or "(objectClass=*)",
                scope=scope,
                attributes=attributes or ["*"],
                size_limit=1,
            )

        result = self.search(search_request)
        if result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(result.error)

        entries = result.unwrap()
        return FlextResult[FlextLdapModels.Entry | None].ok(
            entries[0] if entries else None,
        )

    def search_users(
        self,
        base_dn: str,
        filter_str: str | None = None,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search for user entries.

        Args:
            base_dn: Base DN for user search
            filter_str: Additional LDAP filter (combined with user filter)
            attributes: List of attributes to retrieve

        Returns:
            FlextResult containing list of user entries

        """
        user_filter = FlextLdapModels.SearchRequest.create_user_filter(filter_str)
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=user_filter,
            scope="subtree",
            attributes=attributes
            or FlextLdapModels.SearchRequest.get_user_attributes(),
        )

        return self.search(search_request)

    def find_user(
        self,
        username: str,
        base_dn: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Find a specific user by username.

        Args:
            username: Username to search for
            base_dn: Base DN for user search
            attributes: List of attributes to retrieve

        Returns:
            FlextResult containing user entry or None

        """
        filter_str = f"(uid={username})"
        return self.search_one(
            base_dn,
            filter_str=filter_str,
            scope="subtree",
            attributes=attributes,
        )

    def search_groups(
        self,
        base_dn: str | None = None,
        filter_str: str | None = None,
        attributes: list[str] | None = None,
        search_base: str | None = None,  # Alias for base_dn
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search for group entries.

        Args:
            base_dn: Base DN for group search
            filter_str: Additional LDAP filter (combined with group filter)
            attributes: List of attributes to retrieve
            search_base: Alias for base_dn (for backward compatibility)

        Returns:
            FlextResult containing list of group entries

        """
        # Handle parameter aliases
        effective_base_dn = base_dn or search_base
        if not effective_base_dn:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                "base_dn or search_base must be provided",
            )

        group_filter = FlextLdapModels.SearchRequest.create_group_filter(filter_str)
        search_request = FlextLdapModels.SearchRequest(
            base_dn=effective_base_dn,
            filter_str=group_filter,
            scope="subtree",
            attributes=attributes
            or FlextLdapModels.SearchRequest.get_group_attributes(),
        )

        return self.search(search_request)

    def get_group(
        self,
        dn: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Get a specific group by DN.

        Args:
            dn: Distinguished name of the group
            attributes: List of attributes to retrieve

        Returns:
            FlextResult containing group entry or None

        """
        return self.search_one(
            dn,
            filter_str="(objectClass=groupOfNames)",
            scope="base",
            attributes=attributes,
        )

    def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, str | FlextTypes.StringList],
    ) -> FlextResult[bool]:
        """Update user attributes.

        Args:
            dn: User distinguished name
            attributes: Dictionary of attributes to update

        Returns:
            FlextResult indicating success

        """
        changes: FlextTypes.Dict = {}
        for attr_name, attr_value in attributes.items():
            changes[attr_name] = [
                (
                    "MODIFY_REPLACE",
                    [attr_value] if isinstance(attr_value, str) else attr_value,
                )
            ]

        return self.modify_entry(dn, changes)

    def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, str | FlextTypes.StringList],
    ) -> FlextResult[bool]:
        """Update group attributes.

        Args:
            dn: Group distinguished name
            attributes: Dictionary of attributes to update

        Returns:
            FlextResult indicating success

        """
        changes: FlextTypes.Dict = {}
        for attr_name, attr_value in attributes.items():
            changes[attr_name] = [
                (
                    "MODIFY_REPLACE",
                    [attr_value] if isinstance(attr_value, str) else attr_value,
                )
            ]

        return self.modify_entry(dn, changes)

    def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete a user entry.

        Args:
            dn: User distinguished name

        Returns:
            FlextResult indicating success

        """
        return self.delete_entry(dn)

    def search_entries(
        self,
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = "subtree",
        attributes: list[str] | None = None,
        size_limit: int | None = None,
        time_limit: int | None = None,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Perform comprehensive LDAP search returning SearchResponse.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope
            attributes: List of attributes to retrieve
            size_limit: Maximum number of entries to return (None uses model default)
            time_limit: Time limit for search in seconds (None uses model default)

        Returns:
            FlextResult containing SearchResponse with entries and metadata

        """
        # Build search request with explicit parameters to satisfy type checker
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
            size_limit=size_limit if size_limit is not None else 0,
            time_limit=time_limit if time_limit is not None else 0,
        )

        return self.client.search_with_request(search_request)

    def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate user credentials against LDAP.

        Args:
            dn: User distinguished name
            password: User password

        Returns:
            FlextResult indicating credential validity

        """
        return self.client.validate_credentials(dn, password)

    def add_entries_batch(
        self,
        entries: list[tuple[str, dict[str, str | FlextTypes.StringList]]],
    ) -> FlextResult[list[bool]]:
        """Add multiple LDAP entries in batch.

        Args:
            entries: List of (dn, attributes) tuples

        Returns:
            FlextResult containing list of success indicators

        """
        results = []
        for dn, attributes in entries:
            result = self.add_entry(dn, attributes)
            results.append(result.is_success)

        return FlextResult[list[bool]].ok(results)

    def search_entries_bulk(
        self,
        base_dns: list[str],
        filters: list[str],
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[list[FlextLdapModels.Entry]]]:
        """Perform bulk search across multiple base DNs.

        Args:
            base_dns: List of base DNs to search
            filters: List of filter strings (one per base DN)
            scope: Search scope
            attributes: List of attributes to retrieve

        Returns:
            FlextResult containing list of entry lists (one per search)

        """
        if len(base_dns) != len(filters):
            return FlextResult[list[list[FlextLdapModels.Entry]]].fail(
                "base_dns and filters lists must have the same length",
            )

        results = []
        for base_dn, filter_str in zip(base_dns, filters, strict=False):
            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn,
                filter_str=filter_str,
                scope=scope,
                attributes=attributes,
            )

            result = self.search(search_request)
            if result.is_failure:
                return FlextResult[list[list[FlextLdapModels.Entry]]].fail(
                    f"Bulk search failed for {base_dn}: {result.error}",
                )

            results.append(result.unwrap())

        return FlextResult[list[list[FlextLdapModels.Entry]]].ok(results)

    def validate_configuration_consistency(self) -> FlextResult[bool]:
        """Validate LDAP configuration consistency.

        Returns:
            FlextResult indicating configuration validity

        """
        validation_result = self.config.validate_ldap_requirements()
        # Convert FlextResult[None] to FlextResult[bool]
        return validation_result.map(lambda _: True)

    # =========================================================================
    # SERVER OPERATIONS - Delegate to server operations
    # =========================================================================

    def convert_entry_between_servers(
        self,
        entry: FlextLdapModels.Entry,
        source_server_type: str,
        target_server_type: str,
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Convert LDAP entry between different server types.

        Args:
            entry: LDAP entry to convert
            source_server_type: Source server type
            target_server_type: Target server type

        Returns:
            Converted entry or error

        """
        source_servers = FlextLdapServers(source_server_type)
        # FlextLdapModels.Entry and FlextLdifModels.Entry are structurally compatible
        return source_servers.normalize_entry_for_server(entry, target_server_type)

    def detect_entry_server_type(
        self, entry: FlextLdapModels.Entry
    ) -> FlextResult[str]:
        """Detect the server type an entry is compatible with.

        Args:
            entry: LDAP entry to analyze

        Returns:
            Server type or error

        """
        # Try each server type to see which one accepts the entry
        server_types = [
            FlextLdapServers.SERVER_OPENLDAP1,
            FlextLdapServers.SERVER_OPENLDAP2,
            FlextLdapServers.SERVER_OID,
            FlextLdapServers.SERVER_OUD,
            FlextLdapServers.SERVER_AD,
        ]

        for server_type in server_types:
            servers = FlextLdapServers(server_type)
            # FlextLdapModels.Entry and FlextLdifModels.Entry are structurally compatible
            validation_result = servers.validate_entry_for_server(entry, server_type)
            if validation_result.is_success and validation_result.unwrap():
                return FlextResult[str].ok(server_type)

        return FlextResult[str].ok(FlextLdapServers.SERVER_GENERIC)

    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextResult[FlextLdapModels.Entry]:
        """Normalize LDAP entry for target server type.

        Args:
            entry: Entry to normalize
            target_server_type: Target server type

        Returns:
            Normalized entry or error

        """
        # FlextLdapModels.Entry and FlextLdifModels.Entry are structurally compatible
        return self.servers.normalize_entry_for_server(entry, target_server_type)

    def validate_entry_for_server(
        self,
        entry: FlextLdapModels.Entry,
        server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate LDAP entry compatibility with server.

        Args:
            entry: Entry to validate
            server_type: Server type to validate against

        Returns:
            Validation result

        """
        # FlextLdapModels.Entry and FlextLdifModels.Entry are structurally compatible
        return self.servers.validate_entry_for_server(entry, server_type)

    def get_server_specific_attributes(self) -> FlextResult[FlextTypes.Dict]:
        """Get server-specific attributes for current server type.

        Returns:
            Dictionary of server-specific attributes

        """
        # This would need to be implemented in the servers module
        # For now, return empty dict
        return FlextResult[FlextTypes.Dict].ok({})

    def get_detected_server_type(self) -> FlextResult[str | None]:
        """Get the detected server type from current connection.

        Returns:
            Server type or None if not detected

        """
        # This would require inspecting the current connection
        # For now, return None
        return FlextResult[str | None].ok(None)

    def get_server_capabilities(self) -> FlextResult[FlextTypes.Dict]:
        """Get server capabilities and supported features.

        Returns:
            Dictionary of server capabilities

        """
        # This would need to query the server
        # For now, return basic capabilities
        capabilities: dict[str, object] = {
            "supports_ssl": True,
            "supports_starttls": True,
            "supports_paged_results": True,
            "max_page_size": 1000,
        }
        return FlextResult[FlextTypes.Dict].ok(capabilities)

    def get_server_operations(self) -> FlextResult[list[str]]:
        """Get list of supported server operations.

        Returns:
            List of supported operations

        """
        operations = [
            "search",
            "add",
            "modify",
            "delete",
            "bind",
            "unbind",
            "compare",
            "extended",
        ]
        return FlextResult[list[str]].ok(operations)

    def search_universal(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform universal search with automatic server adaptation.

        Args:
            search_request: Search request parameters

        Returns:
            Search results

        """
        return self.search(search_request)

    # =========================================================================
    # CONTEXT MANAGER SUPPORT
    # =========================================================================

    def __enter__(self) -> Self:
        """Enter context manager - ensure connection is ready."""
        # Test connection if possible
        if hasattr(self.client, "test_connection"):
            test_result = self.client.test_connection()
            if test_result.is_failure:
                error_msg = f"LDAP connection test failed: {test_result.error}"
                raise RuntimeError(error_msg)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager - cleanup resources."""
        # Unbind if connected
        if hasattr(self.client, "unbind"):
            with suppress(Exception):
                self.client.unbind()


__all__ = [
    "FlextLdap",
]
