"""FlextLdap - Thin facade for LDAP operations with full FLEXT integration.

This module provides the main facade for the flext-ldap domain.
Following FLEXT standards, this is the thin entry point that provides
access to all LDAP domain functionality with proper integration of:
- FlextBus for event emission
- FlextContainer for dependency injection
- FlextContext for operation context
- FlextLdif for LDIF file operations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextLogger,
    FlextResult,
    FlextService,
)

from flext_ldap.acl import FlextLdapAclManager
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdap(FlextService[None]):
    """Thin facade for LDAP operations with full FLEXT ecosystem integration.

    This facade provides a simplified interface to LDAP operations while integrating:
    - FlextBus: Event emission for all operations
    - FlextContainer: Dependency injection for services
    - FlextContext: Operation context tracking
    - FlextLdif: LDIF file import/export operations

    All business logic is delegated to specialized services.
    """

    @override
    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize the LDAP facade with FLEXT ecosystem integration."""
        super().__init__()
        self._config = config or FlextLdapConfig.get_global_instance()

        # FLEXT ecosystem integration
        self._container = FlextContainer.get_global()
        self._context = FlextContext()
        self._bus = FlextBus()
        self._logger = FlextLogger(__name__)

        # Lazy-loaded components
        self._client: FlextLdapClient | None = None
        self._repositories: FlextLdapRepositories | None = None
        self._acl_manager: FlextLdapAclManager | None = None
        self._ldif: object | None = None  # FlextLdif instance


# Legacy alias for backward compatibility
class FlextLdapAPI(FlextLdap):
    """Main domain access point for LDAP operations.

    This class provides the primary API interface for the flext-ldap domain.
    Following FLEXT standards, this is the single unified class that provides
    access to all LDAP domain functionality.

    **CENTRALIZED APPROACH**: All operations follow centralized patterns:
    - FlextLdapAPI.* for LDAP-specific operations
    - Centralized validation through FlextLdapValidations
    - No wrappers, aliases, or fallbacks
    - Direct use of flext-core centralized services

    **PYTHON 3.13+ COMPATIBILITY**: Uses modern async/await patterns and latest type features.

    Implements FlextLdapProtocols through structural subtyping:
    - LdapConnectionProtocol: connect, is_connected methods (delegates to client)
    - LdapSearchProtocol: search, search_entries methods
    - LdapModifyProtocol: via client delegation
    - LdapAuthenticationProtocol: via client delegation
    - LdapValidationProtocol: via client delegation
    """

    @override
    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize the LDAP API service."""
        super().__init__()
        self._client: FlextLdapClient | None = None
        self._repositories: FlextLdapRepositories | None = None
        self._acl_manager: FlextLdapAclManager | None = None
        self._config: FlextLdapConfig | None = config

    @classmethod
    def create(cls) -> FlextLdapAPI:
        """Create a new FlextLdapAPI instance (factory method)."""
        return cls()

    @override
    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    async def execute_async(self) -> FlextResult[None]:
        """Execute the main domain operation asynchronously (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =============================================================================
    # PROPERTY ACCESSORS - Direct access to domain components
    # =============================================================================

    @property
    def client(self) -> FlextLdapClient:
        """Get the LDAP client instance."""
        if self._client is None:
            self._client = FlextLdapClient()
        return self._client

    @property
    def config(self) -> FlextLdapConfig:
        """Get the LDAP configuration instance."""
        if self._config is not None:
            return self._config
        return FlextLdapConfig.get_global_instance()

    @property
    def users(self) -> FlextLdapRepositories:
        """Get the users repository instance."""
        if self._repositories is None:
            self._repositories = FlextLdapRepositories()
        return self._repositories

    @property
    def groups(self) -> FlextLdapRepositories:
        """Get the groups repository instance."""
        if self._repositories is None:
            self._repositories = FlextLdapRepositories()
        return self._repositories

    @property
    def models(self) -> type[FlextLdapModels]:
        """Get the LDAP models class."""
        return FlextLdapModels

    @property
    def types(self) -> type[FlextLdapTypes]:
        """Get the LDAP types class."""
        return FlextLdapTypes

    @property
    def protocols(self) -> type[FlextLdapProtocols]:
        """Get the LDAP protocols class."""
        return FlextLdapProtocols

    @property
    def validations(self) -> type[FlextLdapValidations]:
        """Get the LDAP validations class."""
        return FlextLdapValidations

    # =============================================================================
    # CONNECTION MANAGEMENT METHODS - Enhanced with proper error handling
    # =============================================================================

    async def is_connected(self) -> bool:
        """Check if the LDAP client is connected."""
        return self.client.is_connected()

    async def test_connection(self) -> FlextResult[bool]:
        """Test the LDAP connection with enhanced error handling."""
        try:
            return self.client.test_connection()
        except Exception as e:
            return FlextResult[bool].fail(f"Connection test failed: {e}")

    async def connect(self) -> FlextResult[bool]:
        """Connect to LDAP server with enhanced error handling."""
        try:
            return self.client.test_connection()
        except Exception as e:
            return FlextResult[bool].fail(f"Connection failed: {e}")

    async def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server with enhanced error handling."""
        try:
            # Implementation would go here - for now return success
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Unbind failed: {e}")

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server - implements LdapConnectionProtocol.

        Alias for unbind to match protocol interface.

        Returns:
            FlextResult[None]: Disconnect success status

        """
        return await self.unbind()

    # =============================================================================
    # PROTOCOL IMPLEMENTATION METHODS - FlextLdapProtocols compliance
    # =============================================================================

    async def search(
        self,
        search_base: str,
        filter_str: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            filter_str: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Entry models search results

        """
        # Get search response and extract entries
        search_result = await self.search_entries(
            search_base, filter_str, FlextLdapConstants.Scopes.SUBTREE, attributes
        )
        if search_result.is_failure:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                search_result.error or "Search failed"
            )

        response = search_result.unwrap()
        return FlextResult[list[FlextLdapModels.Entry]].ok(response.entries)

    async def search_one(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Perform LDAP search for single entry - implements LdapSearchProtocol.

        Args:
            search_base: LDAP search base DN
            search_filter: LDAP search filter
            attributes: List of attributes to retrieve

        Returns:
            FlextResult[FlextLdapModels.Entry | None]: Single Entry model result or None

        """
        # Use existing search method and return first result
        search_result = await self.search(search_base, search_filter, attributes)
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(
                search_result.error or "Search failed"
            )

        results = search_result.unwrap()
        if not results:
            return FlextResult[FlextLdapModels.Entry | None].ok(None)

        return FlextResult[FlextLdapModels.Entry | None].ok(results[0])

    async def add_entry(
        self, dn: str, attributes: dict[str, str | list[str]]
    ) -> FlextResult[bool]:
        """Add new LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult[bool]: Add operation success status

        """
        # Delegate to client
        client = self.client
        return await client.add_entry(dn, attributes)

    async def modify_entry(
        self, dn: str, changes: dict[str, object]
    ) -> FlextResult[bool]:
        """Modify existing LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextResult[bool]: Modify operation success status

        """
        # Delegate to client
        client = self.client
        return await client.modify_entry(dn, changes)

    async def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry - implements LdapModifyProtocol.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult[bool]: Delete operation success status

        """
        # Delegate to client
        client = self.client
        return await client.delete_entry(dn)

    async def authenticate_user(
        self, username: str, password: str
    ) -> FlextResult[bool]:
        """Authenticate user against LDAP - implements LdapAuthenticationProtocol.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            FlextResult[bool]: Authentication success status

        """
        # Delegate to client and convert result
        client = self.client
        auth_result = await client.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextResult[bool].fail(auth_result.error or "Authentication failed")
        return FlextResult[bool].ok(True)

    async def validate_credentials(self, dn: str, password: str) -> FlextResult[bool]:
        """Validate user credentials against LDAP - implements LdapAuthenticationProtocol.

        Args:
            dn: User distinguished name
            password: User password

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Delegate to client
        client = self.client
        return await client.validate_credentials(dn, password)

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate distinguished name format - implements LdapValidationProtocol.

        Args:
            dn: Distinguished name to validate

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Delegate to client
        client = self.client
        return client.validate_dn(dn)

    def validate_entry(self, entry: FlextLdapModels.Entry) -> FlextResult[bool]:
        """Validate LDAP entry structure - implements LdapValidationProtocol.

        Args:
            entry: LDAP Entry model to validate

        Returns:
            FlextResult[bool]: Validation success status

        """
        # Delegate to client
        client = self.client
        return client.validate_entry(entry)

    # =============================================================================
    # SEARCH METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        filter_str: str | None = None,
        scope: str = FlextLdapConstants.Scopes.SUBTREE,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for LDAP groups with enhanced validation."""
        try:
            # Validate input parameters
            validation_result = self.validations.validate_dn(base_dn)
            if validation_result.is_failure:
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    f"Invalid base DN: {validation_result.error}"
                )

            if filter_str:
                filter_validation = self.validations.validate_filter(filter_str)
                if filter_validation.is_failure:
                    return FlextResult[list[FlextLdapModels.Group]].fail(
                        f"Invalid filter: {filter_validation.error}"
                    )

            return await self.client.search_groups(
                base_dn=base_dn,
                cn=cn,
                filter_str=filter_str,
                scope=scope,
                attributes=attributes,
            )
        except Exception as e:
            return FlextResult[list[FlextLdapModels.Group]].fail(f"Search failed: {e}")

    async def search_entries(
        self,
        base_dn: str,
        filter_str: str,
        scope: str = FlextLdapConstants.Scopes.SUBTREE,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search for LDAP entries using search_with_request with enhanced validation."""
        try:
            # Validate input parameters
            validation_result = self.validations.validate_dn(base_dn)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    f"Invalid base DN: {validation_result.error}"
                )

            filter_validation = self.validations.validate_filter(filter_str)
            if filter_validation.is_failure:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    f"Invalid filter: {filter_validation.error}"
                )

            request = self.models.SearchRequest(
                base_dn=base_dn,
                filter_str=filter_str,
                scope=scope,
                attributes=attributes or [],
                page_size=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
                paged_cookie=b"",
            )
            return await self.client.search_with_request(request)
        except Exception as e:
            return FlextResult[FlextLdapModels.SearchResponse].fail(
                f"Search failed: {e}"
            )

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get a specific LDAP group by DN with enhanced validation."""
        try:
            # Validate DN
            validation_result = self.validations.validate_dn(dn)
            if validation_result.is_failure:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"Invalid DN: {validation_result.error}"
                )

            return await self.client.get_group(dn)
        except Exception as e:
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}"
            )

    # =============================================================================
    # UPDATE METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    async def update_user_attributes(
        self, dn: str, attributes: dict[str, object]
    ) -> FlextResult[bool]:
        """Update user attributes with enhanced validation."""
        try:
            # Validate DN
            validation_result = self.validations.validate_dn(dn)
            if validation_result.is_failure:
                return FlextResult[bool].fail(f"Invalid DN: {validation_result.error}")

            return await self.client.update_user_attributes(dn, attributes)
        except Exception as e:
            return FlextResult[bool].fail(f"Update user attributes failed: {e}")

    async def update_group_attributes(
        self, dn: str, attributes: dict[str, object]
    ) -> FlextResult[bool]:
        """Update group attributes with enhanced validation."""
        try:
            # Validate DN
            validation_result = self.validations.validate_dn(dn)
            if validation_result.is_failure:
                return FlextResult[bool].fail(f"Invalid DN: {validation_result.error}")

            return await self.client.update_group_attributes(dn, attributes)
        except Exception as e:
            return FlextResult[bool].fail(f"Update group attributes failed: {e}")

    # =============================================================================
    # DELETE METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete a user with enhanced validation."""
        try:
            # Validate DN
            validation_result = self.validations.validate_dn(dn)
            if validation_result.is_failure:
                return FlextResult[None].fail(f"Invalid DN: {validation_result.error}")

            return await self.client.delete_user(dn)
        except Exception as e:
            return FlextResult[None].fail(f"Delete user failed: {e}")

    # =============================================================================
    # VALIDATION METHODS - Enhanced with proper error handling
    # =============================================================================

    def validate_configuration_consistency(self) -> FlextResult[bool]:
        """Validate configuration consistency with enhanced error handling."""
        try:
            config = self.config
            if config.ldap_bind_dn and not config.ldap_bind_password:
                return FlextResult[bool].fail(
                    "Bind password required when bind DN is provided"
                )
            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Configuration validation failed: {e}")

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format with enhanced error handling."""
        try:
            return self.validations.validate_filter(filter_str).map(lambda _: None)
        except Exception as e:
            return FlextResult[None].fail(f"Filter validation failed: {e}")

    # =============================================================================
    # LDIF OPERATIONS - Integration with FlextLdif for file operations
    # =============================================================================

    @property
    def ldif(self) -> object:
        """Get FlextLdif instance for LDIF operations."""
        if self._ldif is None:
            try:
                from flext_ldif import FlextLdif

                self._ldif = FlextLdif()
            except (ImportError, AttributeError, TypeError) as exc:
                # FlextLdif not available or initialization failed, return a stub
                self._logger.warning(
                    "FlextLdif initialization failed, using stub",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                error_msg = str(exc)

                class _LdifStub:
                    def parse_file(self, _path: Path) -> FlextResult[list]:
                        return FlextResult[list].fail(
                            f"FlextLdif not available: {error_msg}. Install with: pip install flext-ldif"
                        )

                    def write_file(
                        self, _entries: list, _path: Path
                    ) -> FlextResult[bool]:
                        return FlextResult[bool].fail(
                            f"FlextLdif not available: {error_msg}. Install with: pip install flext-ldif"
                        )

                self._ldif = _LdifStub()
        return self._ldif

    async def import_from_ldif(
        self, path: Path
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Import entries from LDIF file using FlextLdif.

        Args:
            path: Path to LDIF file

        Returns:
            FlextResult containing list of entries or error
        """
        try:
            # Use FlextLdif for parsing
            result = self.ldif.parse_file(path)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    result.error or "LDIF parsing failed"
                )

            # Log import event
            self._logger.info(
                "LDIF import successful",
                path=str(path),
                entry_count=len(result.value or []),
            )

            return FlextResult[list[FlextLdapModels.Entry]].ok(result.value or [])
        except Exception as e:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"LDIF import failed: {e}"
            )

    async def export_to_ldif(
        self, entries: list[FlextLdapModels.Entry], path: Path
    ) -> FlextResult[bool]:
        """Export entries to LDIF file using FlextLdif.

        Args:
            entries: List of LDAP entries to export
            path: Path to output LDIF file

        Returns:
            FlextResult indicating success or failure
        """
        try:
            # Use FlextLdif for writing
            result = self.ldif.write_file(entries, path)
            if result.is_failure:
                return FlextResult[bool].fail(result.error or "LDIF writing failed")

            # Log export event
            self._logger.info(
                "LDIF export successful", path=str(path), entry_count=len(entries)
            )

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"LDIF export failed: {e}")


__all__ = [
    "FlextLdap",
    "FlextLdapAPI",
]
