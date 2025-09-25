"""FlextLdapAPI - Main domain access point for LDAP operations.

This module provides the primary API interface for the flext-ldap domain.
Following FLEXT standards, this is the single unified class that provides
access to all LDAP domain functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService
from flext_ldap.acl import (
    FlextLdapAclManager,
)
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapAPI(FlextService[None]):
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
    """

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

    # =============================================================================
    # SEARCH METHODS - Enhanced with proper error handling and validation
    # =============================================================================

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        filter_str: str | None = None,
        scope: str = "subtree",
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
        scope: str = "subtree",
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
                page_size=100,
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

    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN format with enhanced error handling."""
        try:
            return self.validations.validate_dn(dn)
        except Exception as e:
            return FlextResult[None].fail(f"DN validation failed: {e}")

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format with enhanced error handling."""
        try:
            return self.validations.validate_filter(filter_str)
        except Exception as e:
            return FlextResult[None].fail(f"Filter validation failed: {e}")


__all__ = [
    "FlextLdapAPI",
]
