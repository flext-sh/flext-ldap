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
from flext_ldap.config import FlextLdapConfigs
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
    """

    def __init__(self, config: FlextLdapConfigs | None = None) -> None:
        """Initialize the LDAP API service."""
        super().__init__()
        self._client: FlextLdapClient | None = None
        self._repositories: FlextLdapRepositories | None = None
        self._acl_manager: FlextLdapAclManager | None = None
        self._config: FlextLdapConfigs | None = config

    @classmethod
    def create(cls) -> FlextLdapAPI:
        """Create a new FlextLdapAPI instance (factory method)."""
        return cls()

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
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
    def config(self) -> FlextLdapConfigs:
        """Get the LDAP configuration instance."""
        if self._config is not None:
            return self._config
        return FlextLdapConfigs.get_global_instance()

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
    # CONNECTION MANAGEMENT METHODS
    # =============================================================================

    async def is_connected(self) -> bool:
        """Check if the LDAP client is connected."""
        return self.client.is_connected()

    async def test_connection(self) -> FlextResult[bool]:
        """Test the LDAP connection."""
        return self.client.test_connection()

    # =============================================================================
    # SEARCH METHODS - Delegate to client
    # =============================================================================

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        filter_str: str | None = None,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for LDAP groups."""
        return await self.client.search_groups(
            base_dn=base_dn,
            cn=cn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

    async def search_entries(
        self,
        base_dn: str,
        filter_str: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Search for LDAP entries using search_with_request."""
        request = self.models.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=getattr(self.models.Scope, scope.upper(), self.models.Scope.SUBTREE),
            attributes=attributes or [],
            page_size=100,
            paged_cookie=b"",
        )
        return await self.client.search_with_request(request)

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get a specific LDAP group by DN."""
        return await self.client.get_group(dn)

    # =============================================================================
    # UPDATE METHODS - Delegate to client
    # =============================================================================

    async def update_user_attributes(
        self, dn: str, attributes: dict[str, str]
    ) -> FlextResult[bool]:
        """Update user attributes."""
        return await self.client.update_user_attributes(dn, attributes)

    async def update_group_attributes(
        self, dn: str, attributes: dict[str, str]
    ) -> FlextResult[bool]:
        """Update group attributes."""
        return await self.client.update_group_attributes(dn, attributes)

    # =============================================================================
    # DELETE METHODS - Delegate to client
    # =============================================================================

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete a user."""
        return await self.client.delete_user(dn)

    # =============================================================================
    # VALIDATION METHODS - Delegate to validations
    # =============================================================================

    def validate_configuration_consistency(self) -> FlextResult[bool]:
        """Validate configuration consistency."""
        config = self.config
        if config.ldap_bind_dn and not config.ldap_bind_password:
            return FlextResult[bool].fail(
                "Bind password required when bind DN is provided"
            )
        return FlextResult[bool].ok(True)

    def validate_dn(self, dn: str) -> FlextResult[str]:
        """Validate DN format."""
        return self.validations.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[str]:
        """Validate LDAP filter format."""
        return self.validations.validate_filter(filter_str)

    # =============================================================================
    # LEGACY METHODS - For backward compatibility
    # =============================================================================

    def get_client(self) -> FlextLdapClient:
        """Get the LDAP client instance (legacy method)."""
        return self.client

    def get_repositories(self) -> FlextLdapRepositories:
        """Get the LDAP repositories instance (legacy method)."""
        return self.users

    def get_acl_manager(self) -> FlextLdapAclManager:
        """Get the ACL manager instance (legacy method)."""
        if self._acl_manager is None:
            self._acl_manager = FlextLdapAclManager()
        return self._acl_manager


__all__ = [
    "FlextLdapAPI",
]
