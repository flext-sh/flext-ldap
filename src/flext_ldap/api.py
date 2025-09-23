"""FlextLdapAPI - Main domain access point for LDAP operations.

This module provides the primary API interface for the flext-ldap domain.
Following FLEXT standards, this is the single unified class that provides
access to all LDAP domain functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfigs
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapAPI:
    """Main LDAP domain API providing unified access to all LDAP functionality.

    This is the primary entry point for the flext-ldap domain following FLEXT
    standards. It provides a single unified interface for all LDAP operations
    including connection management, authentication, search, CRUD operations,
    and domain-specific functionality.

    The API provides access to:
    - LDAP client operations (connection, authentication, search)
    - Repository pattern for data access
    - Model validation and type checking
    - Configuration management
    - Domain constants and utilities

    Example:
        api = FlextLdapClient()
        result = await api.authenticate_user("username", "password")
        if result.is_success:
            user = result.value

    """

    def __init__(self, config: FlextLdapConfigs | None = None) -> None:
        """Initialize FlextLdapAPI with optional configuration.

        Args:
            config: Optional LDAP configuration. If None, uses global instance.

        """
        self._config = config or FlextLdapConfigs.get_global_instance()
        self._client = FlextLdapClient()
        self._user_repository = FlextLdapRepositories.UserRepository(self._client)
        self._group_repository = FlextLdapRepositories.GroupRepository(self._client)

    @classmethod
    def create(cls, config: FlextLdapConfigs | None = None) -> FlextLdapAPI:
        """Factory method to create FlextLdapAPI instance.

        Args:
            config: Optional LDAP configuration.

        Returns:
            New FlextLdapAPI instance.

        """
        return cls(config=config)

    # =========================================================================
    # DOMAIN ACCESS PROPERTIES
    # =========================================================================

    @property
    def client(self) -> FlextLdapClient:
        """Access to LDAP client for direct operations."""
        return self._client

    @property
    def config(self) -> FlextLdapConfigs:
        """Access to LDAP configuration."""
        return self._config

    @property
    def users(self) -> FlextLdapRepositories.UserRepository:
        """Access to user repository."""
        return self._user_repository

    @property
    def groups(self) -> FlextLdapRepositories.GroupRepository:
        """Access to group repository."""
        return self._group_repository

    @property
    def models(self) -> type[FlextLdapModels]:
        """Access to LDAP models class."""
        return FlextLdapModels

    @property
    def types(self) -> type[FlextLdapTypes]:
        """Access to LDAP types class."""
        return FlextLdapTypes

    @property
    def protocols(self) -> type[FlextLdapProtocols]:
        """Access to LDAP protocols class."""
        return FlextLdapProtocols

    @property
    def validations(self) -> type[FlextLdapValidations]:
        """Access to LDAP validations class."""
        return FlextLdapValidations

    # =========================================================================
    # AUTHENTICATION METHODS
    # =========================================================================

    async def authenticate_user(
        self, username: str, password: str
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Authenticate user credentials against LDAP directory.

        Args:
            username: Username to authenticate.
            password: User password.

        Returns:
            FlextResult containing authenticated user or error.

        """
        return await self._client.authenticate_user(username, password)

    async def bind(
        self, dn: str | None = None, password: str | None = None
    ) -> FlextResult[bool]:
        """Bind to LDAP server with credentials.

        Args:
            dn: Distinguished Name for binding. If None, uses config.
            password: Password for binding. If None, uses config.

        Returns:
            FlextResult indicating bind success or error.

        """
        # Get actual values from config if None provided
        actual_dn = dn or self._config.get_effective_bind_dn()
        actual_password = password or self._config.get_effective_bind_password()

        if not actual_dn or not actual_password:
            return FlextResult[bool].fail("DN and password are required")

        bind_result = await self._client.bind(actual_dn, actual_password)
        if bind_result.is_failure:
            return FlextResult[bool].fail(bind_result.error or "Bind failed")
        return FlextResult[bool].ok(True)

    # =========================================================================
    # CONNECTION METHODS
    # =========================================================================

    async def connect(self) -> FlextResult[bool]:
        """Establish connection to LDAP server.

        Returns:
            FlextResult indicating connection success or error.

        """
        # Get connection details from config
        uri = self._config.get_effective_server_uri()
        bind_dn = self._config.get_effective_bind_dn()
        password = self._config.get_effective_bind_password()

        if not uri or not bind_dn or not password:
            return FlextResult[bool].fail("Missing connection configuration")

        connect_result = await self._client.connect(uri, bind_dn, password)
        if connect_result.is_failure:
            return FlextResult[bool].fail(connect_result.error or "Connection failed")
        return FlextResult[bool].ok(True)

    async def disconnect(self) -> FlextResult[bool]:
        """Close connection to LDAP server.

        Returns:
            FlextResult indicating disconnection success or error.

        """
        unbind_result = await self._client.unbind()
        if unbind_result.is_failure:
            return FlextResult[bool].fail(unbind_result.error or "Disconnect failed")
        return FlextResult[bool].ok(True)

    async def is_connected(self) -> bool:
        """Check if currently connected to LDAP server.

        Returns:
            True if connected, False otherwise.

        """
        return self._client.is_connected()

    # =========================================================================
    # SEARCH METHODS
    # =========================================================================

    async def search_users(
        self, filter_str: str | None = None, base_dn: str | None = None
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Search for users in LDAP directory.

        Args:
            filter_str: LDAP search filter. If None, uses default user filter.
            base_dn: Search base DN. If None, uses a default.

        Returns:
            FlextResult containing list of users or error.

        """
        # Get defaults - use a reasonable default for base_dn
        actual_base_dn = base_dn or "ou=users,dc=example,dc=com"

        # If custom filter provided, use generic search_entries
        if filter_str:
            search_result = await self.search_entries(
                base_dn=actual_base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=None,
            )
            if search_result.is_failure:
                return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                    search_result.error or "Search failed"
                )

            # Convert SearchResponse entries to LdapUser objects
            users = []
            for entry in search_result.value.entries:
                # Create minimal user object from search result
                user = FlextLdapModels.LdapUser(
                    dn=str(entry.get("dn", "")),
                    cn=str(entry.get("cn", "")),
                    uid=str(entry.get("uid", "")),
                    sn=str(entry.get("sn", "")),
                    given_name=str(entry.get("givenName"))
                    if entry.get("givenName")
                    else None,
                    mail=str(entry.get("mail")) if entry.get("mail") else None,
                    telephone_number=None,
                    mobile=None,
                    department=None,
                    title=None,
                    organization=None,
                    organizational_unit=None,
                    user_password=None,
                    created_timestamp=None,
                    modified_timestamp=None,
                )
                users.append(user)
            return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)

        # Use default client search for standard user queries
        return await self._client.search_users(actual_base_dn, uid=None)

    async def search_groups(
        self, filter_str: str | None = None, base_dn: str | None = None
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for groups in LDAP directory.

        Args:
            filter_str: LDAP search filter. If None, uses default group filter.
            base_dn: Search base DN. If None, uses a default.

        Returns:
            FlextResult containing list of groups or error.

        """
        # Get defaults - use a reasonable default for base_dn
        actual_base_dn = base_dn or "ou=groups,dc=example,dc=com"

        # If custom filter provided, use generic search_entries
        if filter_str:
            search_result = await self.search_entries(
                base_dn=actual_base_dn,
                filter_str=filter_str,
                scope="subtree",
                attributes=None,
            )
            if search_result.is_failure:
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    search_result.error or "Search failed"
                )

            # Convert SearchResponse entries to Group objects
            groups = []
            for entry in search_result.value.entries:
                # Create minimal group object from search result
                group = FlextLdapModels.Group(
                    dn=str(entry.get("dn", "")),
                    cn=str(entry.get("cn", "")),
                    gid_number=int(str(entry.get("gidNumber", 0)))
                    if entry.get("gidNumber")
                    else None,
                    description=str(entry.get("description"))
                    if entry.get("description")
                    else None,
                    created_timestamp=None,
                    modified_timestamp=None,
                )
                groups.append(group)
            return FlextResult[list[FlextLdapModels.Group]].ok(groups)

        # Use default client search for standard group queries
        return await self._client.search_groups(actual_base_dn, cn=None)

    async def search_entries(
        self,
        base_dn: str,
        filter_str: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Generic search for LDAP entries.

        Args:
            base_dn: Search base Distinguished Name.
            filter_str: LDAP search filter.
            scope: Search scope (base, onelevel, subtree).
            attributes: Attributes to return. If None, returns all.

        Returns:
            FlextResult containing search response or error.

        """
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter=filter_str,  # Use the alias 'filter' instead of 'filter_str'
            scope=scope,
            attributes=attributes,
            page_size=None,
            paged_cookie=None,
        )
        return await self._client.search_with_request(search_request)

    # =========================================================================
    # CRUD METHODS
    # =========================================================================

    async def create_user(
        self, user_request: FlextLdapModels.CreateUserRequest
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create new user in LDAP directory.

        Args:
            user_request: User creation request with required fields.

        Returns:
            FlextResult containing created user or error.

        """
        return await self._client.create_user(user_request)

    async def create_group(
        self, group_request: FlextLdapModels.CreateGroupRequest
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create new group in LDAP directory.

        Args:
            group_request: Group creation request with required fields.

        Returns:
            FlextResult containing created group or error.

        """
        return await self._client.create_group(group_request)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by Distinguished Name.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult containing user or None if not found.

        """
        return await self._client.get_user(dn)

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by Distinguished Name.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult containing group or None if not found.

        """
        return await self._client.get_group(dn)

    async def update_user_attributes(
        self, dn: str, attributes: dict[str, object]
    ) -> FlextResult[bool]:
        """Update user attributes.

        Args:
            dn: User Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating update success or error.

        """
        return await self._client.update_user_attributes(dn, attributes)

    async def update_group_attributes(
        self, dn: str, attributes: dict[str, object]
    ) -> FlextResult[bool]:
        """Update group attributes.

        Args:
            dn: Group Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating update success or error.

        """
        return await self._client.update_group_attributes(dn, attributes)

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete user from LDAP directory.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult indicating deletion success or error.

        """
        delete_result = await self._client.delete_user(dn)
        if delete_result.is_failure:
            return FlextResult[bool].fail(delete_result.error or "Delete failed")
        return FlextResult[bool].ok(True)

    async def delete_group(self, dn: str) -> FlextResult[bool]:
        """Delete group from LDAP directory.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult indicating deletion success or error.

        """
        delete_result = await self._client.delete_group(dn)
        if delete_result.is_failure:
            return FlextResult[bool].fail(delete_result.error or "Delete failed")
        return FlextResult[bool].ok(True)

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    async def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection.

        Returns:
            FlextResult indicating connection test success or error.

        """
        test_result = self._client.test_connection()
        if test_result.is_failure:
            return FlextResult[bool].fail(test_result.error or "Connection test failed")
        return FlextResult[bool].ok(True)

    def validate_configuration_consistency(self) -> FlextResult[None]:
        """Validate LDAP configuration consistency.

        Returns:
            FlextResult indicating validation success or error.

        """
        try:
            # Check required configuration fields using helper methods
            server_uri = self._config.get_effective_server_uri()
            bind_dn = self._config.get_effective_bind_dn()
            bind_password = self._config.get_effective_bind_password()

            if not server_uri:
                return FlextResult[None].fail("Server URI is required")
            if not bind_dn:
                return FlextResult[None].fail("Bind DN is required")
            if not bind_password:
                return FlextResult[None].fail("Bind password is required")

            # Validate DN format
            dn_validation = FlextLdapValidations.validate_dn(bind_dn)
            if dn_validation.is_failure:
                return FlextResult[None].fail(f"Invalid bind DN: {dn_validation.error}")

            # Use business rules validation from config
            business_validation = self._config.validate_business_rules()
            if business_validation.is_failure:
                return FlextResult[None].fail(
                    f"Business rules validation failed: {business_validation.error}"
                )

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation error: {e}")

    def validate_dn(self, dn: str) -> FlextResult[str]:
        """Validate Distinguished Name format.

        Args:
            dn: Distinguished Name to validate.

        Returns:
            FlextResult containing validated DN or error.

        """
        validation_result = FlextLdapValidations.validate_dn(dn)
        if validation_result.is_failure:
            return FlextResult[str].fail(
                validation_result.error or "DN validation failed"
            )
        return FlextResult[str].ok(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[str]:
        """Validate LDAP search filter format.

        Args:
            filter_str: Search filter to validate.

        Returns:
            FlextResult containing validated filter or error.

        """
        validation_result = FlextLdapValidations.validate_filter(filter_str)
        if validation_result.is_failure:
            return FlextResult[str].fail(
                validation_result.error or "Filter validation failed"
            )
        return FlextResult[str].ok(filter_str)

    def validate_email(self, email: str | None) -> FlextResult[str | None]:
        """Validate email address format.

        Args:
            email: Email address to validate.

        Returns:
            FlextResult containing validated email or error.

        """
        if email is None:
            return FlextResult[str | None].ok(None)

        validation_result = FlextLdapValidations.validate_email(email)
        if validation_result.is_failure:
            return FlextResult[str | None].fail(
                validation_result.error or "Email validation failed"
            )
        return FlextResult[str | None].ok(email)


__all__ = [
    "FlextLdapAPI",
]
