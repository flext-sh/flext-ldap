"""LDAP client implementation for flext-ldap.

This module provides the core LDAP client functionality using ldap3
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""
# type: ignore[attr-defined]

from typing import Any, Literal

from flext_core import FlextLogger, FlextResult
from flext_ldap.models import FlextLdapModels
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.typings import FlextLdapTypes


class FlextLdapClient:
    """FlextLdapClient - Main LDAP client using ldap3 library.

    This class provides a comprehensive interface for LDAP operations including
    connection management, authentication, search, and CRUD operations.
    It uses the ldap3 library internally and provides a FlextResult-based API.

    The client supports both synchronous and asynchronous operations, with
    automatic connection management and proper error handling.
    """

    def __init__(self, config: FlextLdapModels.ConnectionConfig | None = None) -> None:
        """Initialize FlextLdapClient."""
        self._connection: FlextLdapTypes.Connection | None = None
        self._server: FlextLdapTypes.Server | None = None
        self._logger = FlextLogger(__name__)
        self._config = config
        self._container_manager = None  # Placeholder for container management
        self._session_id: str | None = None

        # Schema discovery properties
        self._schema_discovery: FlextLdapSchema.Discovery | None = None
        self._discovered_schema: FlextLdapModels.SchemaDiscoveryResult | None = None
        self._is_schema_discovered = False

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        password: str,
        *, auto_discover_schema: bool = True,
        connection_options: dict | None = None,
    ) -> FlextResult[bool]:
        """Connect and bind to LDAP server with universal compatibility.

        Args:
            server_uri: LDAP server URI (e.g., 'ldap://localhost:389').
            bind_dn: Distinguished Name for binding.
            password: Password for binding.
            auto_discover_schema: Whether to automatically discover schema.
            connection_options: Additional connection options.

        Returns:
            FlextResult[bool]: Success result or error.

        """
        try:
            self._logger.info("Connecting to LDAP server: %s", server_uri)

            # Apply connection options if provided
            server_options = connection_options or {}
            self._server = FlextLdapTypes.Server(server_uri, **server_options)

            self._connection = FlextLdapTypes.Connection(
                self._server, bind_dn, password, auto_bind=True
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            self._logger.info("Successfully connected to LDAP server")

            # Perform schema discovery if requested
            if auto_discover_schema:
                discovery_result = await self.discover_schema()
                if discovery_result.is_failure:
                    self._logger.warning(
                        "Schema discovery failed: %s", discovery_result.error
                    )
                    # Continue without schema discovery

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Connection failed")
            return FlextResult[bool].fail(f"Connection failed: {e}")

    async def bind(self, bind_dn: str, password: str) -> FlextResult[bool]:
        """Bind to LDAP server with specified credentials.

        Args:
            bind_dn: Distinguished Name for binding.
            password: Password for authentication.

        Returns:
            FlextResult[bool]: Success result or error.

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Create new connection with provided credentials
            if not self._server:
                return FlextResult[bool].fail("No server connection established")
            self._connection = FlextLdapTypes.Connection(
                self._server, bind_dn, password, auto_bind=True
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Bind failed - invalid credentials")

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Bind operation failed")
            return FlextResult[bool].fail(f"Bind failed: {e}")

    async def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server.

        Returns:
            FlextResult[None]: Success result or error.

        """
        try:
            if self._connection and self._connection.bound:
                self._connection.unbind()
                self._logger.info("Unbound from LDAP server")

            self._connection = None
            self._server = None
            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Unbind failed")
            return FlextResult[None].fail(f"Unbind failed: {e}")

    def is_connected(self) -> bool:
        """Check if client is connected to LDAP server.

        Returns:
            bool: True if connected and bound, False otherwise.

        """
        return self._connection is not None and self._connection.bound

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection.

        Returns:
            FlextResult[bool]: FlextLdapTypes.Connection test result.

        """
        if not self.is_connected():
            return FlextResult[bool].fail("Not connected to LDAP server")

        try:
            # Perform a simple search to test the connection
            if self._connection:
                self._connection.search(
                    "",
                    "(objectClass=*)",
                    "FlextLdapTypes.SUBTREE",
                    attributes=["objectClass"],
                )
            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"FlextLdapTypes.Connection test failed: {e}")

    async def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Authenticate user credentials.

        Args:
            username: Username to authenticate.
            password: User password.

        Returns:
            FlextResult containing authenticated user or error.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "No connection established",
                )

            # Search for user by username (uid or cn)
            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = "ou=users,dc=example,dc=com"  # Default base

            self._connection.search(
                search_base,
                search_filter,
                "FlextLdapTypes.SUBTREE",
                attributes=["*"],
            )

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.LdapUser].fail("User not found")

            user_entry = self._connection.entries[0]
            user_dn = str(user_entry.entry_dn)

            # Test authentication by attempting to bind with user credentials
            if not self._server:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "No server connection established",
                )
            test_connection = FlextLdapTypes.Connection(
                self._server,
                user_dn,
                password,
                auto_bind=False,
            )

            if not test_connection.bind():
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "Authentication failed",
                )

            test_connection.unbind()

            # Create user object from LDAP entry
            user = self._create_user_from_entry(user_entry)
            return FlextResult[FlextLdapModels.LdapUser].ok(user)

        except Exception as e:
            self._logger.exception("Authentication failed")
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"Authentication failed: {e}",
            )

    async def search_with_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Perform LDAP search with SearchRequest.

        Args:
            request: Search request containing all search parameters.

        Returns:
            FlextResult containing search response or error.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    "No connection established",
                )

            # Convert scope string to ldap3 scope
            scope_map: dict[
                str,
                Literal[
                    "FlextLdapTypes.BASE",
                    "FlextLdapTypes.LEVEL",
                    "FlextLdapTypes.SUBTREE",
                ],
            ] = {
                "base": FlextLdapTypes.BASE,
                "onelevel": FlextLdapTypes.LEVEL,
                "subtree": FlextLdapTypes.SUBTREE,
            }
            ldap3_scope: Literal[
                "FlextLdapTypes.BASE",
                "FlextLdapTypes.LEVEL",
                "FlextLdapTypes.SUBTREE",
            ] = scope_map.get(request.scope, FlextLdapTypes.SUBTREE)

            # Perform search
            success = self._connection.search(
                request.base_dn,
                request.filter_str,
                ldap3_scope,
                attributes=request.attributes,
            )

            if not success:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    "Search operation failed",
                )

            # Convert entries to our format
            entries: list[dict[str, object]] = []
            for entry in self._connection.entries:
                entry_dict: dict[str, object] = {"dn": str(entry.entry_dn)}
                for attr_name in entry.entry_attributes:
                    attr_value = entry[attr_name].value
                    if isinstance(attr_value, list) and len(attr_value) == 1:
                        entry_dict[attr_name] = attr_value[0]
                    else:
                        entry_dict[attr_name] = attr_value
                entries.append(entry_dict)

            response = FlextLdapModels.SearchResponse(
                entries=entries,
                total_count=len(entries),
                result_code=0,
                result_description="Success",
                matched_dn="",
                next_cookie=None,
                entries_returned=len(entries),
                time_elapsed=0.0,
            )

            return FlextResult[FlextLdapModels.SearchResponse].ok(response)

        except Exception as e:
            self._logger.exception("Search failed")
            return FlextResult[FlextLdapModels.SearchResponse].fail(
                f"Search failed: {e}",
            )

    async def search_users(
        self,
        base_dn: str,
        uid: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
        """Search for users in LDAP directory.

        Args:
            base_dn: Base DN for search.
            uid: Optional UID filter.

        Returns:
            FlextResult containing list of users or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                    "No connection established",
                )

            # Build search filter
            if uid:
                search_filter = f"(&(objectClass=inetOrgPerson)(uid={uid}))"
            else:
                search_filter = "(objectClass=inetOrgPerson)"

            # Perform search
            self._connection.search(
                base_dn, search_filter, FlextLdapTypes.SUBTREE, attributes=["*"]
            )

            users = []
            for entry in self._connection.entries:
                user = self._create_user_from_entry(entry)
                users.append(user)

            return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)

        except Exception as e:
            self._logger.exception("User search failed")
            return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                f"User search failed: {e}",
            )

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for groups in LDAP directory.

        Args:
            base_dn: Base DN for search.
            cn: Optional CN filter.

        Returns:
            FlextResult containing list of groups or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    "No connection established",
                )

            # Build search filter
            if cn:
                search_filter = f"(&(objectClass=groupOfNames)(cn={cn}))"
            else:
                search_filter = "(objectClass=groupOfNames)"

            # Perform search
            self._connection.search(
                base_dn, search_filter, FlextLdapTypes.SUBTREE, attributes=["*"]
            )

            groups = []
            for entry in self._connection.entries:
                group = self._create_group_from_entry(entry)
                groups.append(group)

            return FlextResult[list[FlextLdapModels.Group]].ok(groups)

        except Exception as e:
            self._logger.exception("Group search failed")
            return FlextResult[list[FlextLdapModels.Group]].fail(
                f"Group search failed: {e}",
            )

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser | None]:
        """Get user by Distinguished Name.

        Args:
            dn: Distinguished Name of the user.

        Returns:
            FlextResult containing user or None if not found.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    "No connection established",
                )

            success = self._connection.search(
                dn,
                "(objectClass=*)",
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._logger.debug("Entry not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

                self._logger.warning("LDAP search failed for DN %s: %s", dn, error_msg)
                return FlextResult[FlextLdapModels.LdapUser | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._connection.entries:
                self._logger.debug("No entries found for DN: %s", dn)
                return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

            user = self._create_user_from_entry(self._connection.entries[0])
            return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

        except Exception as e:
            self._logger.exception("Get user failed for DN %s", dn)
            return FlextResult[FlextLdapModels.LdapUser | None].fail(
                f"Get user failed: {e}",
            )

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by Distinguished Name.

        Args:
            dn: Distinguished Name of the group.

        Returns:
            FlextResult containing group or None if not found.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.Group | None].fail(
                    "No connection established",
                )

            success = self._connection.search(
                dn,
                "(objectClass=*)",
                FlextLdapTypes.BASE,
                attributes=["*"],
            )

            if not success:
                error_msg = self._connection.last_error or "Unknown error"
                if "noSuchObject" in error_msg or "No such object" in error_msg:
                    self._logger.debug("Group not found for DN: %s", dn)
                    return FlextResult[FlextLdapModels.Group | None].ok(None)

                self._logger.warning("LDAP search failed for DN %s: %s", dn, error_msg)
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"LDAP search failed: {error_msg}",
                )

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.Group | None].ok(None)

            group = self._create_group_from_entry(self._connection.entries[0])
            return FlextResult[FlextLdapModels.Group | None].ok(group)

        except Exception as e:
            self._logger.exception("Get group failed")
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}",
            )

    async def create_user(
        self,
        request: FlextLdapModels.CreateUserRequest,
    ) -> FlextResult[FlextLdapModels.LdapUser]:
        """Create new user in LDAP directory.

        Args:
            request: User creation request.

        Returns:
            FlextResult containing created user or error.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "No connection established",
                )

            # Use the provided DN directly
            user_dn = request.dn

            # Build LDAP attributes
            ldap3_attributes: FlextLdapTypes.Attributes = {
                "objectClass": ["inetOrgPerson", "organizationalPerson", "person"],
                "uid": request.uid,
                "cn": request.cn,
                "sn": request.sn,
            }

            # Add optional attributes
            if request.given_name:
                ldap3_attributes["givenName"] = request.given_name
            if request.mail:
                ldap3_attributes["mail"] = request.mail
            if request.telephone_number:
                ldap3_attributes["telephoneNumber"] = request.telephone_number
            if request.department:
                ldap3_attributes["departmentNumber"] = request.department
            if request.title:
                ldap3_attributes["title"] = request.title
            if request.organization:
                ldap3_attributes["o"] = request.organization
            if request.user_password:
                ldap3_attributes["userPassword"] = request.user_password

            # Create user
            success = self._connection.add(
                dn=user_dn,
                attributes=ldap3_attributes,
            )

            if not success:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"Failed to create user: {self._connection.last_error}",
                )

            # Retrieve created user
            created_user_result = await self.get_user(user_dn)
            if created_user_result.is_failure:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "User created but failed to retrieve",
                )

            # We know the user exists since we just created it
            user = created_user_result.value
            if user is None:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "User created but returned None",
                )

            return FlextResult[FlextLdapModels.LdapUser].ok(user)

        except Exception as e:
            self._logger.exception("Create user failed")
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"Create user failed: {e}",
            )

    async def create_group(
        self,
        request: FlextLdapModels.CreateGroupRequest,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create new group in LDAP directory.

        Args:
            request: Group creation request.

        Returns:
            FlextResult containing created group or error.

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.Group].fail(
                    "No connection established",
                )

            # Use the provided DN directly
            group_dn = request.dn

            # Build LDAP attributes
            ldap3_attributes: FlextLdapTypes.Attributes = {
                "objectClass": ["groupOfNames"],
                "cn": request.cn,
                "member": "uid=placeholder,ou=users,dc=example,dc=com",  # Placeholder member
            }

            # Add optional attributes
            if request.description:
                ldap3_attributes["description"] = request.description

            # Create group
            success = self._connection.add(
                dn=group_dn,
                attributes=ldap3_attributes,
            )

            if not success:
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Failed to create group: {self._connection.last_error}",
                )

            # Retrieve created group
            created_group_result = await self.get_group(group_dn)
            if created_group_result.is_failure:
                return FlextResult[FlextLdapModels.Group].fail(
                    "Group created but failed to retrieve",
                )

            # We know the group exists since we just created it
            group = created_group_result.value
            if group is None:
                return FlextResult[FlextLdapModels.Group].fail(
                    "Group created but returned None",
                )

            return FlextResult[FlextLdapModels.Group].ok(group)

        except Exception as e:
            self._logger.exception("Create group failed")
            return FlextResult[FlextLdapModels.Group].fail(f"Create group failed: {e}")

    async def close_connection(self) -> FlextResult[None]:
        """Close LDAP connection.

        Returns:
            FlextResult indicating success or error.

        """
        return await self.unbind()

    async def update_group(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update group attributes (alias for update_group_attributes).

        Args:
            dn: Group Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating success or error.

        """
        return await self.update_group_attributes(dn, attributes)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group.

        Args:
            group_dn: Group Distinguished Name.
            member_dn: Member Distinguished Name to remove.

        Returns:
            FlextResult indicating success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            changes: dict[str, list[tuple[str, list[str]]]] = {
                "member": [(FlextLdapTypes.MODIFY_DELETE, [member_dn])],
            }
            success = self._connection.modify(
                group_dn,
                changes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to remove member: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Remove member failed")
            return FlextResult[None].fail(f"Remove member failed: {e}")

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get list of group members.

        Args:
            group_dn: Group Distinguished Name.

        Returns:
            FlextResult containing list of member DNs or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[str]].fail("No connection established")

            # Search for the group
            self._connection.search(
                group_dn,
                "(objectClass=*)",
                "FlextLdapTypes.BASE",
                attributes=["member"],
            )

            if not self._connection.entries:
                return FlextResult[list[str]].fail("Group not found")

            entry = self._connection.entries[0]
            members = []

            if hasattr(entry, "member"):
                member_attr = entry.member
                if hasattr(member_attr, "value"):
                    if isinstance(member_attr.value, list):
                        members = [str(m) for m in member_attr.value]
                    else:
                        members = [str(member_attr.value)]

            return FlextResult[list[str]].ok(members)

        except Exception as e:
            self._logger.exception("Get members failed")
            return FlextResult[list[str]].fail(f"Get members failed: {e}")

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists in LDAP directory.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult containing True if user exists, False otherwise.

        """
        try:
            result = await self.get_user(dn)
            if result.is_success:
                exists = result.unwrap() is not None
                return FlextResult[bool].ok(exists)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"User existence check failed: {e}")

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists in LDAP directory.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult containing True if group exists, False otherwise.

        """
        try:
            result = await self.get_group(dn)
            if result.is_success:
                exists = result.unwrap() is not None
                return FlextResult[bool].ok(exists)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"Group existence check failed: {e}")

    async def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        page_size: int = 0,
        paged_cookie: str | None = None,
    ) -> FlextResult[list[dict[str, object]]]:
        """Perform LDAP search operation.

        Args:
            base_dn: Base DN for search.
            filter_str: LDAP search filter.
            attributes: List of attributes to retrieve.
            page_size: Page size for paged search.
            paged_cookie: Cookie for paged search.

        Returns:
            FlextResult containing search results or error.

        """
        try:
            if not self._connection:
                return FlextResult[list[dict[str, object]]].fail(
                    "No connection established",
                )

            # Perform search
            success = self._connection.search(
                base_dn,
                filter_str,
                FlextLdapTypes.SUBTREE,
                attributes=attributes,
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
            )

            if not success:
                return FlextResult[list[dict[str, object]]].fail(
                    f"Search failed: {self._connection.last_error}",
                )

            # Convert entries to our format
            results: list[dict[str, object]] = []
            for entry in self._connection.entries:
                entry_dict: dict[str, object] = {"dn": str(entry.entry_dn)}
                for attr_name in entry.entry_attributes:
                    attr_value = entry[attr_name].value
                    if isinstance(attr_value, list) and len(attr_value) == 1:
                        entry_dict[attr_name] = attr_value[0]
                    else:
                        entry_dict[attr_name] = attr_value
                results.append(entry_dict)

            return FlextResult[list[dict[str, object]]].ok(results)

        except Exception as e:
            self._logger.exception("Search failed")
            return FlextResult[list[dict[str, object]]].fail(f"Search failed: {e}")

    async def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update user attributes.

        Args:
            dn: User Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating update success or error.

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Convert attributes to LDAP modification format
            ldap3_changes: FlextLdapTypes.ModifyChanges = {}
            for attr_name, attr_value in attributes.items():
                ldap3_changes[attr_name] = [
                    (FlextLdapTypes.MODIFY_REPLACE, [str(attr_value)])
                ]

            # Perform modification
            success = self._connection.modify(
                dn,
                ldap3_changes,
            )

            if not success:
                return FlextResult[bool].fail(
                    f"Failed to update user: {self._connection.last_error}",
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Update user failed")
            return FlextResult[bool].fail(f"Update user failed: {e}")

    async def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Update group attributes.

        Args:
            dn: Group Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating update success or error.

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Convert attributes to LDAP modification format
            changes: FlextLdapTypes.ModifyChanges = {}
            for attr_name, attr_value in attributes.items():
                changes[attr_name] = [
                    (FlextLdapTypes.MODIFY_REPLACE, [str(attr_value)])
                ]

            # Perform modification
            success = self._connection.modify(dn, changes)

            if not success:
                return FlextResult[bool].fail(
                    f"Failed to update group: {self._connection.last_error}",
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Update group failed")
            return FlextResult[bool].fail(f"Update group failed: {e}")

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user from LDAP directory.

        Args:
            dn: User Distinguished Name.

        Returns:
            FlextResult indicating deletion success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            success = self._connection.delete(dn)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to delete user: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Delete user failed")
            return FlextResult[None].fail(f"Delete user failed: {e}")

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group from LDAP directory.

        Args:
            dn: Group Distinguished Name.

        Returns:
            FlextResult indicating deletion success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            success = self._connection.delete(dn)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to delete group: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Delete group failed")
            return FlextResult[None].fail(f"Delete group failed: {e}")

    async def add(
        self,
        dn: str,
        attributes: dict[str, str | list[str]] | None = None,
    ) -> FlextResult[None]:
        """Add entry to LDAP directory (low-level operation).

        Args:
            dn: Distinguished Name of entry to add.
            attributes: LDAP attributes dictionary.

        Returns:
            FlextResult indicating add success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            success = self._connection.add(
                dn,
                attributes=attributes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to add entry: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Add entry failed")
            return FlextResult[None].fail(f"Add entry failed: {e}")

    async def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[None]:
        """Modify entry in LDAP directory (low-level operation).

        Args:
            dn: Distinguished Name of entry to modify.
            changes: Dictionary of attribute changes.

        Returns:
            FlextResult indicating modify success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            success = self._connection.modify(dn, changes)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to modify entry: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Modify entry failed")
            return FlextResult[None].fail(f"Modify entry failed: {e}")

    async def delete(self, dn: str) -> FlextResult[None]:
        """Delete entry from LDAP directory (low-level operation).

        Args:
            dn: Distinguished Name of entry to delete.

        Returns:
            FlextResult indicating delete success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            success = self._connection.delete(dn)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to delete entry: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Delete entry failed")
            return FlextResult[None].fail(f"Delete entry failed: {e}")

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group.

        Args:
            group_dn: Group Distinguished Name.
            member_dn: Member Distinguished Name to add.

        Returns:
            FlextResult indicating success or error.

        """
        try:
            if not self._connection:
                return FlextResult[None].fail("No connection established")

            changes: dict[str, list[tuple[str, list[str]]]] = {
                "member": [(FlextLdapTypes.MODIFY_ADD, [member_dn])],
            }
            success = self._connection.modify(
                group_dn,
                changes,
            )

            if not success:
                return FlextResult[None].fail(
                    f"Failed to add member: {self._connection.last_error}",
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            self._logger.exception("Add member failed")
            return FlextResult[None].fail(f"Add member failed: {e}")

    @property
    def session_id(self) -> str | None:
        """Get current session ID."""
        return self._session_id

    @session_id.setter
    def session_id(self, value: str | None) -> None:
        """Set session ID."""
        self._session_id = value

    def _create_user_from_entry(
        self, entry: FlextLdapTypes.Entry
    ) -> FlextLdapModels.LdapUser:
        """Create LdapUser from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            LdapUser object.

        """

        def get_attribute_value(attr_name: str) -> str | None:
            """Safely get attribute value from entry."""
            try:
                # Try to access the attribute directly
                if hasattr(entry, attr_name):
                    attr = getattr(entry, attr_name)
                    if hasattr(attr, "value"):
                        value = attr.value
                        if isinstance(value, list) and value:
                            return str(value[0])
                        if isinstance(value, str) and value:
                            return value
                return None
            except (AttributeError, TypeError, KeyError):
                return None

        cn = get_attribute_value("cn")
        if not cn:
            cn = (
                entry.entry_dn.split(",")[0].split("=")[1]
                if "=" in entry.entry_dn
                else "Unknown"
            )

        return FlextLdapModels.LdapUser(
            dn=str(entry.entry_dn),
            cn=cn,
            uid=get_attribute_value("uid"),
            sn=get_attribute_value("sn"),
            given_name=get_attribute_value("givenName"),
            mail=get_attribute_value("mail"),
            telephone_number=get_attribute_value("telephoneNumber"),
            mobile=get_attribute_value("mobile"),
            department=get_attribute_value("departmentNumber"),
            title=get_attribute_value("title"),
            organization=get_attribute_value("o"),
            organizational_unit=get_attribute_value("ou"),
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

    def _create_group_from_entry(
        self, entry: FlextLdapTypes.Entry
    ) -> FlextLdapModels.Group:
        """Create Group from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            Group object.

        """

        def get_attribute_value(attr_name: str) -> str | None:
            """Safely get attribute value from entry."""
            try:
                # Try to access the attribute directly
                if hasattr(entry, attr_name):
                    attr = getattr(entry, attr_name)
                    if hasattr(attr, "value"):
                        value = attr.value
                        if isinstance(value, list) and value:
                            return str(value[0])
                        if isinstance(value, str) and value:
                            return value
                return None
            except (AttributeError, TypeError, KeyError):
                return None

        def get_int_attribute_value(attr_name: str) -> int | None:
            """Safely get integer attribute value from entry."""
            try:
                # Try to access the attribute directly
                value: object = None
                if hasattr(entry, attr_name):
                    attr = getattr(entry, attr_name)
                    if hasattr(attr, "value"):
                        value = attr.value
                        if isinstance(value, list) and value:
                            return int(value[0])
                    if isinstance(value, str) and value:
                        return int(value)
                return None
            except (AttributeError, TypeError, ValueError, KeyError):
                return None

        return FlextLdapModels.Group(
            dn=str(entry.entry_dn),
            cn=get_attribute_value("cn") or "",
            gid_number=get_int_attribute_value("gidNumber"),
            description=get_attribute_value("description"),
            created_timestamp=None,
            modified_timestamp=None,
        )

    # =========================================================================
    # UNIVERSAL GENERIC METHODS - Complete LDAP compatibility
    # =========================================================================

    async def search_universal(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
        size_limit: int = 0,
        time_limit: int = 0,  # noqa: ARG002
        deref_aliases: str = "deref_always",  # noqa: ARG002
        *, types_only: bool = False,  # noqa: ARG002
        controls: list | None = None,  # noqa: ARG002
    ) -> FlextResult[list[dict[str, object]]]:
        """Universal search that adapts to any LDAP server.

        Args:
            base_dn: Base DN for search
            search_filter: LDAP search filter
            attributes: Attributes to return (None for all)
            scope: Search scope (base, onelevel, subtree, children)
            size_limit: Maximum number of entries to return
            time_limit: Maximum time for search
            deref_aliases: How to dereference aliases
            types_only: Return only attribute types, not values
            controls: LDAP controls to use

        Returns:
            FlextResult[list[dict[str, object]]]: Search results

        """
        try:
            if not self._connection:
                return FlextResult[list[dict[str, object]]].fail(
                    "No connection established"
                )

            # Normalize inputs according to server quirks
            normalized_base_dn = self.normalize_dn(base_dn)
            normalized_filter = self._normalize_filter(search_filter)
            normalized_attributes = (
                self._normalize_attributes(attributes) if attributes else None
            )

            # Apply server-specific search limitations
            if self._server_quirks:
                if scope in self._server_quirks.search_scope_limitations:
                    self._logger.warning(
                        "Search scope %s not supported by server", scope
                    )
                    scope = "subtree"  # Fallback to subtree

                if size_limit > self._server_quirks.max_page_size:
                    self._logger.warning(
                        "Size limit %d exceeds server max %d",
                        size_limit,
                        self._server_quirks.max_page_size,
                    )
                    size_limit = self._server_quirks.max_page_size

            # Perform search using base client
            search_result = await self.search(
                base_dn=normalized_base_dn,
                filter_str=normalized_filter,
                attributes=normalized_attributes,
                page_size=max(0, size_limit),
            )

            if search_result.is_success:
                # Normalize results according to server quirks
                normalized_results = self._normalize_search_results(search_result.value)
                return FlextResult[list[dict[str, object]]].ok(normalized_results)

            return search_result

        except Exception as e:
            self._logger.exception("Universal search failed")
            return FlextResult[list[dict[str, object]]].fail(f"Search failed: {e}")

    async def add_entry_universal(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        *, controls: list | None = None,  # noqa: ARG002
    ) -> FlextResult[bool]:
        """Universal add entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Normalize inputs
            normalized_dn = self.normalize_dn(dn)
            normalized_attributes = self._normalize_entry_attributes(attributes)

            # Perform add using base client
            return await self.add_entry(normalized_dn, normalized_attributes)

        except Exception as e:
            self._logger.exception("Universal add entry failed")
            return FlextResult[bool].fail(f"Add entry failed: {e}")

    async def modify_entry_universal(
        self,
        dn: str,
        changes: dict[str, Any],
        *, controls: list | None = None,  # noqa: ARG002
    ) -> FlextResult[bool]:
        """Universal modify entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            changes: Modification changes
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Normalize inputs
            normalized_dn = self.normalize_dn(dn)
            normalized_changes = self._normalize_modify_changes(changes)

            # Perform modify using base client
            return await self.modify_entry(normalized_dn, normalized_changes)

        except Exception as e:
            self._logger.exception("Universal modify entry failed")
            return FlextResult[bool].fail(f"Modify entry failed: {e}")

    async def delete_entry_universal(
        self,
        dn: str,
        *, controls: list | None = None,  # noqa: ARG002
    ) -> FlextResult[bool]:
        """Universal delete entry that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            controls: LDAP controls to use

        Returns:
            FlextResult[bool]: Success result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Normalize DN
            normalized_dn = self.normalize_dn(dn)

            # Perform delete using base client
            return await self.delete_entry(normalized_dn)

        except Exception as e:
            self._logger.exception("Universal delete entry failed")
            return FlextResult[bool].fail(f"Delete entry failed: {e}")

    async def compare_universal(
        self,
        dn: str,
        attribute: str,
        value: str,
    ) -> FlextResult[bool]:
        """Universal compare operation that adapts to any LDAP server.

        Args:
            dn: Distinguished Name for the entry
            attribute: Attribute to compare
            value: Value to compare against

        Returns:
            FlextResult[bool]: Comparison result

        """
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Normalize inputs
            normalized_dn = self.normalize_dn(dn)
            normalized_attribute = self.normalize_attribute_name(attribute)

            # Perform compare
            success = self._connection.compare(
                normalized_dn, normalized_attribute, value
            )

            if success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(
                f"Compare failed: {self._connection.last_error}"
            )

        except Exception as e:
            self._logger.exception("Universal compare failed")
            return FlextResult[bool].fail(f"Compare failed: {e}")

    async def extended_operation_universal(
        self,
        request_name: str,
        request_value: str | None = None,
        *, controls: list | None = None,  # noqa: ARG002
    ) -> FlextResult[dict[str, Any]]:
        """Universal extended operation that adapts to any LDAP server.

        Args:
            request_name: Name of the extended operation
            request_value: Value for the operation
            controls: LDAP controls to use

        Returns:
            FlextResult[dict[str, Any]]: Operation result

        """
        try:
            if not self._connection:
                return FlextResult[dict[str, Any]].fail("No connection established")

            # Perform extended operation
            success = self._connection.extended(request_name, request_value)

            if success:
                result = {
                    "request_name": request_name,
                    "request_value": request_value,
                    "response_name": getattr(self._connection, "response_name", None),
                    "response_value": getattr(self._connection, "response_value", None),
                }
                return FlextResult[dict[str, Any]].ok(result)
            return FlextResult[dict[str, Any]].fail(
                f"Extended operation failed: {self._connection.last_error}"
            )

        except Exception as e:
            self._logger.exception("Universal extended operation failed")
            return FlextResult[dict[str, Any]].fail(f"Extended operation failed: {e}")

    async def search_with_controls_universal(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
        controls: list | None = None,
    ) -> FlextResult[list[dict[str, object]]]:
        """Universal search with LDAP controls that adapts to any server.

        Args:
            base_dn: Base DN for search
            search_filter: LDAP search filter
            attributes: Attributes to return
            scope: Search scope
            controls: LDAP controls to use

        Returns:
            FlextResult[list[dict[str, object]]]: Search results

        """
        try:
            if not self._connection:
                return FlextResult[list[dict[str, object]]].fail(
                    "No connection established"
                )

            # Normalize inputs
            normalized_base_dn = self.normalize_dn(base_dn)
            normalized_filter = self._normalize_filter(search_filter)
            normalized_attributes = (
                self._normalize_attributes(attributes) if attributes else None
            )

            # Perform search with controls
            success = self._connection.search(
                normalized_base_dn,
                normalized_filter,
                scope,
                attributes=normalized_attributes,
                controls=controls,
            )

            if not success:
                return FlextResult[list[dict[str, object]]].fail(
                    f"Search failed: {self._connection.last_error}"
                )

            # Convert entries to our format
            results: list[dict[str, object]] = []
            for entry in self._connection.entries:
                entry_dict: dict[str, object] = {"dn": str(entry.entry_dn)}
                for attr_name in entry.entry_attributes:
                    attr_value = entry[attr_name].value
                    if isinstance(attr_value, list) and len(attr_value) == 1:
                        entry_dict[attr_name] = attr_value[0]
                    else:
                        entry_dict[attr_name] = attr_value
                results.append(entry_dict)

            # Normalize results
            normalized_results = self._normalize_search_results(results)
            return FlextResult[list[dict[str, object]]].ok(normalized_results)

        except Exception as e:
            self._logger.exception("Universal search with controls failed")
            return FlextResult[list[dict[str, object]]].fail(f"Search failed: {e}")

    def get_server_capabilities(self) -> dict[str, Any]:
        """Get comprehensive server capabilities and information.

        Returns:
            dict[str, Any]: Server capabilities

        """
        capabilities = {
            "connected": self.is_connected(),
            "schema_discovered": self.is_schema_discovered(),
            "server_info": self.get_server_info(),
            "server_type": self.get_server_type(),
            "server_quirks": self.get_server_quirks(),
        }

        if self._discovered_schema:
            capabilities.update({
                "naming_contexts": self._discovered_schema.naming_contexts,
                "supported_controls": self._discovered_schema.supported_controls,
                "supported_extensions": self._discovered_schema.supported_extensions,
                "discovered_attributes": len(self._discovered_schema.attributes),
                "discovered_object_classes": len(
                    self._discovered_schema.object_classes
                ),
            })

        return capabilities

    def _normalize_filter(self, search_filter: str) -> str:
        """Normalize search filter according to server quirks."""
        if not self._server_quirks:
            return search_filter

        # Apply filter syntax quirks
        normalized_filter = search_filter

        if "case_insensitive" in self._server_quirks.filter_syntax_quirks:
            # Make filter case-insensitive by converting to lowercase
            # This is a simple approach - more sophisticated normalization could be added
            normalized_filter = search_filter.lower()

        return normalized_filter

    def _normalize_attributes(self, attributes: list[str]) -> list[str]:
        """Normalize attribute names according to server quirks."""
        if not self._server_quirks or not self._schema_discovery:
            return attributes

        return [self.normalize_attribute_name(attr) for attr in attributes]

    def _normalize_entry_attributes(
        self, attributes: dict[str, str | list[str]]
    ) -> dict[str, str | list[str]]:
        """Normalize entry attributes according to server quirks."""
        if not self._server_quirks or not self._schema_discovery:
            return attributes

        normalized = {}
        for attr_name, attr_value in attributes.items():
            normalized_name = self.normalize_attribute_name(attr_name)
            normalized[normalized_name] = attr_value

        return normalized

    def _normalize_modify_changes(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Normalize modify changes according to server quirks."""
        if not self._server_quirks or not self._schema_discovery:
            return changes

        normalized = {}
        for attr_name, change_value in changes.items():
            normalized_name = self.normalize_attribute_name(attr_name)
            normalized[normalized_name] = change_value

        return normalized

    def _normalize_search_results(
        self, results: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Normalize search results according to server quirks."""
        if not self._server_quirks or not self._schema_discovery:
            return results

        normalized_results = []
        for result in results:
            normalized_result = {}

            # Normalize DN
            if "dn" in result:
                normalized_result["dn"] = self.normalize_dn(str(result["dn"]))

            # Normalize attributes
            if "attributes" in result:
                normalized_attributes = {}
                for attr_name, attr_value in result["attributes"].items():
                    normalized_name = self.normalize_attribute_name(attr_name)
                    normalized_attributes[normalized_name] = attr_value
                normalized_result["attributes"] = normalized_attributes
            else:
                # Handle flat result format
                for key, value in result.items():
                    if key != "dn":
                        normalized_name = self.normalize_attribute_name(key)
                        normalized_result[normalized_name] = value
                    else:
                        normalized_result[key] = self.normalize_dn(str(value))

            normalized_results.append(normalized_result)

        return normalized_results

    @property
    def _server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
        """Get server quirks from discovered schema."""
        if self._discovered_schema:
            return self._discovered_schema.server_quirks
        return None

    # =========================================================================
    # SCHEMA DISCOVERY METHODS - Universal compatibility features
    # =========================================================================

    async def discover_schema(
        self,
    ) -> FlextResult[FlextLdapModels.SchemaDiscoveryResult]:
        """Discover LDAP server schema and capabilities.

        Returns:
            FlextResult[FlextLdapModels.SchemaDiscoveryResult]: Schema discovery result

        """
        try:
            if not self._connection:
                return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                    "No connection established"
                )

            self._schema_discovery = FlextLdapSchema.Discovery(self._connection)
            discovery_result = await self._schema_discovery.discover_schema()

            if discovery_result.is_success:
                self._discovered_schema = discovery_result.value
                self._is_schema_discovered = True
                self._logger.info("Schema discovery completed successfully")

            return discovery_result

        except Exception as e:
            self._logger.exception("Schema discovery failed")
            return FlextResult[FlextLdapModels.SchemaDiscoveryResult].fail(
                f"Schema discovery failed: {e}"
            )

    def get_server_info(self) -> dict | None:
        """Get discovered server information.

        Returns:
            dict | None: Server information or None if not discovered

        """
        if self._discovered_schema:
            return self._discovered_schema.server_info
        return None

    def get_server_type(self) -> str | None:
        """Get detected server type.

        Returns:
            str | None: Server type or None if not discovered

        """
        if self._discovered_schema:
            return self._discovered_schema.server_type.value
        return None

    def get_server_quirks(self) -> FlextLdapModels.ServerQuirks | None:
        """Get discovered server quirks.

        Returns:
            FlextLdapModels.ServerQuirks | None: Server quirks or None if not discovered

        """
        if self._discovered_schema:
            return self._discovered_schema.server_quirks
        return None

    def is_schema_discovered(self) -> bool:
        """Check if schema has been discovered.

        Returns:
            bool: True if schema has been discovered

        """
        return self._is_schema_discovered

    def normalize_attribute_name(self, attribute_name: str) -> str:
        """Normalize attribute name according to server quirks.

        Args:
            attribute_name: Attribute name to normalize

        Returns:
            str: Normalized attribute name

        """
        if self._schema_discovery:
            return self._schema_discovery.normalize_attribute_name(attribute_name)
        return attribute_name

    def normalize_object_class(self, object_class: str) -> str:
        """Normalize object class name according to server quirks.

        Args:
            object_class: Object class name to normalize

        Returns:
            str: Normalized object class name

        """
        if self._schema_discovery:
            return self._schema_discovery.normalize_object_class(object_class)
        return object_class

    def normalize_dn(self, dn: str) -> str:
        """Normalize DN according to server quirks.

        Args:
            dn: DN to normalize

        Returns:
            str: Normalized DN

        """
        if self._schema_discovery:
            return self._schema_discovery.normalize_dn(dn)
        return dn


__all__ = [
    "FlextLdapClient",
]


__all__ = [
    "FlextLdapClient",
]


__all__ = [
    "FlextLdapClient",
]
