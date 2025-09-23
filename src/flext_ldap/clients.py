"""LDAP client implementation for flext-ldap.

This module provides the core LDAP client functionality using ldap3
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from collections.abc import Mapping
from typing import cast

from ldap3 import BASE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
from ldap3.core.connection import Connection
from ldap3.core.server import Server

from flext_core import FlextLogger, FlextResult
from flext_ldap.ldap3_types import (
    Ldap3Attributes,
    Ldap3Connection,
    Ldap3Entry,
    Ldap3ModifyChanges,
)
from flext_ldap.models import FlextLdapModels


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
        self._connection: Ldap3Connection | None = None
        self._server: Server | None = None
        self._logger = FlextLogger(__name__)
        self._config = config
        self._container_manager = None  # Placeholder for container management
        self._session_id: str | None = None

    async def connect(
        self, server_uri: str, bind_dn: str, password: str
    ) -> FlextResult[bool]:
        """Connect and bind to LDAP server.

        Args:
            server_uri: LDAP server URI (e.g., 'ldap://localhost:389').
            bind_dn: Distinguished Name for binding.
            password: Password for binding.

        Returns:
            FlextResult[bool]: Success result or error.

        """
        try:
            self._logger.info(f"Connecting to LDAP server: {server_uri}")
            self._server = Server(server_uri)
            self._connection = cast(
                "Ldap3Connection",
                Connection(self._server, bind_dn, password, auto_bind=True),
            )

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            self._logger.info("Successfully connected to LDAP server")
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
            self._connection = cast(
                "Ldap3Connection",
                Connection(self._server, bind_dn, password, auto_bind=True),
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
            FlextResult[bool]: Connection test result.

        """
        if not self.is_connected():
            return FlextResult[bool].fail("Not connected to LDAP server")

        try:
            # Perform a simple search to test the connection
            if self._connection:
                self._connection.search(
                    "", "(objectClass=*)", "SUBTREE", attributes=["objectClass"]
                )
            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Connection test failed: {e}")

    async def authenticate_user(
        self, username: str, password: str
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
                    "No connection established"
                )

            # Search for user by username (uid or cn)
            search_filter = f"(|(uid={username})(cn={username}))"
            search_base = "ou=users,dc=example,dc=com"  # Default base

            self._connection.search(
                search_base, search_filter, "SUBTREE", attributes=None
            )

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.LdapUser].fail("User not found")

            user_entry = self._connection.entries[0]
            user_dn = str(user_entry.entry_dn)

            # Test authentication by attempting to bind with user credentials
            if not self._server:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "No server connection established"
                )
            test_connection = Connection(
                self._server, user_dn, password, auto_bind=False
            )

            if not test_connection.bind():
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "Authentication failed"
                )

            test_connection.unbind()  # type: ignore[no-untyped-call]

            # Create user object from LDAP entry
            user = self._create_user_from_entry(user_entry)
            return FlextResult[FlextLdapModels.LdapUser].ok(user)

        except Exception as e:
            self._logger.exception("Authentication failed")
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"Authentication failed: {e}"
            )

    async def search_with_request(
        self, request: FlextLdapModels.SearchRequest
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
                    "No connection established"
                )

            # Convert scope string to ldap3 scope
            scope_map: dict[str, str] = {
                "base": "BASE",
                "onelevel": "LEVEL",
                "subtree": "SUBTREE",
            }
            ldap3_scope = scope_map.get(request.scope, "SUBTREE")

            # Perform search
            success = self._connection.search(
                request.base_dn,
                request.filter_str,
                ldap3_scope,
                attributes=request.attributes,
            )

            if not success:
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    "Search operation failed"
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
                f"Search failed: {e}"
            )

    async def search_users(
        self, base_dn: str, uid: str | None = None
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
                    "No connection established"
                )

            # Build search filter
            if uid:
                search_filter = f"(&(objectClass=inetOrgPerson)(uid={uid}))"
            else:
                search_filter = "(objectClass=inetOrgPerson)"

            # Perform search
            self._connection.search(base_dn, search_filter, SUBTREE, attributes=None)

            users = []
            for entry in self._connection.entries:
                user = self._create_user_from_entry(entry)
                users.append(user)

            return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)

        except Exception as e:
            self._logger.exception("User search failed")
            return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                f"User search failed: {e}"
            )

    async def search_groups(
        self, base_dn: str, cn: str | None = None
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
                    "No connection established"
                )

            # Build search filter
            if cn:
                search_filter = f"(&(objectClass=groupOfNames)(cn={cn}))"
            else:
                search_filter = "(objectClass=groupOfNames)"

            # Perform search
            self._connection.search(base_dn, search_filter, SUBTREE, attributes=None)

            groups = []
            for entry in self._connection.entries:
                group = self._create_group_from_entry(entry)
                groups.append(group)

            return FlextResult[list[FlextLdapModels.Group]].ok(groups)

        except Exception as e:
            self._logger.exception("Group search failed")
            return FlextResult[list[FlextLdapModels.Group]].fail(
                f"Group search failed: {e}"
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
                    "No connection established"
                )

            # Search for the specific user by DN
            self._connection.search(dn, "(objectClass=*)", BASE, attributes=None)

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.LdapUser | None].ok(None)

            user = self._create_user_from_entry(self._connection.entries[0])
            return FlextResult[FlextLdapModels.LdapUser | None].ok(user)

        except Exception as e:
            self._logger.exception("Get user failed")
            return FlextResult[FlextLdapModels.LdapUser | None].fail(
                f"Get user failed: {e}"
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
                    "No connection established"
                )

            # Search for the specific group by DN
            self._connection.search(dn, "(objectClass=*)", BASE, attributes=None)

            if not self._connection.entries:
                return FlextResult[FlextLdapModels.Group | None].ok(None)

            group = self._create_group_from_entry(self._connection.entries[0])
            return FlextResult[FlextLdapModels.Group | None].ok(group)

        except Exception as e:
            self._logger.exception("Get group failed")
            return FlextResult[FlextLdapModels.Group | None].fail(
                f"Get group failed: {e}"
            )

    async def create_user(
        self, request: FlextLdapModels.CreateUserRequest
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
                    "No connection established"
                )

            # Use the provided DN directly
            user_dn = request.dn

            # Build LDAP attributes
            ldap3_attributes: Ldap3Attributes = {
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
            success = self._connection.add(dn=user_dn, attributes=ldap3_attributes)

            if not success:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"Failed to create user: {self._connection.last_error}"
                )

            # Retrieve created user
            created_user_result = await self.get_user(user_dn)
            if created_user_result.is_failure or not created_user_result.value:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    "User created but failed to retrieve"
                )

            return FlextResult[FlextLdapModels.LdapUser].ok(created_user_result.value)

        except Exception as e:
            self._logger.exception("Create user failed")
            return FlextResult[FlextLdapModels.LdapUser].fail(
                f"Create user failed: {e}"
            )

    async def create_group(
        self, request: FlextLdapModels.CreateGroupRequest
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
                    "No connection established"
                )

            # Use the provided DN directly
            group_dn = request.dn

            # Build LDAP attributes
            ldap3_attributes: Ldap3Attributes = {
                "objectClass": ["groupOfNames"],
                "cn": request.cn,
                "member": "uid=placeholder,ou=users,dc=example,dc=com",  # Placeholder member
            }

            # Add optional attributes
            if request.description:
                ldap3_attributes["description"] = request.description

            # Create group
            success = self._connection.add(dn=group_dn, attributes=ldap3_attributes)

            if not success:
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Failed to create group: {self._connection.last_error}"
                )

            # Retrieve created group
            created_group_result = await self.get_group(group_dn)
            if created_group_result.is_failure or not created_group_result.value:
                return FlextResult[FlextLdapModels.Group].fail(
                    "Group created but failed to retrieve"
                )

            return FlextResult[FlextLdapModels.Group].ok(created_group_result.value)

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
        self, dn: str, attributes: dict[str, object]
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
                "member": [(MODIFY_DELETE, [member_dn])]
            }
            success = self._connection.modify(group_dn, changes)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to remove member: {self._connection.last_error}"
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
                group_dn, "(objectClass=*)", "BASE", attributes=["member"]
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

    def validate_dn(self, dn: str) -> FlextResult[bool]:
        """Validate Distinguished Name format.

        Args:
            dn: Distinguished Name to validate.

        Returns:
            FlextResult indicating validation success or error.

        """
        try:
            if not dn or not isinstance(dn, str):
                return FlextResult[bool].fail("DN must be a non-empty string")

            # Basic DN validation - check for common patterns
            if not dn.strip():
                return FlextResult[bool].fail("DN cannot be empty or whitespace")

            # Check for basic DN structure (attribute=value,attribute=value)
            if "=" not in dn:
                return FlextResult[bool].fail("DN must contain attribute=value pairs")

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"DN validation failed: {e}")

    def validate_filter(self, filter_str: str) -> FlextResult[bool]:
        """Validate LDAP search filter format.

        Args:
            filter_str: LDAP filter string to validate.

        Returns:
            FlextResult indicating validation success or error.

        """
        try:
            if not filter_str or not isinstance(filter_str, str):
                return FlextResult[bool].fail("Filter must be a non-empty string")

            # Basic filter validation
            if not filter_str.strip():
                return FlextResult[bool].fail("Filter cannot be empty or whitespace")

            # Check for balanced parentheses
            if filter_str.count("(") != filter_str.count(")"):
                return FlextResult[bool].fail("Filter has unbalanced parentheses")

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Filter validation failed: {e}")

    def validate_attributes(self, attributes: list[str]) -> FlextResult[bool]:
        """Validate LDAP attribute names.

        Args:
            attributes: List of attribute names to validate.

        Returns:
            FlextResult indicating validation success or error.

        """
        try:
            for attr in attributes:
                if not isinstance(attr, str) or not attr.strip():
                    return FlextResult[bool].fail(f"Invalid attribute name: {attr}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Attribute validation failed: {e}")

    def validate_object_classes(self, object_classes: list[str]) -> FlextResult[bool]:
        """Validate LDAP object class names.

        Args:
            object_classes: List of object class names to validate.

        Returns:
            FlextResult indicating validation success or error.

        """
        try:
            for oc in object_classes:
                if not isinstance(oc, str) or not oc.strip():
                    return FlextResult[bool].fail(f"Invalid object class name: {oc}")

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Object class validation failed: {e}")

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
                exists = result.value is not None
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
                exists = result.value is not None
                return FlextResult[bool].ok(exists)
            return FlextResult[bool].ok(False)

        except Exception as e:
            return FlextResult[bool].fail(f"Group existence check failed: {e}")

    async def add_member_to_group(
        self, group_dn: str, member_dn: str
    ) -> FlextResult[None]:
        """Add member to group (alias for add_member).

        Args:
            group_dn: Group Distinguished Name.
            member_dn: Member Distinguished Name to add.

        Returns:
            FlextResult indicating success or error.

        """
        return await self.add_member(group_dn, member_dn)

    async def remove_member_from_group(
        self, group_dn: str, member_dn: str
    ) -> FlextResult[None]:
        """Remove member from group (alias for remove_member).

        Args:
            group_dn: Group Distinguished Name.
            member_dn: Member Distinguished Name to remove.

        Returns:
            FlextResult indicating success or error.

        """
        return await self.remove_member(group_dn, member_dn)

    async def get_group_members_list(self, group_dn: str) -> FlextResult[list[str]]:
        """Get list of group members (alias for get_members).

        Args:
            group_dn: Group Distinguished Name.

        Returns:
            FlextResult containing list of member DNs or error.

        """
        return await self.get_members(group_dn)

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
                    "No connection established"
                )

            # Perform search
            success = self._connection.search(
                base_dn,
                filter_str,
                "SUBTREE",
                attributes=attributes,
                paged_size=page_size if page_size > 0 else None,
                paged_cookie=paged_cookie,
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

            return FlextResult[list[dict[str, object]]].ok(results)

        except Exception as e:
            self._logger.exception("Search failed")
            return FlextResult[list[dict[str, object]]].fail(f"Search failed: {e}")

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server (alias for unbind).

        Returns:
            FlextResult indicating success or error.

        """
        return await self.unbind()

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
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Convert attributes to LDAP modification format
            ldap3_changes: Ldap3ModifyChanges = {}
            for attr_name, attr_value in attributes.items():
                ldap3_changes[attr_name] = [(MODIFY_REPLACE, [str(attr_value)])]

            # Perform modification
            success = self._connection.modify(dn, ldap3_changes)

            if not success:
                return FlextResult[bool].fail(
                    f"Failed to update user: {self._connection.last_error}"
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            self._logger.exception("Update user failed")
            return FlextResult[bool].fail(f"Update user failed: {e}")

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
        try:
            if not self._connection:
                return FlextResult[bool].fail("No connection established")

            # Convert attributes to LDAP modification format
            changes: Ldap3ModifyChanges = {}
            for attr_name, attr_value in attributes.items():
                changes[attr_name] = [(MODIFY_REPLACE, [str(attr_value)])]

            # Perform modification
            success = self._connection.modify(dn, changes)

            if not success:
                return FlextResult[bool].fail(
                    f"Failed to update group: {self._connection.last_error}"
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
                    f"Failed to delete user: {self._connection.last_error}"
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
                    f"Failed to delete group: {self._connection.last_error}"
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

            success = self._connection.add(dn, attributes=attributes)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to add entry: {self._connection.last_error}"
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
                    f"Failed to modify entry: {self._connection.last_error}"
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
                    f"Failed to delete entry: {self._connection.last_error}"
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
                "member": [(MODIFY_ADD, [member_dn])]
            }
            success = self._connection.modify(group_dn, changes)

            if not success:
                return FlextResult[None].fail(
                    f"Failed to add member: {self._connection.last_error}"
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

    async def update_user(
        self,
        dn: str,
        attributes: Mapping[str, object] | dict[str, object],
    ) -> FlextResult[None]:
        """Update user attributes (alias for modify).

        Args:
            dn: User Distinguished Name.
            attributes: Attributes to update.

        Returns:
            FlextResult indicating success or error.

        """
        # Convert attributes to modify format
        changes: dict[str, list[tuple[str, list[str]]]] = {}
        for attr_name, attr_value in attributes.items():
            if isinstance(attr_value, (str, list)):
                changes[attr_name] = [
                    (
                        MODIFY_REPLACE,
                        [str(attr_value)]
                        if isinstance(attr_value, str)
                        else [str(v) for v in attr_value],
                    )
                ]
            else:
                changes[attr_name] = [(MODIFY_REPLACE, [str(attr_value)])]

        return await self.modify(dn, changes)

    def _create_user_from_entry(self, entry: Ldap3Entry) -> FlextLdapModels.LdapUser:
        """Create LdapUser from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            LdapUser object.

        """

        def get_attribute_value(attr_name: str) -> str | None:
            """Safely get attribute value from entry."""
            try:
                if hasattr(entry, attr_name):
                    attr_obj = getattr(entry, attr_name)
                    if hasattr(attr_obj, "value") and attr_obj.value:
                        return str(attr_obj.value)
                return None
            except (AttributeError, TypeError):
                return None

        return FlextLdapModels.LdapUser(
            dn=str(entry.entry_dn),
            cn=get_attribute_value("cn") or "",
            uid=get_attribute_value("uid") or "",
            sn=get_attribute_value("sn") or "",
            given_name=get_attribute_value("givenName"),
            mail=get_attribute_value("mail"),
            telephone_number=get_attribute_value("telephoneNumber"),
            mobile=get_attribute_value("mobile"),
            department=get_attribute_value("departmentNumber"),
            title=get_attribute_value("title"),
            organization=get_attribute_value("o"),
            organizational_unit=get_attribute_value("ou"),
            user_password=None,  # Never expose password
            created_timestamp=None,  # Not available in basic LDAP
            modified_timestamp=None,  # Not available in basic LDAP
        )

    def _create_group_from_entry(self, entry: Ldap3Entry) -> FlextLdapModels.Group:
        """Create Group from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            Group object.

        """

        def get_attribute_value(attr_name: str) -> str | None:
            """Safely get attribute value from entry."""
            try:
                if hasattr(entry, attr_name):
                    attr_obj = getattr(entry, attr_name)
                    if hasattr(attr_obj, "value") and attr_obj.value:
                        return str(attr_obj.value)
                return None
            except (AttributeError, TypeError):
                return None

        def get_int_attribute_value(attr_name: str) -> int | None:
            """Safely get integer attribute value from entry."""
            try:
                if hasattr(entry, attr_name):
                    attr_obj = getattr(entry, attr_name)
                    if hasattr(attr_obj, "value") and attr_obj.value:
                        return int(attr_obj.value)
                return None
            except (AttributeError, TypeError, ValueError):
                return None

        return FlextLdapModels.Group(
            dn=str(entry.entry_dn),
            cn=get_attribute_value("cn") or "",
            gid_number=get_int_attribute_value("gidNumber"),
            description=get_attribute_value("description"),
            created_timestamp=None,  # Not available in basic LDAP
            modified_timestamp=None,  # Not available in basic LDAP
        )


__all__ = [
    "FlextLdapClient",
]


__all__ = [
    "FlextLdapClient",
]


__all__ = [
    "FlextLdapClient",
]
