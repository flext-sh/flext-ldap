"""LDAP client implementation for flext-ldap.

This module provides the core LDAP client functionality using ldap3
with Clean Architecture patterns and flext-core integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ldap3.abstract.entry import Entry

from ldap3 import ALL_ATTRIBUTES, BASE, LEVEL, MODIFY_REPLACE, SUBTREE
from ldap3.core.connection import Connection
from ldap3.core.server import Server

from flext_core import FlextLogger, FlextResult
from flext_ldap.models import FlextLdapModels

# from flext_ldap.protocols import FlextLdapProtocols  # Removed - consolidated
# from flext_ldap.typings import FlextLdapTypes  # Removed - consolidated

# LDAPSearchStrategies ELIMINATED - consolidated into FlextLdapClient nested classes
# Following flext-core consolidation pattern: ALL functionality within single class


class FlextLdapClient:
    """FlextLdapClient - Main LDAP client using ldap3 library.

    This class provides a comprehensive interface for LDAP operations including
    connection management, authentication, search, and CRUD operations.
    It uses the ldap3 library internally and provides a FlextResult-based API.

    The client supports both synchronous and asynchronous operations, with
    automatic connection management and proper error handling.
    """

    def __init__(self) -> None:
        """Initialize FlextLdapClient."""
        self._connection: Connection | None = None
        self._server: Server | None = None
        self._logger = FlextLogger(__name__)

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
            self._connection = Connection(
                self._server, bind_dn, password, auto_bind=True
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
            self._connection = Connection(
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
            FlextResult[bool]: Connection test result.

        """
        if not self.is_connected():
            return FlextResult[bool].fail("Not connected to LDAP server")

        try:
            # Perform a simple search to test the connection
            if self._connection:
                self._connection.search(
                    "", "(objectClass=*)", SUBTREE, attributes=["objectClass"]
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
                search_base, search_filter, SUBTREE, attributes=ALL_ATTRIBUTES
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

            test_connection.unbind()

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
            scope_map = {
                "base": BASE,
                "onelevel": LEVEL,
                "subtree": SUBTREE,
            }
            ldap3_scope = scope_map.get(request.scope, SUBTREE)

            # Perform search
            success = self._connection.search(
                request.base_dn,
                request.filter_str,
                ldap3_scope,
                attributes=request.attributes or ALL_ATTRIBUTES,
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
            self._connection.search(
                base_dn, search_filter, SUBTREE, attributes=ALL_ATTRIBUTES
            )

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
            self._connection.search(
                base_dn, search_filter, SUBTREE, attributes=ALL_ATTRIBUTES
            )

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
            self._connection.search(
                dn, "(objectClass=*)", BASE, attributes=ALL_ATTRIBUTES
            )

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
            self._connection.search(
                dn, "(objectClass=*)", BASE, attributes=ALL_ATTRIBUTES
            )

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
            ldap3_attributes = {
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
            ldap3_attributes = {
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
            ldap3_changes = {}
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
            changes = {}
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

    def _create_user_from_entry(self, entry: Entry) -> FlextLdapModels.LdapUser:
        """Create LdapUser from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            LdapUser object.

        """
        return FlextLdapModels.LdapUser(
            dn=str(entry.entry_dn),
            cn=str(entry.cn.value) if hasattr(entry, "cn") and entry.cn.value else "",
            uid=str(entry.uid.value)
            if hasattr(entry, "uid") and entry.uid.value
            else "",
            sn=str(entry.sn.value) if hasattr(entry, "sn") and entry.sn.value else "",
            given_name=str(entry.givenName.value)
            if hasattr(entry, "givenName") and entry.givenName.value
            else None,
            mail=str(entry.mail.value)
            if hasattr(entry, "mail") and entry.mail.value
            else None,
            telephone_number=str(entry.telephoneNumber.value)
            if hasattr(entry, "telephoneNumber") and entry.telephoneNumber.value
            else None,
            mobile=str(entry.mobile.value)
            if hasattr(entry, "mobile") and entry.mobile.value
            else None,
            department=str(entry.departmentNumber.value)
            if hasattr(entry, "departmentNumber") and entry.departmentNumber.value
            else None,
            title=str(entry.title.value)
            if hasattr(entry, "title") and entry.title.value
            else None,
            organization=str(entry.o.value)
            if hasattr(entry, "o") and entry.o.value
            else None,
            organizational_unit=str(entry.ou.value)
            if hasattr(entry, "ou") and entry.ou.value
            else None,
            user_password=None,  # Never expose password
            created_timestamp=None,  # Not available in basic LDAP
            modified_timestamp=None,  # Not available in basic LDAP
        )

    def _create_group_from_entry(self, entry: Entry) -> FlextLdapModels.Group:
        """Create Group from LDAP entry.

        Args:
            entry: LDAP entry object.

        Returns:
            Group object.

        """
        gid_number = None
        if hasattr(entry, "gidNumber") and entry.gidNumber.value:
            try:
                gid_number = int(entry.gidNumber.value)
            except (ValueError, TypeError):
                gid_number = None

        return FlextLdapModels.Group(
            dn=str(entry.entry_dn),
            cn=str(entry.cn.value) if hasattr(entry, "cn") and entry.cn.value else "",
            gid_number=gid_number,
            description=str(entry.description.value)
            if hasattr(entry, "description") and entry.description.value
            else None,
            created_timestamp=None,  # Not available in basic LDAP
            modified_timestamp=None,  # Not available in basic LDAP
        )


__all__ = [
    "FlextLdapClient",
]
