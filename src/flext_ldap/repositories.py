"""LDAP repositories for flext-ldap.

This module provides repository pattern implementations for LDAP operations,
following FLEXT architectural patterns and domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, override

from flext_core import FlextLogger, FlextResult, T
from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes


class FlextLdapRepositories:
    """Unified LDAP repositories class consolidating ALL repository implementations.

    This class provides repository pattern implementations for LDAP operations,
    following FLEXT one-class-per-module standards.
    """

    class Repository(ABC, Generic[T]):
        """Base repository interface for LDAP operations."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize repository with LDAP client."""
            self._client = client
            self._logger = FlextLogger(__name__)

        @abstractmethod
        async def find_by_dn(self, dn: str) -> FlextResult[T]:
            """Find entry by Distinguished Name."""

        @abstractmethod
        async def search(
            self,
            base_dn: str,
            filter_str: str,
            page_size: int | None = None,
            paged_cookie: bytes | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search LDAP entries."""

        @abstractmethod
        async def save(self, entry: T) -> FlextResult[T]:
            """Save entry to LDAP."""

        @abstractmethod
        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete LDAP entry."""

        @abstractmethod
        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if entry exists."""

        @abstractmethod
        async def update(
            self,
            dn: str,
            attributes: FlextLdapTypes.EntryAttributeDict,
        ) -> FlextResult[bool]:
            """Update entry attributes."""

    class UserRepository(Repository[FlextLdapModels.LdapUser]):
        """Repository for LDAP user operations with real LDAP client integration."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize repository with LDAP client."""
            super().__init__(client)
            self._ldap_client = client  # Store reference to actual LDAP client

        @override
        async def find_by_dn(self, dn: str) -> FlextResult[FlextLdapModels.LdapUser]:
            """Find user by Distinguished Name using real LDAP operations."""
            try:
                # Use real LDAP client to get user
                if not hasattr(self._ldap_client, "get_user"):
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        "LDAP client does not support get_user operation"
                    )

                result = await self._ldap_client.get_user(dn)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        f"Failed to retrieve user: {result.error}"
                    )

                user = result.value
                if user is None:
                    return FlextResult[FlextLdapModels.LdapUser].fail("User not found")

                return FlextResult[FlextLdapModels.LdapUser].ok(user)
            except Exception as e:
                self._logger.exception("Error finding user by DN: %s", dn)
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"Error finding user: {e}"
                )

        @override
        async def search(
            self,
            base_dn: str,
            filter_str: str,
            page_size: int | None = None,
            paged_cookie: bytes | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search users using real LDAP operations."""
            try:
                self._logger.debug(
                    "Searching users with base_dn=%s, filter=%s, page_size=%s, paged_cookie=%r",
                    base_dn,
                    filter_str,
                    page_size,
                    paged_cookie,
                )

                # Use real LDAP client to search users
                if not hasattr(self._ldap_client, "search"):
                    return FlextResult[list[dict[str, object]]].fail(
                        "LDAP client does not support search operation"
                    )

                # Create search request
                search_request = FlextLdapModels.SearchRequest(
                    base_dn=base_dn,
                    filter_str=filter_str,
                    page_size=page_size,
                    paged_cookie=paged_cookie,
                )

                # Perform search using LDAP client
                result = await self._ldap_client.search_with_request(search_request)
                if result.is_failure:
                    return FlextResult[list[dict[str, object]]].fail(
                        f"Search failed: {result.error}"
                    )

                search_response = result.value
                return FlextResult[list[dict[str, object]]].ok(search_response.entries)
            except Exception as e:
                self._logger.exception("Error searching users")
                return FlextResult[list[dict[str, object]]].fail(f"Search error: {e}")

        @override
        async def save(
            self,
            entry: FlextLdapModels.LdapUser,
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Save user entry using real LDAP operations."""
            try:
                # Check if user already exists
                exists_result = await self.exists(entry.dn)
                if exists_result.is_failure:
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        f"Failed to check user existence: {exists_result.error}"
                    )

                if exists_result.value:
                    # User exists, update it
                    update_result = await self.update(
                        entry.dn, entry.additional_attributes
                    )
                    if update_result.is_failure:
                        return FlextResult[FlextLdapModels.LdapUser].fail(
                            f"Failed to update user: {update_result.error}"
                        )
                else:
                    # User doesn't exist, create it
                    create_request = FlextLdapModels.CreateUserRequest(
                        dn=entry.dn,
                        uid=entry.uid or "",
                        cn=entry.cn,
                        sn=entry.sn or "",
                        given_name=entry.given_name,
                        mail=entry.mail,
                        user_password=entry.user_password.get_secret_value()
                        if entry.user_password
                        else None,
                        telephone_number=entry.telephone_number,
                        description=getattr(entry, "description", None),
                        department=entry.department,
                        title=entry.title,
                        organization=entry.organization,
                    )

                    create_result = await self._ldap_client.create_user(create_request)
                    if create_result.is_failure:
                        return FlextResult[FlextLdapModels.LdapUser].fail(
                            f"Failed to create user: {create_result.error}"
                        )

                # Retrieve the saved user to return
                return await self.find_by_dn(entry.dn)
            except Exception as e:
                self._logger.exception("Error saving user: %s", entry.dn)
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"Error saving user: {e}"
                )

        @override
        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete user using real LDAP operations."""
            try:
                if not dn:
                    return FlextResult[bool].fail("DN cannot be empty")

                # Use real LDAP client to delete user
                if not hasattr(self._ldap_client, "delete_user"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support delete_user operation"
                    )

                delete_result = await self._ldap_client.delete_user(dn)
                if delete_result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to delete user: {delete_result.error}"
                    )

                return FlextResult[bool].ok(True)
            except Exception as e:
                self._logger.exception("Error deleting user: %s", dn)
                return FlextResult[bool].fail(f"Error deleting user: {e}")

        @override
        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if user exists using real LDAP operations."""
            try:
                if not dn:
                    return FlextResult[bool].fail("DN cannot be empty")

                # Use real LDAP client to check user existence
                if not hasattr(self._ldap_client, "user_exists"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support user_exists operation"
                    )

                exists_result = await self._ldap_client.user_exists(dn)
                if exists_result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to check user existence: {exists_result.error}"
                    )

                return FlextResult[bool].ok(exists_result.value)
            except Exception as e:
                self._logger.exception("Error checking user existence: %s", dn)
                return FlextResult[bool].fail(f"Error checking user existence: {e}")

        @override
        async def update(
            self,
            dn: str,
            attributes: FlextLdapTypes.EntryAttributeDict,
        ) -> FlextResult[bool]:
            """Update user attributes using real LDAP operations."""
            try:
                if not dn:
                    return FlextResult[bool].fail("DN cannot be empty")
                if not attributes:
                    return FlextResult[bool].fail("Attributes cannot be empty")

                # Use real LDAP client to update user attributes
                if not hasattr(self._ldap_client, "update_user_attributes"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support update_user_attributes operation"
                    )

                # Convert AttributeDict to dict[str, object] for compatibility
                converted_attributes: dict[str, object] = dict(attributes.items())
                update_result = await self._ldap_client.update_user_attributes(
                    dn, converted_attributes
                )
                if update_result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to update user attributes: {update_result.error}"
                    )

                return FlextResult[bool].ok(update_result.value)
            except Exception as e:
                self._logger.exception("Error updating user attributes: %s", dn)
                return FlextResult[bool].fail(f"Error updating user attributes: {e}")

        async def find_user_by_uid(
            self,
            uid: str,
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Find user by UID using real LDAP operations."""
            try:
                if not uid:
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        "UID cannot be empty"
                    )

                # Search for user by UID using LDAP client
                if not hasattr(self._ldap_client, "search_users"):
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        "LDAP client does not support search_users operation"
                    )

                # Search for users with the specified UID
                search_result = await self._ldap_client.search_users(
                    base_dn="ou=users,dc=example,dc=com",  # Default base DN
                    uid=uid,
                )

                if search_result.is_failure:
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        f"Failed to search for user by UID: {search_result.error}"
                    )

                users = search_result.value
                if not users:
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        f"User with UID '{uid}' not found"
                    )

                # Return the first user found
                return FlextResult[FlextLdapModels.LdapUser].ok(users[0])
            except Exception as e:
                self._logger.exception("Error finding user by UID: %s", uid)
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"Error finding user by UID: {e}"
                )

        async def find_users_by_filter(
            self,
            filter_str: str,
        ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
            """Find users by filter using real LDAP operations."""
            try:
                if not filter_str:
                    return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                        "Filter cannot be empty"
                    )

                # Use search method with the provided filter
                search_result = await self.search(
                    base_dn="ou=users,dc=example,dc=com",  # Default base DN
                    filter_str=filter_str,
                )

                if search_result.is_failure:
                    return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                        f"Failed to search users by filter: {search_result.error}"
                    )

                # Convert search results to LdapUser objects
                users = []
                for entry_dict in search_result.value:
                    try:
                        # Convert object types to proper string types
                        def safe_str(value: object) -> str | None:
                            return str(value) if value is not None else None

                        user = FlextLdapModels.LdapUser(
                            dn=str(entry_dict.get("dn", "")),
                            cn=str(entry_dict.get("cn", "")),
                            uid=safe_str(entry_dict.get("uid")),
                            sn=safe_str(entry_dict.get("sn")),
                            given_name=safe_str(entry_dict.get("givenName")),
                            mail=safe_str(entry_dict.get("mail")),
                            telephone_number=safe_str(
                                entry_dict.get("telephoneNumber")
                            ),
                            mobile=safe_str(entry_dict.get("mobile")),
                            department=safe_str(entry_dict.get("departmentNumber")),
                            title=safe_str(entry_dict.get("title")),
                            organization=safe_str(entry_dict.get("o")),
                            organizational_unit=safe_str(entry_dict.get("ou")),
                            user_password=None,  # Don't include password in search results
                            created_timestamp=None,
                            modified_timestamp=None,
                        )
                        users.append(user)
                    except Exception as e:
                        self._logger.warning(
                            "Failed to convert entry to LdapUser: %s", e
                        )
                        continue

                return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)
            except Exception as e:
                self._logger.exception("Error finding users by filter: %s", filter_str)
                return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                    f"Error finding users by filter: {e}"
                )

    class GroupRepository(Repository[FlextLdapModels.Group]):
        """Repository for LDAP group operations with real LDAP client integration."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize repository with LDAP client."""
            super().__init__(client)
            self._ldap_client = client  # Store reference to actual LDAP client

        @override
        async def find_by_dn(self, dn: str) -> FlextResult[FlextLdapModels.Group]:
            """Find group by Distinguished Name using real LDAP operations."""
            try:
                # Use real LDAP client to get group
                if not hasattr(self._ldap_client, "get_group"):
                    return FlextResult[FlextLdapModels.Group].fail(
                        "LDAP client does not support get_group operation"
                    )

                result = await self._ldap_client.get_group(dn)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.Group].fail(
                        f"Failed to retrieve group: {result.error}"
                    )

                group = result.value
                if group is None:
                    return FlextResult[FlextLdapModels.Group].fail("Group not found")

                return FlextResult[FlextLdapModels.Group].ok(group)
            except Exception as e:
                self._logger.exception("Error finding group by DN: %s", dn)
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Error finding group: {e}"
                )

        @override
        async def search(
            self,
            base_dn: str,
            filter_str: str,
            page_size: int | None = None,
            paged_cookie: bytes | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search for groups using real LDAP operations."""
            try:
                # Use real LDAP client to search groups
                if not hasattr(self._ldap_client, "search_groups"):
                    return FlextResult[list[dict[str, object]]].fail(
                        "LDAP client does not support search_groups operation"
                    )

                result = await self._ldap_client.search_groups(base_dn, filter_str)
                if result.is_failure:
                    return FlextResult[list[dict[str, object]]].fail(
                        f"Failed to search groups: {result.error}"
                    )

                groups = result.value or []
                # Convert Group objects to dict format for compatibility
                group_dicts = []
                for group in groups:
                    if hasattr(group, "__dict__"):
                        group_dicts.append(group.__dict__)
                    else:
                        group_dicts.append({"dn": str(group)})

                return FlextResult[list[dict[str, object]]].ok(group_dicts)
            except Exception as e:
                self._logger.exception("Error searching groups: %s", filter_str)
                return FlextResult[list[dict[str, object]]].fail(
                    f"Error searching groups: {e}"
                )

        @override
        async def save(
            self, entry: FlextLdapModels.Group
        ) -> FlextResult[FlextLdapModels.Group]:
            """Save group using real LDAP operations."""
            try:
                # Use real LDAP client to create group
                if not hasattr(self._ldap_client, "create_group"):
                    return FlextResult[FlextLdapModels.Group].fail(
                        "LDAP client does not support create_group operation"
                    )

                # Convert Group to CreateGroupRequest
                create_request = FlextLdapModels.CreateGroupRequest(
                    dn=entry.dn,
                    cn=entry.cn,
                    description=getattr(entry, "description", None),
                    members=entry.member_dns or None,
                )
                result = await self._ldap_client.create_group(create_request)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.Group].fail(
                        f"Failed to create group: {result.error}"
                    )

                return FlextResult[FlextLdapModels.Group].ok(entry)
            except Exception as e:
                self._logger.exception("Error saving group: %s", entry.dn)
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Error saving group: {e}"
                )

        @override
        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete group using real LDAP operations."""
            try:
                # Use real LDAP client to delete group
                if not hasattr(self._ldap_client, "delete_group"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support delete_group operation"
                    )

                result = await self._ldap_client.delete_group(dn)
                if result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to delete group: {result.error}"
                    )

                return FlextResult[bool].ok(True)
            except Exception as e:
                self._logger.exception("Error deleting group: %s", dn)
                return FlextResult[bool].fail(f"Error deleting group: {e}")

        @override
        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if group exists using real LDAP operations."""
            try:
                # Use real LDAP client to check group existence
                if not hasattr(self._ldap_client, "group_exists"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support group_exists operation"
                    )

                result = await self._ldap_client.group_exists(dn)
                if result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to check group existence: {result.error}"
                    )

                return FlextResult[bool].ok(result.value)
            except Exception as e:
                self._logger.exception("Error checking group existence: %s", dn)
                return FlextResult[bool].fail(f"Error checking group existence: {e}")

        @override
        async def update(
            self,
            dn: str,
            attributes: FlextLdapTypes.EntryAttributeDict,
        ) -> FlextResult[bool]:
            """Update group using real LDAP operations."""
            try:
                # Use real LDAP client to update group
                if not hasattr(self._ldap_client, "update_group_attributes"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support update_group_attributes operation"
                    )

                # Convert AttributeDict to dict[str, object] for compatibility
                converted_attributes: dict[str, object] = dict(attributes.items())
                result = await self._ldap_client.update_group_attributes(
                    dn, converted_attributes
                )
                if result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to update group: {result.error}"
                    )

                return FlextResult[bool].ok(True)
            except Exception as e:
                self._logger.exception("Error updating group: %s", dn)
                return FlextResult[bool].fail(f"Error updating group: {e}")

        async def find_group_by_cn(
            self, cn: str, base_dn: str | None = None
        ) -> FlextResult[FlextLdapModels.Group]:
            """Find group by Common Name using real LDAP operations."""
            try:
                # Use real LDAP client to find group by CN
                search_result = await self._ldap_client.search_groups(
                    base_dn=base_dn or "dc=flext,dc=local", cn=cn
                )

                if search_result.is_failure:
                    return FlextResult[FlextLdapModels.Group].fail(
                        f"Failed to search for group: {search_result.error}"
                    )

                groups = search_result.value
                if not groups:
                    return FlextResult[FlextLdapModels.Group].fail("Group not found")

                group = groups[0]
                return FlextResult[FlextLdapModels.Group].ok(group)
            except Exception as e:
                self._logger.exception("Error finding group by CN: %s", cn)
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Error finding group by CN: {e}"
                )

        async def get_group_members(self, group_dn: str) -> FlextResult[list[str]]:
            """Get group members using real LDAP operations."""
            try:
                # Use real LDAP client to get group members
                # Use get_members method which exists in the client
                result = await self._ldap_client.get_members(group_dn)
                if result.is_failure:
                    return FlextResult[list[str]].fail(
                        f"Failed to get group members: {result.error}"
                    )

                members = result.value or []
                return FlextResult[list[str]].ok(members)
            except Exception as e:
                self._logger.exception("Error getting group members: %s", group_dn)
                return FlextResult[list[str]].fail(f"Error getting group members: {e}")

        async def add_member_to_group(
            self, group_dn: str, member_dn: str
        ) -> FlextResult[bool]:
            """Add member to group using real LDAP operations."""
            try:
                # Use real LDAP client to add member to group
                if not hasattr(self._ldap_client, "add_member_to_group"):
                    return FlextResult[bool].fail(
                        "LDAP client does not support add_member_to_group operation"
                    )

                result = await self._ldap_client.add_member_to_group(
                    group_dn, member_dn
                )
                if result.is_failure:
                    return FlextResult[bool].fail(
                        f"Failed to add member to group: {result.error}"
                    )

                return FlextResult[bool].ok(True)
            except Exception as e:
                self._logger.exception(
                    "Error adding member to group: %s -> %s", member_dn, group_dn
                )
                return FlextResult[bool].fail(f"Error adding member to group: {e}")
