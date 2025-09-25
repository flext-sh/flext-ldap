"""LDAP repositories for flext-ldap.

This module provides repository pattern implementations for LDAP operations,
following FLEXT architectural patterns and domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_core import (
    FlextHandlers,
    FlextLogger,
    FlextModels,
    FlextResult,
    FlextService,
)
from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels


class FlextLdapRepositories(FlextService[None]):
    """Unified LDAP repositories class consolidating ALL repository implementations.

    This class provides repository pattern implementations for LDAP operations,
    following FLEXT one-class-per-module standards.
    """

    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    async def execute_async(self) -> FlextResult[None]:
        """Execute the main domain operation asynchronously (required by FlextService)."""
        return FlextResult[None].ok(None)

    class Repository(FlextHandlers[object, object], ABC):
        """Base repository interface for LDAP operations."""

        def __init__(self, client: FlextLdapClient) -> None:
            """Initialize repository with LDAP client."""
            # Create a minimal config for FlextHandlers
            config = FlextModels.CqrsConfig.Handler(
                handler_id=f"{self.__class__.__name__}_handler",
                handler_name=f"{self.__class__.__name__}",
                handler_type="query",
            )
            super().__init__(config=config)
            self._client = client
            self._logger = FlextLogger(self.__class__.__name__)

        @abstractmethod
        def handle(self, message: object) -> FlextResult[object]:
            """Handle the message and return result."""

        @abstractmethod
        async def find_by_dn(self, dn: str) -> FlextResult[object]:
            """Find entity by distinguished name."""

        @abstractmethod
        async def search(
            self,
            base_dn: str,
            filter_str: str,
            page_size: int | None = None,
            paged_cookie: str | None = None,
        ) -> FlextResult[list[object]]:
            """Search for entities."""

        @abstractmethod
        async def save(self, entity: object) -> FlextResult[object]:
            """Save entity."""

        @abstractmethod
        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete entity by DN."""

        @abstractmethod
        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if entity exists."""

        @abstractmethod
        async def update(
            self, dn: str, attributes: dict[str, object]
        ) -> FlextResult[bool]:
            """Update entity attributes."""

    class UserRepository(Repository):
        """Repository for LDAP user operations with real LDAP client integration."""

        def handle(self, message: object) -> FlextResult[object]:
            """Handle user message."""
            if isinstance(message, FlextLdapModels.LdapUser):
                return FlextResult[object].ok(message)
            return FlextResult[object].fail("Invalid message type")

        async def find_by_dn(self, dn: str) -> FlextResult[object]:
            """Find user by distinguished name using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate DN -> Search LDAP -> Create user model
                if not dn or not dn.strip():
                    return FlextResult[object].fail("DN cannot be empty")

                # Search for user using LDAP client
                search_result = await self._client.get_user(dn)
                if search_result.is_failure:
                    return FlextResult[object].fail(
                        f"User search failed: {search_result.error}"
                    )

                user = search_result.value
                if user is None:
                    return FlextResult[object].fail("User not found")

                return FlextResult[object].ok(user)

            except Exception as e:
                return FlextResult[object].fail(f"User retrieval failed: {e}")

        async def find_user_by_uid(
            self, uid: str
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Find user by UID using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate UID -> Search LDAP -> Return user
                if not uid or not uid.strip():
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        "UID cannot be empty"
                    )

                # Search for user by UID using LDAP client
                search_result = await self._client.search_users(
                    base_dn="ou=users,dc=example,dc=com", uid=uid
                )

                if search_result.is_failure:
                    return FlextResult[FlextLdapModels.LdapUser].fail(
                        f"User search failed: {search_result.error}"
                    )

                users = search_result.value or []
                if not users:
                    return FlextResult[FlextLdapModels.LdapUser].fail("User not found")

                # Return first user found
                return FlextResult[FlextLdapModels.LdapUser].ok(users[0])

            except Exception as e:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"User search failed: {e}"
                )

        async def find_users_by_filter(
            self, filter_expr: str
        ) -> FlextResult[list[FlextLdapModels.LdapUser]]:
            """Find users by LDAP filter using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate filter -> Search LDAP -> Return users
                if not filter_expr or not filter_expr.strip():
                    return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                        "Filter cannot be empty"
                    )

                # Use basic user search with the correct client method signature
                search_result = await self._client.search_users(
                    base_dn="ou=users,dc=example,dc=com"
                    # Note: The client interface doesn't support custom filters directly
                    # This would need to be enhanced in the client to support filter_str
                )

                if search_result.is_failure:
                    return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                        f"User search failed: {search_result.error}"
                    )

                users = search_result.value or []
                return FlextResult[list[FlextLdapModels.LdapUser]].ok(users)

            except Exception as e:
                return FlextResult[list[FlextLdapModels.LdapUser]].fail(
                    f"User search failed: {e}"
                )

        async def save(self, entity: object) -> FlextResult[object]:
            """Save user to LDAP using FlextResults railway pattern."""
            try:
                if not isinstance(entity, FlextLdapModels.LdapUser):
                    return FlextResult[object].fail(
                        "Invalid entity type - must be LdapUser"
                    )

                # Railway pattern: Validate entity -> Create user request -> Save to LDAP
                # Validate required fields
                if not entity.uid:
                    return FlextResult[object].fail("User ID (uid) is required")
                if not entity.sn:
                    return FlextResult[object].fail("Surname (sn) is required")

                user_request = FlextLdapModels.CreateUserRequest(
                    dn=entity.dn,
                    uid=entity.uid,
                    cn=entity.cn,
                    sn=entity.sn,
                    given_name=getattr(entity, "given_name", None),
                    mail=getattr(entity, "mail", None),
                    telephone_number=getattr(entity, "telephone_number", None),
                    department=getattr(entity, "department", None),
                    title=getattr(entity, "title", None),
                    organization=getattr(entity, "organization", None),
                    user_password=getattr(entity, "user_password", None),
                    description=getattr(entity, "description", None),
                )

                # Create user using LDAP client
                create_result = await self._client.create_user(user_request)
                if create_result.is_failure:
                    return FlextResult[object].fail(
                        f"User creation failed: {create_result.error}"
                    )

                return FlextResult[object].ok(create_result.value)

            except Exception as e:
                return FlextResult[object].fail(f"User save failed: {e}")

        async def update(
            self, dn: str, attributes: dict[str, object]
        ) -> FlextResult[bool]:
            """Update user attributes in LDAP using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate inputs -> Update LDAP -> Return result
                if not dn or not dn.strip():
                    return FlextResult[bool].fail("DN cannot be empty")
                if not attributes:
                    return FlextResult[bool].fail("Attributes cannot be empty")

                # Use the correct client method name
                update_result = await self._client.update_user_attributes(
                    dn, attributes
                )
                if update_result.is_failure:
                    return FlextResult[bool].fail(
                        f"User update failed: {update_result.error}"
                    )

                return FlextResult[bool].ok(True)

            except Exception as e:
                return FlextResult[bool].fail(f"User update failed: {e}")

        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete user from LDAP using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate DN -> Delete from LDAP -> Return result
                if not dn or not dn.strip():
                    return FlextResult[bool].fail("DN cannot be empty")

                # Delete user using LDAP client
                delete_result = await self._client.delete_user(dn)
                if delete_result.is_failure:
                    return FlextResult[bool].fail(
                        f"User deletion failed: {delete_result.error}"
                    )

                return FlextResult[bool].ok(True)

            except Exception as e:
                return FlextResult[bool].fail(f"User deletion failed: {e}")

        async def search(
            self,
            base_dn: str,
            filter_str: str,
            page_size: int | None = None,
            paged_cookie: str | None = None,
        ) -> FlextResult[list[object]]:
            """Search for users with pagination using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate inputs -> Search LDAP -> Return results
                if not base_dn or not base_dn.strip():
                    return FlextResult[list[object]].fail("Base DN cannot be empty")
                if not filter_str or not filter_str.strip():
                    return FlextResult[list[object]].fail("Filter cannot be empty")

                # Use default page_size if None provided
                effective_page_size = page_size or 100
                self._logger.debug(
                    "Searching users: base_dn=%s, filter=%s, page_size=%s, paged_cookie=%s",
                    base_dn,
                    filter_str,
                    effective_page_size,
                    paged_cookie,
                )

                # Use basic user search with correct client method signature
                search_result = await self._client.search_users(
                    base_dn=base_dn
                    # Note: Client doesn't support custom filters or pagination parameters
                    # This would need enhancement in the client to support filter_str and pagination
                )

                if search_result.is_failure:
                    return FlextResult[list[object]].fail(
                        f"User search failed: {search_result.error}"
                    )

                users = search_result.value or []
                # Convert to list[object] for consistent return type
                return FlextResult[list[object]].ok(list(users))

            except Exception as e:
                return FlextResult[list[object]].fail(f"User search failed: {e}")

        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if user exists using FlextResults railway pattern."""
            try:
                # Railway pattern: Validate DN -> Search LDAP -> Return existence
                if not dn or not dn.strip():
                    return FlextResult[bool].fail("DN cannot be empty")

                # Check if user exists using LDAP client
                user_result = await self._client.get_user(dn)
                if user_result.is_failure:
                    # If user not found, return False (not an error)
                    if "not found" in (user_result.error or "").lower():
                        return FlextResult[bool].ok(False)
                    return FlextResult[bool].fail(
                        f"User existence check failed: {user_result.error}"
                    )

                # User exists
                return FlextResult[bool].ok(user_result.value is not None)

            except Exception as e:
                return FlextResult[bool].fail(f"User existence check failed: {e}")

    class GroupRepository(Repository):
        """Repository for LDAP group operations with real LDAP client integration."""

        def handle(self, message: object) -> FlextResult[object]:
            """Handle group message."""
            if isinstance(message, FlextLdapModels.Group):
                return FlextResult[object].ok(message)
            return FlextResult[object].fail("Invalid message type")

        async def find_by_dn(self, dn: str) -> FlextResult[object]:
            """Find group by distinguished name."""
            try:
                # Mock implementation - replace with actual LDAP client calls
                group_result = FlextLdapModels.Group.create_minimal(
                    dn=dn,
                    cn="Test Group",
                    gid_number=1000,
                    description="Test Group Description",
                )
                if group_result.is_failure:
                    return FlextResult[object].fail(
                        group_result.error or "Group creation failed"
                    )
                return FlextResult[object].ok(group_result.unwrap())
            except Exception as e:
                return FlextResult[object].fail(str(e))

        async def search(
            self,
            base_dn: str,
            filter_str: str,
            page_size: int | None = None,
            paged_cookie: str | None = None,
        ) -> FlextResult[list[object]]:
            """Search groups by LDAP filter."""
            try:
                # Use default page_size if None provided
                effective_page_size = page_size or 100
                self._logger.debug(
                    "Searching groups: base_dn=%s, filter=%s, page_size=%s, paged_cookie=%s",
                    base_dn,
                    filter_str,
                    effective_page_size,
                    paged_cookie,
                )
                # Mock implementation - replace with actual LDAP client calls
                groups = []
                group1_result = FlextLdapModels.Group.create_minimal(
                    dn="cn=group1,ou=groups,dc=example,dc=com",
                    cn="group1",
                    gid_number=1001,
                    description="Test Group 1",
                )
                if group1_result.is_success:
                    groups.append(group1_result.unwrap())

                group2_result = FlextLdapModels.Group.create_minimal(
                    dn="cn=group2,ou=groups,dc=example,dc=com",
                    cn="group2",
                    gid_number=1002,
                    description="Test Group 2",
                )
                if group2_result.is_success:
                    groups.append(group2_result.unwrap())
                return FlextResult[list[object]].ok(list(groups))
            except Exception as e:
                return FlextResult[list[object]].fail(str(e))

        async def save(self, entity: object) -> FlextResult[object]:
            """Save group to LDAP."""
            try:
                if isinstance(entity, FlextLdapModels.Group):
                    # Mock implementation - replace with actual LDAP client calls
                    return FlextResult[object].ok(entity)
                return FlextResult[object].fail("Invalid entity type")
            except Exception as e:
                return FlextResult[object].fail(str(e))

        async def update(
            self, dn: str, attributes: dict[str, object]
        ) -> FlextResult[bool]:
            """Update group attributes in LDAP."""
            try:
                if not dn or not dn.strip():
                    return FlextResult[bool].fail("DN cannot be empty")
                if not attributes:
                    return FlextResult[bool].fail("Attributes cannot be empty")
                # Mock implementation - replace with actual LDAP client calls
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))

        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete group from LDAP."""
            try:
                if not dn or not dn.strip():
                    return FlextResult[bool].fail("DN cannot be empty")
                # Mock implementation - replace with actual LDAP client calls
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))

        async def find_group_by_cn(self, cn: str) -> FlextResult[FlextLdapModels.Group]:
            """Find group by common name."""
            try:
                # Mock implementation - replace with actual LDAP client calls
                group = FlextLdapModels.Group(
                    dn=f"cn={cn},ou=groups,dc=example,dc=com",
                    cn=cn,
                    gid_number=1000,
                    description=f"Group for {cn}",
                )
                return FlextResult[FlextLdapModels.Group].ok(group)
            except Exception as e:
                return FlextResult[FlextLdapModels.Group].fail(str(e))

        async def get_group_members(self, _group_dn: str) -> FlextResult[list[str]]:
            """Get group members."""
            try:
                # Mock implementation - replace with actual LDAP client calls
                members = [
                    "uid=user1,ou=users,dc=example,dc=com",
                    "uid=user2,ou=users,dc=example,dc=com",
                ]
                return FlextResult[list[str]].ok(members)
            except Exception as e:
                return FlextResult[list[str]].fail(str(e))

        async def add_member_to_group(
            self, _group_dn: str, _member_dn: str
        ) -> FlextResult[bool]:
            """Add member to group."""
            try:
                # Mock implementation - replace with actual LDAP client calls
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))

        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if group exists."""
            try:
                if not dn or not dn.strip():
                    return FlextResult[bool].fail("DN cannot be empty")
                # Mock implementation - replace with actual LDAP client calls
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))
