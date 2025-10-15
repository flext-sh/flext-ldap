"""LDAP repository implementations for flext-ldap domain.

This module provides repository classes that implement the Domain.Repository
protocol from flext-core. Repositories handle data access patterns for LDAP
entities with proper domain-driven design.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TypeVar

from flext_core import FlextCore

from flext_ldap.clients import FlextLdapClients
from flext_ldap.models import FlextLdapModels

# TypeVar at module level for proper Generic support
T = TypeVar("T", bound=FlextLdapModels.Entity)


class FlextLdapRepositories:
    """Unified namespace class for LDAP repositories.

    Consolidates all LDAP repository implementations into a single namespace class
    following FLEXT single-class-per-module pattern while maintaining domain-driven design.
    """

    # Logger moved into class to follow single-class-per-module pattern
    logger = FlextCore.Logger(__name__)

    class LdapRepository(ABC, FlextCore.Protocols.Domain.Repository[T]):
        """Abstract base class for LDAP repositories implementing Domain.Repository protocol.

        This class provides the foundation for LDAP-specific repository implementations,
        implementing the flext-core Domain.Repository protocol through explicit inheritance.

        Generic type T is bound to FlextLdapModels.Entity to ensure all repository
        operations work with domain entities.
        """

        def __init__(self, client: FlextLdapClients | None = None) -> None:
            """Initialize repository with LDAP client.

            Args:
                client: LDAP client instance. If None, creates a new instance.

            """
            super().__init__()
            self._client = client or FlextLdapClients()
            self.logger = FlextCore.Logger(__name__)

        # =========================================================================
        # DOMAIN.REPOSITORY PROTOCOL IMPLEMENTATION
        # =========================================================================

        @abstractmethod
        def get_by_id(self, entity_id: str) -> FlextCore.Result[T | None]:
            """Get entity by ID - implements Domain.Repository protocol.

            Args:
                id: Entity identifier

            Returns:
                FlextCore.Result with entity or None if not found

            """
            ...

        def find_all(self) -> FlextCore.Result[list[T]]:
            """Find all entities - implements Domain.Repository protocol.

            Returns:
                FlextCore.Result with list of all entities

            """
            # Default implementation - subclasses should override for efficiency
            return FlextCore.Result[list[T]].fail(
                "find_all not implemented - use subclass",
            )

        def save(self, entity: T) -> FlextCore.Result[T]:
            """Save entity - implements Domain.Repository protocol.

            Args:
                entity: Entity to save

            Returns:
                FlextCore.Result with saved entity

            """
            # Default implementation - check if entity exists and add or update accordingly
            entity_dn = getattr(entity, "dn", None) or str(entity)
            exists_result = self.exists(entity_dn)
            if exists_result.is_failure:
                return FlextCore.Result[T].fail(
                    f"Failed to check existence: {exists_result.error}",
                )

            if exists_result.unwrap():
                # Entity exists, update it
                return self.update(entity)
            # Entity doesn't exist, add it
            return self.add(entity)

        @abstractmethod
        def add(self, entity: T) -> FlextCore.Result[T]:
            """Add new entity - implements Domain.Repository protocol.

            Args:
                entity: Entity to add

            Returns:
                FlextCore.Result with added entity

            """
            ...

        @abstractmethod
        def update(self, entity: T) -> FlextCore.Result[T]:
            """Update existing entity - implements Domain.Repository protocol.

            Args:
                entity: Entity to update

            Returns:
                FlextCore.Result with updated entity

            """
            ...

        @abstractmethod
        def delete(self, entity_id: str) -> FlextCore.Result[bool]:
            """Delete entity by ID - implements Domain.Repository protocol.

            Args:
                entity_id: Entity identifier

            Returns:
                FlextCore.Result with True if deleted, False if not found

            """
            ...

        def exists(self, entity_id: str) -> FlextCore.Result[bool]:
            """Check if entity exists - implements Domain.Repository protocol.

            Args:
                entity_id: Entity identifier

            Returns:
                FlextCore.Result with True if exists, False otherwise

            """
            # Default implementation using get_by_id
            result = self.get_by_id(entity_id)
            if result.is_failure:
                return FlextCore.Result[bool].fail(
                    result.error or "Failed to check existence",
                )
            return FlextCore.Result[bool].ok(result.unwrap() is not None)

    class UserRepository(LdapRepository[FlextLdapModels.LdapUser]):
        """Repository for LDAP User entities implementing Domain.Repository protocol."""

        def __init__(
            self,
            client: FlextLdapClients | None = None,
            base_dn: str = "dc=example,dc=com",
        ) -> None:
            """Initialize user repository with LDAP client and base DN.

            Args:
                client: LDAP client instance. If None, creates a new instance.
                base_dn: Base DN for user searches (default: dc=example,dc=com)

            """
            super().__init__(client)
            self._base_dn = base_dn

        def get_by_id(
            self,
            entity_id: str,
        ) -> FlextCore.Result[FlextLdapModels.LdapUser | None]:
            """Get user by ID (DN or UID).

            Args:
                entity_id: User DN or UID

            Returns:
                FlextCore.Result with User entity or None

            """
            try:
                # Try as DN first
                if entity_id.startswith(("cn=", "uid=", "ou=")):
                    result = self._client.get_user(entity_id)
                else:
                    # Try as UID with search using repository's base DN
                    search_result = self._client.search_users(
                        base_dn=self._base_dn,
                        filter_str=f"(uid={entity_id})",
                    )
                    if search_result.is_failure:
                        return FlextCore.Result[FlextLdapModels.LdapUser | None].fail(
                            search_result.error or "User search failed",
                        )

                    # search_users returns list[Entry], need to convert to LdapUser
                    entries = search_result.unwrap()
                    if not entries:
                        return FlextCore.Result[FlextLdapModels.LdapUser | None].ok(
                            None
                        )

                    # Convert Entry to LdapUser - use get_user for proper conversion
                    entry = entries[0]
                    result = self._client.get_user(
                        str(entry.dn) if hasattr(entry, "dn") else entity_id
                    )

                if result.is_failure:
                    # If DN lookup failed, try UID search
                    if entity_id.startswith(("cn=", "uid=", "ou=")):
                        uid_value = entity_id.split(",", maxsplit=1)[0].split("=")[1]

                        search_result = self._client.search_users(
                            base_dn=self._base_dn,
                            filter_str=f"(uid={uid_value})",
                        )
                        if search_result.is_success:
                            entries = search_result.unwrap()
                            if entries:
                                # Convert Entry to LdapUser using get_user
                                entry = entries[0]
                                user_result = self._client.get_user(
                                    str(entry.dn) if hasattr(entry, "dn") else entity_id
                                )
                                if user_result.is_success:
                                    return FlextCore.Result[
                                        FlextLdapModels.LdapUser | None
                                    ].ok(
                                        user_result.unwrap(),
                                    )

                    return FlextCore.Result[FlextLdapModels.LdapUser | None].fail(
                        result.error or "User not found",
                    )

                return FlextCore.Result[FlextLdapModels.LdapUser | None].ok(
                    result.unwrap()
                )

            except Exception as e:
                self.logger.exception(
                    "Failed to get user by ID",
                    exception=e,
                )
                return FlextCore.Result[FlextLdapModels.LdapUser | None].fail(
                    f"User lookup failed: {e}",
                )

        def get_all(self) -> FlextCore.Result[list[FlextLdapModels.LdapUser]]:
            """Get all users.

            Returns:
                FlextCore.Result with list of all users

            """
            try:
                # search_users returns list[Entry], need to convert each to LdapUser
                search_result = self._client.search_users(base_dn=self._base_dn)
                if search_result.is_failure:
                    return FlextCore.Result[list[FlextLdapModels.LdapUser]].fail(
                        search_result.error or "User search failed",
                    )

                entries = search_result.unwrap()
                users: list[FlextLdapModels.LdapUser] = []

                # Convert each Entry to LdapUser
                for entry in entries:
                    if hasattr(entry, "dn"):
                        user_result = self._client.get_user(str(entry.dn))
                        if user_result.is_success:
                            user = user_result.unwrap()
                            if user is not None:
                                users.append(user)

                return FlextCore.Result[list[FlextLdapModels.LdapUser]].ok(users)
            except Exception as e:
                self.logger.exception("Failed to get all users", exception=e)
                return FlextCore.Result[list[FlextLdapModels.LdapUser]].fail(
                    f"User retrieval failed: {e}",
                )

        def add(
            self,
            entity: FlextLdapModels.LdapUser,
        ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
            """Add new user.

            Args:
                entity: User entity to add

            Returns:
                FlextCore.Result with added user entity

            """
            try:
                # Convert entity to create request
                create_request = FlextLdapModels.CreateUserRequest(
                    dn=entity.dn,
                    uid=entity.uid,
                    cn=entity.cn,
                    sn=entity.sn,
                    mail=getattr(entity, "mail", None),
                    object_classes=getattr(
                        entity,
                        "object_classes",
                        ["person", "organizationalPerson"],
                    ),
                )

                result = self._client.create_user(create_request)
                if result.is_failure:
                    return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                        result.error or "User creation failed",
                    )

                created_user = result.unwrap()
                if created_user is None:
                    return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                        "User creation returned None",
                    )

                return FlextCore.Result[FlextLdapModels.LdapUser].ok(created_user)

            except Exception as e:
                self.logger.exception(
                    "Failed to add user",
                    exception=e,
                )
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    f"User creation failed: {e}",
                )

        def update(
            self,
            entity: FlextLdapModels.LdapUser,
        ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
            """Update existing user.

            Args:
                entity: User entity to update

            Returns:
                FlextCore.Result with updated user entity

            """
            try:
                # For now, use attribute update - could be enhanced with change tracking
                attributes: FlextCore.Types.Dict = {
                    "cn": entity.cn,
                    "sn": entity.sn,
                }
                if hasattr(entity, "mail") and entity.mail:
                    attributes["mail"] = entity.mail

                result = self._client.update_user_attributes(entity.dn, attributes)
                if result.is_failure:
                    return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                        result.error or "User update failed",
                    )

                # Return updated entity (could refetch for consistency)
                return FlextCore.Result[FlextLdapModels.LdapUser].ok(entity)

            except Exception as e:
                self.logger.exception(
                    "Failed to update user",
                    exception=e,
                )
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    f"User update failed: {e}",
                )

        def delete(self, entity_id: str) -> FlextCore.Result[bool]:
            """Delete user by ID.

            Args:
                entity_id: User DN or UID

            Returns:
                FlextCore.Result with True if deleted

            """
            try:
                # Get user first to ensure it exists
                get_result = self.get_by_id(entity_id)
                if get_result.is_failure:
                    return FlextCore.Result[bool].fail(
                        get_result.error or "User lookup failed",
                    )

                user = get_result.unwrap()
                if user is None:
                    return FlextCore.Result[bool].ok(False)  # Not found

                result = self._client.delete_user(user.dn)
                if result.is_failure:
                    return FlextCore.Result[bool].fail(
                        result.error or "User deletion failed",
                    )

                return FlextCore.Result[bool].ok(True)

            except Exception as e:
                self.logger.exception("Failed to delete user", exception=e)
                return FlextCore.Result[bool].fail(f"User deletion failed: {e}")

    class GroupRepository(LdapRepository[FlextLdapModels.Group]):
        """Repository for LDAP Group entities implementing Domain.Repository protocol."""

        def __init__(
            self,
            client: FlextLdapClients | None = None,
            base_dn: str = "dc=example,dc=com",
        ) -> None:
            """Initialize group repository with LDAP client and base DN.

            Args:
                client: LDAP client instance. If None, creates a new instance.
                base_dn: Base DN for group searches (default: dc=example,dc=com)

            """
            super().__init__(client)
            self._base_dn = base_dn

        def get_by_id(
            self,
            entity_id: str,
        ) -> FlextCore.Result[FlextLdapModels.Group | None]:
            """Get group by ID (DN or CN).

            Args:
                entity_id: Group DN or CN

            Returns:
                FlextCore.Result with Group entity or None

            """
            try:
                result = self._client.get_group(entity_id)
                if result.is_failure:
                    return FlextCore.Result[FlextLdapModels.Group | None].fail(
                        result.error or "Group lookup failed",
                    )
                return FlextCore.Result[FlextLdapModels.Group | None].ok(
                    result.unwrap()
                )
            except Exception as e:
                self.logger.exception(
                    "Failed to get group by ID",
                    error=str(e),
                    group_id=entity_id,
                )
                return FlextCore.Result[FlextLdapModels.Group | None].fail(
                    f"Group lookup failed: {e}",
                )

        def get_all(self) -> FlextCore.Result[list[FlextLdapModels.Group]]:
            """Get all groups.

            Returns:
                FlextCore.Result with list of all groups

            """
            try:
                result = self._client.search_groups(base_dn=self._base_dn)
                if result.is_failure:
                    return FlextCore.Result[list[FlextLdapModels.Group]].fail(
                        result.error or "Group search failed",
                    )
                return FlextCore.Result[list[FlextLdapModels.Group]].ok(result.unwrap())
            except Exception as e:
                self.logger.exception("Failed to get all groups", exception=e)
                return FlextCore.Result[list[FlextLdapModels.Group]].fail(
                    f"Group retrieval failed: {e}",
                )

        def add(
            self,
            entity: FlextLdapModels.Group,
        ) -> FlextCore.Result[FlextLdapModels.Group]:
            """Add new group.

            Args:
                entity: Group entity to add

            Returns:
                FlextCore.Result with added group entity

            """
            try:
                # Convert entity to create request
                # CreateGroupRequest requires description and members
                description = getattr(entity, "description", "") or "Group"
                members = getattr(entity, "member_dns", []) or []

                create_request = FlextLdapModels.CreateGroupRequest(
                    dn=entity.dn,
                    cn=entity.cn,
                    description=description,
                    members=members,
                    object_classes=getattr(
                        entity,
                        "object_classes",
                        ["groupOfNames", "top"],
                    ),
                )

                result = self._client.create_group(create_request)
                if result.is_failure:
                    return FlextCore.Result[FlextLdapModels.Group].fail(
                        result.error or "Group creation failed",
                    )

                created_group = result.unwrap()
                if created_group is None:
                    return FlextCore.Result[FlextLdapModels.Group].fail(
                        "Group creation returned None",
                    )

                return FlextCore.Result[FlextLdapModels.Group].ok(created_group)

            except Exception as e:
                self.logger.exception(
                    "Failed to add group",
                    exception=e,
                )
                return FlextCore.Result[FlextLdapModels.Group].fail(
                    f"Group creation failed: {e}",
                )

        def update(
            self,
            entity: FlextLdapModels.Group,
        ) -> FlextCore.Result[FlextLdapModels.Group]:
            """Update existing group.

            Args:
                entity: Group entity to update

            Returns:
                FlextCore.Result with updated group entity

            """
            try:
                # For now, use attribute update
                attributes: FlextCore.Types.Dict = {
                    "cn": entity.cn,
                }
                if hasattr(entity, "description") and entity.description:
                    attributes["description"] = entity.description

                result = self._client.update_group_attributes(entity.dn, attributes)
                if result.is_failure:
                    return FlextCore.Result[FlextLdapModels.Group].fail(
                        result.error or "Group update failed",
                    )

                return FlextCore.Result[FlextLdapModels.Group].ok(entity)

            except Exception as e:
                self.logger.exception(
                    "Failed to update group",
                    exception=e,
                )
                return FlextCore.Result[FlextLdapModels.Group].fail(
                    f"Group update failed: {e}",
                )

        def delete(self, entity_id: str) -> FlextCore.Result[bool]:
            """Delete group by ID.

            Args:
                entity_id: Group DN or CN

            Returns:
                FlextCore.Result with True if deleted

            """
            try:
                # Get group first to ensure it exists
                get_result = self.get_by_id(entity_id)
                if get_result.is_failure:
                    return FlextCore.Result[bool].fail(
                        get_result.error or "Group lookup failed",
                    )

                group = get_result.unwrap()
                if group is None:
                    return FlextCore.Result[bool].ok(False)  # Not found

                result = self._client.delete_entry(group.dn)
                if result.is_failure:
                    return FlextCore.Result[bool].fail(
                        result.error or "Group deletion failed",
                    )

                return FlextCore.Result[bool].ok(True)

            except Exception as e:
                self.logger.exception(
                    "Failed to delete group",
                    exception=e,
                )
                return FlextCore.Result[bool].fail(f"Group deletion failed: {e}")
