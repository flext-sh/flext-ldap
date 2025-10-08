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

from flext_core import FlextLogger, FlextProtocols, FlextResult

from flext_ldap.clients import FlextLdapClients
from flext_ldap.models import FlextLdapModels

logger = FlextLogger(__name__)

T = TypeVar("T", bound=FlextLdapModels.Entity)


class FlextLdapRepositories:
    """Unified namespace class for LDAP repositories.

    Consolidates all LDAP repository implementations into a single namespace class
    following FLEXT single-class-per-module pattern while maintaining domain-driven design.
    """

    class LdapRepository(ABC, FlextProtocols.Domain.Repository[T]):
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
            self._client = client or FlextLdapClients()
            self.logger = FlextLogger(__name__)

        # =========================================================================
        # DOMAIN.REPOSITORY PROTOCOL IMPLEMENTATION
        # =========================================================================

        @abstractmethod
        def get_by_id(self, entity_id: str) -> FlextResult[T | None]:
            """Get entity by ID - implements Domain.Repository protocol.

            Args:
                id: Entity identifier

            Returns:
                FlextResult with entity or None if not found

            """
            ...

        def find_all(self) -> FlextResult[list[T]]:
            """Find all entities - implements Domain.Repository protocol.

            Returns:
                FlextResult with list of all entities

            """
            # Default implementation - subclasses should override for efficiency
            return FlextResult[list[T]].fail("find_all not implemented - use subclass")

        def save(self, entity: T) -> FlextResult[T]:
            """Save entity - implements Domain.Repository protocol.

            Args:
                entity: Entity to save

            Returns:
                FlextResult with saved entity

            """
            # Default implementation - check if entity exists and add or update accordingly
            exists_result = self.exists(
                entity.dn if hasattr(entity, "dn") else str(entity)
            )
            if exists_result.is_failure:
                return FlextResult[T].fail(
                    f"Failed to check existence: {exists_result.error}"
                )

            if exists_result.unwrap():
                # Entity exists, update it
                return self.update(entity)
            # Entity doesn't exist, add it
            return self.add(entity)

        @abstractmethod
        def add(self, entity: T) -> FlextResult[T]:
            """Add new entity - implements Domain.Repository protocol.

            Args:
                entity: Entity to add

            Returns:
                FlextResult with added entity

            """
            ...

        @abstractmethod
        def update(self, entity: T) -> FlextResult[T]:
            """Update existing entity - implements Domain.Repository protocol.

            Args:
                entity: Entity to update

            Returns:
                FlextResult with updated entity

            """
            ...

        @abstractmethod
        def delete(self, entity_id: str) -> FlextResult[bool]:
            """Delete entity by ID - implements Domain.Repository protocol.

            Args:
                entity_id: Entity identifier

            Returns:
                FlextResult with True if deleted, False if not found

            """
            ...

        def exists(self, id: str) -> FlextResult[bool]:
            """Check if entity exists - implements Domain.Repository protocol.

            Args:
                id: Entity identifier

            Returns:
                FlextResult with True if exists, False otherwise

            """
            # Default implementation using get_by_id
            result = self.get_by_id(id)
            if result.is_failure:
                return FlextResult[bool].fail(
                    result.error or "Failed to check existence"
                )
            return FlextResult[bool].ok(result.unwrap() is not None)

    class UserRepository(LdapRepository[FlextLdapModels.User]):
        """Repository for LDAP User entities implementing Domain.Repository protocol."""

        def get_by_id(self, entity_id: str) -> FlextResult[FlextLdapModels.User | None]:
            """Get user by ID (DN or UID).

            Args:
                entity_id: User DN or UID

            Returns:
                FlextResult with User entity or None

            """
            try:
                # Try as DN first
                if entity_id.startswith(("cn=", "uid=", "ou=")):
                    result = self._client.get_user(entity_id)
                else:
                    # Try as UID with search
                    search_result = self._client.search_users(
                        base_dn=self._client.config.ldap_user_base_dn, uid=entity_id
                    )
                    if search_result.is_failure:
                        return FlextResult[FlextLdapModels.User | None].fail(
                            search_result.error or "User search failed"
                        )

                    users = search_result.unwrap()
                    if not users:
                        return FlextResult[FlextLdapModels.User | None].ok(None)

                    # Return first match
                    result = FlextResult[FlextLdapModels.User].ok(users[0])

                if result.is_failure:
                    # If DN lookup failed, try UID search
                    if entity_id.startswith(("cn=", "uid=", "ou=")):
                        search_result = self._client.search_users(
                            base_dn=self._client.config.ldap_user_base_dn,
                            uid=entity_id.split(",", maxsplit=1)[0].split("=")[
                                1
                            ],  # Extract UID from DN
                        )
                        if search_result.is_success:
                            users = search_result.unwrap()
                            if users:
                                return FlextResult[FlextLdapModels.User | None].ok(
                                    users[0]
                                )

                    return FlextResult[FlextLdapModels.User | None].fail(
                        result.error or "User not found"
                    )

                return FlextResult[FlextLdapModels.User | None].ok(result.unwrap())

            except Exception as e:
                self.logger.exception(
                    "Failed to get user by ID", error=str(e), user_id=id
                )
                return FlextResult[FlextLdapModels.User | None].fail(
                    f"User lookup failed: {e}"
                )

        def get_all(self) -> FlextResult[list[FlextLdapModels.User]]:
            """Get all users.

            Returns:
                FlextResult with list of all users

            """
            try:
                result = self._client.search_users(
                    base_dn=self._client.config.ldap_user_base_dn
                )
                if result.is_failure:
                    return FlextResult[list[FlextLdapModels.User]].fail(
                        result.error or "User search failed"
                    )
                return FlextResult[list[FlextLdapModels.User]].ok(result.unwrap())
            except Exception as e:
                self.logger.exception("Failed to get all users", error=str(e))
                return FlextResult[list[FlextLdapModels.User]].fail(
                    f"User retrieval failed: {e}"
                )

        def add(
            self, entity: FlextLdapModels.User
        ) -> FlextResult[FlextLdapModels.User]:
            """Add new user.

            Args:
                entity: User entity to add

            Returns:
                FlextResult with added user entity

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
                        entity, "object_classes", ["person", "organizationalPerson"]
                    ),
                )

                result = self._client.create_user(create_request)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.User].fail(
                        result.error or "User creation failed"
                    )

                return FlextResult[FlextLdapModels.User].ok(result.unwrap())

            except Exception as e:
                self.logger.exception(
                    "Failed to add user", error=str(e), user_dn=entity.dn
                )
                return FlextResult[FlextLdapModels.User].fail(
                    f"User creation failed: {e}"
                )

        def update(
            self, entity: FlextLdapModels.User
        ) -> FlextResult[FlextLdapModels.User]:
            """Update existing user.

            Args:
                entity: User entity to update

            Returns:
                FlextResult with updated user entity

            """
            try:
                # For now, use attribute update - could be enhanced with change tracking
                attributes = {
                    "cn": entity.cn,
                    "sn": entity.sn,
                }
                if hasattr(entity, "mail") and entity.mail:
                    attributes["mail"] = entity.mail

                result = self._client.update_user_attributes(entity.dn, attributes)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.User].fail(
                        result.error or "User update failed"
                    )

                # Return updated entity (could refetch for consistency)
                return FlextResult[FlextLdapModels.User].ok(entity)

            except Exception as e:
                self.logger.exception(
                    "Failed to update user", error=str(e), user_dn=entity.dn
                )
                return FlextResult[FlextLdapModels.User].fail(
                    f"User update failed: {e}"
                )

        def delete(self, entity_id: str) -> FlextResult[bool]:
            """Delete user by ID.

            Args:
                entity_id: User DN or UID

            Returns:
                FlextResult with True if deleted

            """
            try:
                # Get user first to ensure it exists
                get_result = self.get_by_id(entity_id)
                if get_result.is_failure:
                    return FlextResult[bool].fail(
                        get_result.error or "User lookup failed"
                    )

                user = get_result.unwrap()
                if user is None:
                    return FlextResult[bool].ok(False)  # Not found

                result = self._client.delete_user(user.dn)
                if result.is_failure:
                    return FlextResult[bool].fail(
                        result.error or "User deletion failed"
                    )

                return FlextResult[bool].ok(True)

            except Exception as e:
                self.logger.exception("Failed to delete user", error=str(e), user_id=id)
                return FlextResult[bool].fail(f"User deletion failed: {e}")

    class GroupRepository(LdapRepository[FlextLdapModels.Group]):
        """Repository for LDAP Group entities implementing Domain.Repository protocol."""

        def get_by_id(
            self, entity_id: str
        ) -> FlextResult[FlextLdapModels.Group | None]:
            """Get group by ID (DN or CN).

            Args:
                entity_id: Group DN or CN

            Returns:
                FlextResult with Group entity or None

            """
            try:
                result = self._client.get_group(entity_id)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.Group | None].fail(
                        result.error or "Group lookup failed"
                    )
                return FlextResult[FlextLdapModels.Group | None].ok(result.unwrap())
            except Exception as e:
                self.logger.exception(
                    "Failed to get group by ID", error=str(e), group_id=entity_id
                )
                return FlextResult[FlextLdapModels.Group | None].fail(
                    f"Group lookup failed: {e}"
                )

        def get_all(self) -> FlextResult[list[FlextLdapModels.Group]]:
            """Get all groups.

            Returns:
                FlextResult with list of all groups

            """
            try:
                result = self._client.search_groups(
                    base_dn=self._client.config.ldap_group_base_dn
                )
                if result.is_failure:
                    return FlextResult[list[FlextLdapModels.Group]].fail(
                        result.error or "Group search failed"
                    )
                return FlextResult[list[FlextLdapModels.Group]].ok(result.unwrap())
            except Exception as e:
                self.logger.exception("Failed to get all groups", error=str(e))
                return FlextResult[list[FlextLdapModels.Group]].fail(
                    f"Group retrieval failed: {e}"
                )

        def add(
            self, entity: FlextLdapModels.Group
        ) -> FlextResult[FlextLdapModels.Group]:
            """Add new group.

            Args:
                entity: Group entity to add

            Returns:
                FlextResult with added group entity

            """
            try:
                # Convert entity to create request
                create_request = FlextLdapModels.CreateGroupRequest(
                    dn=entity.dn,
                    cn=entity.cn,
                    description=getattr(entity, "description", None),
                    object_classes=getattr(
                        entity, "object_classes", ["groupOfNames", "top"]
                    ),
                )

                result = self._client.create_group(create_request)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.Group].fail(
                        result.error or "Group creation failed"
                    )

                return FlextResult[FlextLdapModels.Group].ok(result.unwrap())

            except Exception as e:
                self.logger.exception(
                    "Failed to add group", error=str(e), group_dn=entity.dn
                )
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Group creation failed: {e}"
                )

        def update(
            self, entity: FlextLdapModels.Group
        ) -> FlextResult[FlextLdapModels.Group]:
            """Update existing group.

            Args:
                entity: Group entity to update

            Returns:
                FlextResult with updated group entity

            """
            try:
                # For now, use attribute update
                attributes = {
                    "cn": entity.cn,
                }
                if hasattr(entity, "description") and entity.description:
                    attributes["description"] = entity.description

                result = self._client.update_group_attributes(entity.dn, attributes)
                if result.is_failure:
                    return FlextResult[FlextLdapModels.Group].fail(
                        result.error or "Group update failed"
                    )

                return FlextResult[FlextLdapModels.Group].ok(entity)

            except Exception as e:
                self.logger.exception(
                    "Failed to update group", error=str(e), group_dn=entity.dn
                )
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Group update failed: {e}"
                )

        def delete(self, entity_id: str) -> FlextResult[bool]:
            """Delete group by ID.

            Args:
                entity_id: Group DN or CN

            Returns:
                FlextResult with True if deleted

            """
            try:
                # Get group first to ensure it exists
                get_result = self.get_by_id(entity_id)
                if get_result.is_failure:
                    return FlextResult[bool].fail(
                        get_result.error or "Group lookup failed"
                    )

                group = get_result.unwrap()
                if group is None:
                    return FlextResult[bool].ok(False)  # Not found

                result = self._client.delete_group(group.dn)
                if result.is_failure:
                    return FlextResult[bool].fail(
                        result.error or "Group deletion failed"
                    )

                return FlextResult[bool].ok(True)

            except Exception as e:
                self.logger.exception(
                    "Failed to delete group", error=str(e), group_id=id
                )
                return FlextResult[bool].fail(f"Group deletion failed: {e}")
