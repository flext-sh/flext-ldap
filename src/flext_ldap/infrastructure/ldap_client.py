"""LDAP Infrastructure Client using ldap3.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Real LDAP operations using ldap3 library.
"""

from __future__ import annotations

from typing import Any, Literal, cast

import ldap3
from flext_core.domain.shared_types import ServiceResult
from ldap3 import BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPException


class LDAPInfrastructureClient:
    """Infrastructure client for real LDAP operations using ldap3."""

    def __init__(self) -> None:
        """Initialize LDAP infrastructure client."""
        self._connections: dict[str, ldap3.Connection] = {}

    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
    ) -> ServiceResult[Any]:
        """Connect to LDAP server.

        Args:
            server_url: LDAP server URL
            bind_dn: Distinguished name for binding
            password: Password for binding
            use_ssl: Use SSL/TLS connection

        Returns:
            ServiceResult containing connection ID or error

        """
        try:
            server = ldap3.Server(
                server_url,
                use_ssl=use_ssl,
                get_info=ldap3.ALL,
            )

            connection = ldap3.Connection(
                server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True,
            )

            connection_id = f"{server_url}:{bind_dn or 'anonymous'}"
            self._connections[connection_id] = connection

            return ServiceResult.ok(connection_id)

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP connection failed: {e}")
        except Exception as e:
            msg = f"Unexpected connection error: {e}"
            return ServiceResult.fail(msg)

    async def disconnect(self, connection_id: str) -> ServiceResult[Any]:
        """Disconnect from LDAP server.

        Args:
            connection_id: Connection identifier

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            if connection_id in self._connections:
                self._connections[connection_id].unbind()  # ldap3 library method
                del self._connections[connection_id]
                return ServiceResult.ok(True)
            return ServiceResult.fail("Connection not found")

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP disconnect failed: {e}")
        except Exception as e:
            msg = f"Unexpected disconnect error: {e}"
            return ServiceResult.fail(msg)

    async def search(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
    ) -> ServiceResult[Any]:
        """Search LDAP entries.

        Args:
            connection_id: Connection identifier
            base_dn: Base distinguished name for search
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            scope: Search scope (subtree, onelevel, base)

        Returns:
            ServiceResult containing search results or error

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            scope_map = {
                "subtree": SUBTREE,
                "onelevel": LEVEL,
                "base": BASE,
            }

            search_scope = scope_map.get(scope, SUBTREE)

            success = connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=cast("Literal['BASE', 'LEVEL', 'SUBTREE']", search_scope),
                attributes=attributes or ["*"],
            )

            if not success:
                return ServiceResult.fail(f"Search failed: {connection.result}")

            results = []
            for entry in connection.entries:
                entry_dict = {
                    "dn": str(entry.entry_dn),
                    "attributes": dict(entry.entry_attributes_as_dict),
                }
                results.append(entry_dict)

            return ServiceResult.ok(results)

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP search failed: {e}")
        except Exception as e:
            msg = f"Unexpected search error: {e}"
            return ServiceResult.fail(msg)

    async def add_entry(
        self,
        connection_id: str,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> ServiceResult[Any]:
        """Add LDAP entry.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to add
            attributes: Entry attributes

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            success = connection.add(dn, attributes=attributes)  # ldap3 library method

            if not success:
                return ServiceResult.fail(f"Add failed: {connection.result}")

            return ServiceResult.ok(True)

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP add failed: {e}")
        except Exception as e:
            msg = f"Unexpected add error: {e}"
            return ServiceResult.fail(msg)

    async def modify_entry(
        self,
        connection_id: str,
        dn: str,
        changes: dict[str, Any],
    ) -> ServiceResult[Any]:
        """Modify LDAP entry.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            success = connection.modify(dn, changes)  # ldap3 library method

            if not success:
                return ServiceResult.fail(f"Modify failed: {connection.result}")

            return ServiceResult.ok(True)

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP modify failed: {e}")
        except Exception as e:
            msg = f"Unexpected modify error: {e}"
            return ServiceResult.fail(msg)

    async def delete_entry(
        self,
        connection_id: str,
        dn: str,
    ) -> ServiceResult[Any]:
        """Delete LDAP entry.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            success = connection.delete(dn)  # ldap3 library method

            if not success:
                return ServiceResult.fail(f"Delete failed: {connection.result}")

            return ServiceResult.ok(True)

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP delete failed: {e}")
        except Exception as e:
            msg = f"Unexpected delete error: {e}"
            return ServiceResult.fail(msg)

    def get_connection_info(self, connection_id: str) -> ServiceResult[Any]:
        """Get connection information.

        Args:
            connection_id: Connection identifier

        Returns:
            ServiceResult containing connection info or error

        """
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return ServiceResult.fail("Connection not found")

            info = {
                "server": str(connection.server),
                "bound": connection.bound,
                "user": connection.user,
                "strategy": str(connection.strategy),
                "server_info": (
                    connection.server.info.to_dict() if connection.server.info else None
                ),
            }

            return ServiceResult.ok(info)

        except Exception as e:
            msg = f"Unexpected error getting connection info: {e}"
            return ServiceResult.fail(msg)

    # High-level user operations
    async def create_user(
        self,
        connection: Any,  # LDAPConnection entity
        request: Any,  # CreateUserRequest value object
    ) -> ServiceResult[Any]:  # Returns LDAPUser entity
        """Create LDAP user using basic operations.

        Args:
            connection: LDAP connection entity
            request: User creation request

        Returns:
            ServiceResult containing created LDAPUser or error

        """
        try:
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPUser

            # Build LDAP attributes from request
            attributes = {
                "objectClass": request.object_classes or ["inetOrgPerson"],
                "uid": [request.uid],
                "cn": [request.cn],
                "sn": [request.sn],
            }

            # Add optional attributes
            if request.mail:
                attributes["mail"] = [request.mail]
            if request.phone:
                attributes["telephoneNumber"] = [request.phone]
            if request.ou:
                attributes["ou"] = [request.ou]
            if request.department:
                attributes["departmentNumber"] = [request.department]
            if request.title:
                attributes["title"] = [request.title]

            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Add entry to LDAP
            result = await self.add_entry(connection_id, request.dn, attributes)
            if not result.success:
                return ServiceResult.fail(
                    f"Failed to create user in LDAP: {result.error}",
                )

            # Create and return domain entity
            user = LDAPUser(
                id=uuid4(),
                dn=request.dn,
                uid=request.uid,
                cn=request.cn,
                sn=request.sn,
                mail=request.mail,
                phone=request.phone,
                ou=request.ou,
                department=request.department,
                title=request.title,
                object_classes=request.object_classes or ["inetOrgPerson"],
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            return ServiceResult.ok(user)

        except Exception as e:
            msg = f"Failed to create user: {e}"
            return ServiceResult.fail(msg)

    async def find_user_by_dn(
        self,
        connection: Any,  # LDAPConnection entity
        dn: str,
    ) -> ServiceResult[Any]:  # Returns LDAPUser | None
        """Find user by distinguished name.

        Args:
            connection: LDAP connection entity
            dn: Distinguished name to search for

        Returns:
            ServiceResult containing LDAPUser if found, None if not found, or error

        """
        try:
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPUser

            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Search for user by DN
            result = await self.search(
                connection_id,
                dn,
                "(objectClass=*)",
                attributes=[
                    "uid",
                    "cn",
                    "sn",
                    "mail",
                    "telephoneNumber",
                    "ou",
                    "departmentNumber",
                    "title",
                    "objectClass",
                ],
                scope="base",
            )

            if not result.success:
                return ServiceResult.fail(f"Failed to search user: {result.error}")

            entries = result.data
            if not entries:
                return ServiceResult.ok(None)

            # Convert LDAP entry to domain entity
            entry = entries[0]
            attrs = entry["attributes"]

            user = LDAPUser(
                id=uuid4(),
                dn=entry["dn"],
                uid=attrs.get("uid", [None])[0],
                cn=attrs.get("cn", [None])[0],
                sn=attrs.get("sn", [None])[0],
                mail=attrs.get("mail", [None])[0],
                phone=attrs.get("telephoneNumber", [None])[0],
                ou=attrs.get("ou", [None])[0],
                department=attrs.get("departmentNumber", [None])[0],
                title=attrs.get("title", [None])[0],
                object_classes=attrs.get("objectClass", ["inetOrgPerson"]),
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            return ServiceResult.ok(user)

        except Exception as e:
            msg = f"Failed to find user by DN: {e}"
            return ServiceResult.fail(msg)

    async def find_user_by_uid(
        self,
        connection: Any,  # LDAPConnection entity
        uid: str,
    ) -> ServiceResult[Any]:  # Returns LDAPUser | None
        """Find user by UID attribute.

        Args:
            connection: LDAP connection entity
            uid: User identifier to search for

        Returns:
            ServiceResult containing LDAPUser if found, None if not found, or error

        """
        try:
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPUser

            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Search for user by UID in a common base
            # Use server base DN or a default
            base_dn = "dc=example,dc=com"  # This should come from configuration
            search_filter = f"(uid={uid})"

            result = await self.search(
                connection_id,
                base_dn,
                search_filter,
                attributes=[
                    "uid",
                    "cn",
                    "sn",
                    "mail",
                    "telephoneNumber",
                    "ou",
                    "departmentNumber",
                    "title",
                    "objectClass",
                ],
            )

            if not result.success:
                return ServiceResult.fail(f"Failed to search user: {result.error}")

            entries = result.data
            if not entries:
                return ServiceResult.ok(None)

            # Convert first matching LDAP entry to domain entity
            entry = entries[0]
            attrs = entry["attributes"]

            user = LDAPUser(
                id=uuid4(),
                dn=entry["dn"],
                uid=attrs.get("uid", [None])[0],
                cn=attrs.get("cn", [None])[0],
                sn=attrs.get("sn", [None])[0],
                mail=attrs.get("mail", [None])[0],
                phone=attrs.get("telephoneNumber", [None])[0],
                ou=attrs.get("ou", [None])[0],
                department=attrs.get("departmentNumber", [None])[0],
                title=attrs.get("title", [None])[0],
                object_classes=attrs.get("objectClass", ["inetOrgPerson"]),
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

            return ServiceResult.ok(user)

        except Exception as e:
            msg = f"Failed to find user by UID: {e}"
            return ServiceResult.fail(msg)

    async def list_users(
        self,
        connection: Any,  # LDAPConnection entity
        base_dn: str | None = None,
        limit: int = 100,
    ) -> ServiceResult[list[Any]]:  # Returns list[LDAPUser]
        """List users in organizational unit.

        Args:
            connection: LDAP connection entity
            base_dn: Base DN to search in
            limit: Maximum number of users to return

        Returns:
            ServiceResult containing list of LDAPUsers or error

        """
        try:
            from datetime import UTC, datetime
            from uuid import uuid4

            from flext_ldap.domain.entities import LDAPUser

            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Use provided base DN or default
            search_base = base_dn or "dc=example,dc=com"
            search_filter = "(objectClass=inetOrgPerson)"

            result = await self.search(
                connection_id,
                search_base,
                search_filter,
                attributes=[
                    "uid",
                    "cn",
                    "sn",
                    "mail",
                    "telephoneNumber",
                    "ou",
                    "departmentNumber",
                    "title",
                    "objectClass",
                ],
            )

            if not result.success:
                return ServiceResult.fail(f"Failed to list users: {result.error}")

            entries = result.data or []
            users = []

            # Convert entries to domain entities, respecting limit
            for entry in entries[:limit]:
                attrs = entry["attributes"]
                user = LDAPUser(
                    id=uuid4(),
                    dn=entry["dn"],
                    uid=attrs.get("uid", [None])[0],
                    cn=attrs.get("cn", [None])[0],
                    sn=attrs.get("sn", [None])[0],
                    mail=attrs.get("mail", [None])[0],
                    phone=attrs.get("telephoneNumber", [None])[0],
                    ou=attrs.get("ou", [None])[0],
                    department=attrs.get("departmentNumber", [None])[0],
                    title=attrs.get("title", [None])[0],
                    object_classes=attrs.get("objectClass", ["inetOrgPerson"]),
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
                users.append(user)

            return ServiceResult.ok(users)

        except Exception as e:
            msg = f"Failed to list users: {e}"
            return ServiceResult.fail(msg)

    async def update_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID
        updates: dict[str, Any],
    ) -> ServiceResult[Any]:  # Returns LDAPUser
        """Update user attributes.

        Args:
            connection: LDAP connection entity
            user_id: User UUID (not used for LDAP operations)
            updates: Dictionary of attributes to update

        Returns:
            ServiceResult containing updated LDAPUser or error

        """
        # For now, return a basic implementation
        # In a real implementation, you would need to find the user by ID first
        # and then use modify_entry to update the LDAP entry
        return ServiceResult.fail("User update operations not yet fully implemented")

    async def delete_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID - either UUID or DN string
    ) -> ServiceResult[Any]:
        """Delete user from LDAP.

        Args:
            connection: LDAP connection entity
            user_id: User identifier (UUID or DN)

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # If user_id is a DN string, use it directly
            # Otherwise, this would require finding the user first
            if isinstance(user_id, str) and "=" in user_id:
                dn = user_id
            else:
                # For UUID, we would need to find the user first
                return ServiceResult.fail(
                    "Delete by UUID not yet implemented - use DN instead",
                )

            # Delete entry from LDAP
            result = await self.delete_entry(connection_id, dn)
            if not result.success:
                return ServiceResult.fail(
                    f"Failed to delete user from LDAP: {result.error}",
                )

            return ServiceResult.ok(True)

        except Exception as e:
            msg = f"Failed to delete user: {e}"
            return ServiceResult.fail(msg)

    async def lock_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID
    ) -> ServiceResult[Any]:  # Returns LDAPUser
        """Lock user account.

        Args:
            connection: LDAP connection entity
            user_id: User UUID

        Returns:
            ServiceResult containing locked LDAPUser or error

        """
        # Lock operations would typically modify userAccountControl or similar attributes
        return ServiceResult.fail("User lock operations not yet implemented")

    async def unlock_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID
    ) -> ServiceResult[Any]:  # Returns LDAPUser
        """Unlock user account.

        Args:
            connection: LDAP connection entity
            user_id: User UUID

        Returns:
            ServiceResult containing unlocked LDAPUser or error

        """
        # Unlock operations would typically modify userAccountControl or similar attributes
        return ServiceResult.fail("User unlock operations not yet implemented")
