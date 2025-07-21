"""LDAP Infrastructure Client using ldap3.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Real LDAP operations using ldap3 library.
"""

from __future__ import annotations

from typing import Any

import ldap3  # type: ignore[import-untyped]
from flext_core.domain.types import ServiceResult
from ldap3 import BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPException  # type: ignore[import-untyped]


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
    ) -> ServiceResult[str]:
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

    async def disconnect(self, connection_id: str) -> ServiceResult[bool]:
        """Disconnect from LDAP server.

        Args:
            connection_id: Connection identifier

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            if connection_id in self._connections:
                self._connections[connection_id].unbind()
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
    ) -> ServiceResult[list[dict[str, Any]]]:
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
                search_scope=search_scope,
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
    ) -> ServiceResult[bool]:
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

            success = connection.add(dn, attributes=attributes)

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
    ) -> ServiceResult[bool]:
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

            success = connection.modify(dn, changes)

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
    ) -> ServiceResult[bool]:
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

            success = connection.delete(dn)

            if not success:
                return ServiceResult.fail(f"Delete failed: {connection.result}")

            return ServiceResult.ok(True)

        except LDAPException as e:
            return ServiceResult.fail(f"LDAP delete failed: {e}")
        except Exception as e:
            msg = f"Unexpected delete error: {e}"
            return ServiceResult.fail(msg)

    def get_connection_info(self, connection_id: str) -> ServiceResult[dict[str, Any]]:
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
