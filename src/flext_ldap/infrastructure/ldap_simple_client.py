"""Minimal LDAP Infrastructure Client - Clean Architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Minimal infrastructure client that wraps ldap3 with only essential operations.
Domain logic moved to application services following clean architecture.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import ldap3  # type: ignore[import-untyped]
from flext_core import FlextResult, get_logger
from ldap3 import (
    ALL,
    AUTO_BIND_NONE,
    ROUND_ROBIN,
    Connection,
    Server,
    ServerPool,
    Tls,
)
from ldap3.core.exceptions import LDAPException  # type: ignore[import-untyped]

logger = get_logger(__name__)


@dataclass
class LdapConnectionConfig:
    """Configuration for LDAP connection."""

    server_url: str
    bind_dn: str | None = None
    password: str | None = None
    use_ssl: bool = False
    tls_config: Tls | None = None
    connection_timeout: int = 10
    start_tls: bool = False


@dataclass
class LdapPoolConfig:
    """Configuration for LDAP connection pool."""

    server_urls: list[str]
    bind_dn: str | None = None
    password: str | None = None
    use_ssl: bool = False
    tls_config: Tls | None = None
    connection_timeout: int = 10


@dataclass
class LdapConnectionInfo:
    """Connection information for compatibility methods."""

    server_url: str
    bind_dn: str | None = None


class FlextLdapSimpleClient:
    """Minimal LDAP infrastructure client using clean architecture.

    Only provides basic LDAP operations. Domain logic handled by application services.
    Eliminates the 1,282-line architecture violation.
    """

    def __init__(self) -> None:
        """Initialize minimal LDAP client."""
        self._connections: dict[str, Connection] = {}
        self._servers: dict[str, Server] = {}
        # Compatibility mappings for test support
        self._uuid_to_dn: dict[str, str] = {}
        self._dn_to_uuid: dict[str, str] = {}

    async def connect(self, config: LdapConnectionConfig) -> FlextResult[str]:
        """Connect to LDAP server using ldap3 directly.

        Returns:
            FlextResult containing connection ID or error

        """
        try:
            server = Server(
                config.server_url,
                use_ssl=config.use_ssl,
                get_info=ALL,
                tls=config.tls_config,
                connect_timeout=config.connection_timeout,
            )

            connection = Connection(
                server,
                user=config.bind_dn,
                password=config.password,
                auto_bind=AUTO_BIND_NONE,
                raise_exceptions=True,
                read_only=False,
            )

            if not connection.bind():
                return FlextResult.fail(f"LDAP bind failed: {connection.result}")

            if config.start_tls and not config.use_ssl and not connection.start_tls():
                return FlextResult.fail(f"StartTLS failed: {connection.result}")

            connection_id = f"{config.server_url}:{config.bind_dn or 'anonymous'}"
            self._connections[connection_id] = connection
            self._servers[f"{config.server_url}:{config.use_ssl}"] = server

            logger.info("Connected to LDAP server: %s", config.server_url)
            return FlextResult.ok(connection_id)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP connection failed: {e}")

    async def connect_with_pool(self, config: LdapPoolConfig) -> FlextResult[str]:
        """Connect using ldap3's ServerPool for high availability."""
        try:
            server_pool = ServerPool(None, ROUND_ROBIN, active=True)

            for server_url in config.server_urls:
                server = Server(
                    server_url,
                    use_ssl=config.use_ssl,
                    get_info=ALL,
                    tls=config.tls_config,
                    connect_timeout=config.connection_timeout,
                )
                server_pool.add(server)

            connection = Connection(
                server_pool,
                user=config.bind_dn,
                password=config.password,
                auto_bind=AUTO_BIND_NONE,
                raise_exceptions=True,
            )

            if not connection.bind():
                return FlextResult.fail(f"Pool bind failed: {connection.result}")

            pool_id = f"pool:{','.join(config.server_urls)}"
            self._connections[pool_id] = connection

            logger.info("Connected to LDAP pool: %s", config.server_urls)
            return FlextResult.ok(pool_id)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP pool connection failed: {e}")

    async def disconnect(self, connection_id: str) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        try:
            if connection_id in self._connections:
                connection = self._connections[connection_id]
                connection.unbind()
                del self._connections[connection_id]
                logger.info("Disconnected from LDAP: %s", connection_id)
            return FlextResult.ok(None)

        except LDAPException as e:
            return FlextResult.fail(f"Disconnect failed: {e}")

    async def search(
        self,
        connection_id: str,
        search_base: str,
        search_filter: str,
        attributes: list[str] | None = None,
        *,
        scope: str = "SUBTREE",
    ) -> FlextResult[list[dict[str, Any]]]:
        """Search LDAP directory."""
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail(f"Connection {connection_id} not found")

            # Map scope string to ldap3 constant
            scope_map = {
                "BASE": ldap3.BASE,
                "LEVEL": ldap3.LEVEL,
                "SUBTREE": ldap3.SUBTREE,
            }
            ldap_scope = scope_map.get(scope, ldap3.SUBTREE)

            success = connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap_scope,
                attributes=attributes or ["*"],
            )

            if not success:
                return FlextResult.fail(f"Search failed: {connection.result}")

            # Convert ldap3 entries to simple dictionaries
            results = []
            for entry in connection.entries:
                entry_dict = {
                    "dn": entry.entry_dn,
                    "attributes": dict(entry.entry_attributes_as_dict),
                }
                results.append(entry_dict)

            return FlextResult.ok(results)

        except LDAPException as e:
            return FlextResult.fail(f"Search failed: {e}")

    async def add(
        self,
        connection_id: str,
        dn: str,
        object_class: list[str],
        attributes: dict[str, Any],
    ) -> FlextResult[None]:
        """Add entry to LDAP directory."""
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail(f"Connection {connection_id} not found")

            # Prepare attributes for ldap3
            ldap_attributes = {"objectClass": object_class}
            ldap_attributes.update(attributes)

            success = connection.add(dn, ldap_attributes)
            if not success:
                return FlextResult.fail(f"Add failed: {connection.result}")

            logger.info("Added entry: %s", dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            return FlextResult.fail(f"Add operation failed: {e}")

    async def modify(
        self,
        connection_id: str,
        dn: str,
        changes: dict[str, Any],
    ) -> FlextResult[None]:
        """Modify entry in LDAP directory."""
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail(f"Connection {connection_id} not found")

            # Convert changes to ldap3 format
            ldap_changes = {}
            for attr, value in changes.items():
                if isinstance(value, list):
                    ldap_changes[attr] = [(ldap3.MODIFY_REPLACE, value)]
                else:
                    ldap_changes[attr] = [(ldap3.MODIFY_REPLACE, [value])]

            success = connection.modify(dn, ldap_changes)
            if not success:
                return FlextResult.fail(f"Modify failed: {connection.result}")

            logger.info("Modified entry: %s", dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            return FlextResult.fail(f"Modify operation failed: {e}")

    async def delete(
        self,
        connection_id: str,
        dn: str,
    ) -> FlextResult[None]:
        """Delete entry from LDAP directory."""
        try:
            connection = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail(f"Connection {connection_id} not found")

            success = connection.delete(dn)
            if not success:
                return FlextResult.fail(f"Delete failed: {connection.result}")

            logger.info("Deleted entry: %s", dn)
            return FlextResult.ok(None)

        except LDAPException as e:
            return FlextResult.fail(f"Delete operation failed: {e}")

    def is_connected(self, connection_id: str) -> bool:
        """Check if connection is active."""
        connection = self._connections.get(connection_id)
        return connection is not None and connection.bound

    async def close_all(self) -> None:
        """Close all connections."""
        for connection_id in list(self._connections.keys()):
            await self.disconnect(connection_id)
        self._connections.clear()
        self._servers.clear()
        logger.info("All LDAP connections closed")

    # ========================================
    # COMPATIBILITY METHODS FOR TESTS ONLY
    # ========================================
    # These methods provide compatibility with existing tests
    # In production, domain operations should use application services

    def _register_uuid_dn_mapping(self, entity_uuid: str, dn: str) -> None:
        """Register UUID to DN mapping for entity tracking (test compatibility)."""
        self._uuid_to_dn[entity_uuid] = dn
        self._dn_to_uuid[dn] = entity_uuid

    def _get_dn_from_uuid(self, entity_uuid: str) -> str | None:
        """Get DN from UUID mapping (test compatibility)."""
        return self._uuid_to_dn.get(entity_uuid)

    def _resolve_user_identifier(
        self,
        user_id: str | int | bytes,
    ) -> FlextResult[str]:
        """Resolve user identifier to DN (test compatibility)."""
        try:
            if isinstance(user_id, str):
                if "=" in user_id:
                    return FlextResult.ok(user_id)
                dn = self._get_dn_from_uuid(user_id)
                if dn:
                    return FlextResult.ok(dn)
                return FlextResult.fail(f"UUID {user_id} not found")
            return FlextResult.fail(
                f"Cannot resolve identifier {user_id.decode() if isinstance(user_id, bytes) else user_id}",
            )
        except (ValueError, AttributeError) as e:
            return FlextResult.fail(f"Failed to resolve user identifier: {e}")

    async def create_user(
        self,
        _connection: object,
        _user_request: object,
    ) -> FlextResult[object]:
        """Create user (test compatibility - domain logic should be in application services)."""
        return FlextResult.fail("Use application services for domain operations")

    async def find_user_by_dn(
        self,
        _connection: object,
        _dn: str,
    ) -> FlextResult[object]:
        """Find user by DN (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def find_user_by_uid(
        self,
        _connection: object,
        _uid: str,
    ) -> FlextResult[object]:
        """Find user by UID (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def list_users(
        self,
        _connection: object,
        _base_dn: str,
    ) -> FlextResult[object]:
        """List users (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def update_user(
        self,
        _connection: object,
        _user_id: str,
        _updates: dict[str, object],
    ) -> FlextResult[object]:
        """Update user (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def delete_user(
        self,
        connection: LdapConnectionInfo,
        user_id: str,
    ) -> FlextResult[None]:
        """Delete user (test compatibility)."""
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Resolve user identifier to DN using UUID->DN mapping
            resolve_result = self._resolve_user_identifier(user_id)
            if not resolve_result.success:
                return FlextResult.fail(
                    resolve_result.error or "Failed to resolve user identifier",
                )

            dn = resolve_result.data
            if not isinstance(dn, str):
                return FlextResult.fail("DN must be a string")

            # Delete entry from LDAP using the infrastructure method
            return await self.delete(connection_id, dn)

        except (AttributeError, ValueError) as e:
            return FlextResult.fail(f"Failed to delete user: {e}")

    async def lock_user(
        self,
        _connection: object,
        _user_id: str,
    ) -> FlextResult[None]:
        """Lock user (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def unlock_user(
        self,
        _connection: object,
        _user_id: str,
    ) -> FlextResult[None]:
        """Unlock user (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def create_group(
        self,
        _connection: object,
        _group_request: object,
    ) -> FlextResult[None]:
        """Create group (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def find_group_by_dn(
        self,
        _connection: object,
        _dn: str,
    ) -> FlextResult[None]:
        """Find group by DN (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def add_member_to_group(
        self,
        _connection: object,
        _group_dn: str,
        _member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")

    async def delete_group(
        self,
        _connection: object,
        _group_id: str,
    ) -> FlextResult[None]:
        """Delete group (test compatibility)."""
        return FlextResult.fail("Use application services for domain operations")


# Backward compatibility alias
FlextLdapInfrastructureClient = FlextLdapSimpleClient
