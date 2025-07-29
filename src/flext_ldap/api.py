"""FLEXT-LDAP API - Unified Enterprise Interface.

Single point of entry for all LDAP operations using flext-core patterns.
Eliminates code duplication by consolidating multiple API layers.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from flext_core import FlextResult, get_flext_container, get_logger

from flext_ldap.entities import (
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient
from flext_ldap.values import FlextLdapCreateUserRequest, FlextLdapDistinguishedName

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from flext_ldap.config import FlextLdapConnectionConfig

logger = get_logger(__name__)


class FlextLdapApi:
    """Unified LDAP API using flext-core patterns.

    Single interface that consolidates all LDAP operations with:
    - Type-safe error handling via FlextResult
    - Domain-driven design with rich entities
    - Enterprise dependency injection via flext-core
    - Connection pooling and management
    """

    def __init__(self, config: FlextLdapConnectionConfig | None = None) -> None:
        """Initialize LDAP API with optional configuration."""
        self._client = FlextLdapSimpleClient()
        self._config = config
        self._connections: dict[str, str] = {}  # session_id -> connection_id
        self._container = get_flext_container()

        # Register self in container for dependency injection
        self._container.register("ldap_api", self)

        logger.info("FlextLdapApi initialized")

    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
        session_id: str | None = None,
    ) -> FlextResult[str]:
        """Connect to LDAP server with session management.

        Args:
            server_url: LDAP server URL
            bind_dn: Bind DN for authentication
            password: Password for authentication
            session_id: Optional session identifier

        Returns:
            FlextResult containing session ID

        """
        try:
            # Create connection
            result = await self._client.connect(server_url, bind_dn, password)
            if not result.is_success:
                return FlextResult.fail(f"Connection failed: {result.error}")

            # Manage session
            session = session_id or str(uuid4())
            self._connections[session] = result.data

            logger.info("Connected to LDAP server", extra={"session_id": session})
            return FlextResult.ok(session)

        except ConnectionError as e:
            return FlextResult.fail(f"Connection error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Network error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Configuration error: {e}")

    async def disconnect(self, session_id: str) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            connection_id = self._connections[session_id]
            result = await self._client.disconnect(connection_id)

            if result.is_success:
                del self._connections[session_id]
                logger.info("Disconnected from LDAP server", extra={"session_id": session_id})

            return result

        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Disconnect error: {e}")

    @asynccontextmanager
    async def connection(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> AsyncIterator[str]:
        """Async context manager for LDAP connections."""
        connect_result = await self.connect(server_url, bind_dn, password)
        if not connect_result.is_success:
            msg = f"Failed to connect: {connect_result.error}"
            raise RuntimeError(msg)

        session_id = connect_result.data
        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    async def search(
        self,
        session_id: str,
        base_dn: str | FlextLdapDistinguishedName,
        filter_expr: str,
        attributes: list[str] | None = None,
        scope: str = "sub",
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Search LDAP directory with rich domain objects.

        Returns FlextLdapEntry entities instead of raw dictionaries.
        """
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            connection_id = self._connections[session_id]
            base_str = str(base_dn) if isinstance(base_dn, FlextLdapDistinguishedName) else base_dn

            result = await self._client.search(
                connection_id, base_str, filter_expr, attributes or ["*"], scope,
            )

            if not result.is_success:
                return FlextResult.fail(result.error)

            # Convert to domain entities
            entries = []
            for raw_entry in result.data:
                entry = FlextLdapEntry(
                    dn=raw_entry.get("dn", ""),
                    object_classes=raw_entry.get("attributes", {}).get("objectClass", []),
                    attributes=raw_entry.get("attributes", {}),
                    id=str(uuid4()),  # FlextEntity requires id
                )
                entries.append(entry)

            return FlextResult.ok(entries)

        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Search error: {e}")

    async def create_user(
        self,
        session_id: str,
        user_request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create user with domain validation and business rules."""
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            connection_id = self._connections[session_id]

            # Prepare LDAP attributes
            attributes = {
                "objectClass": ["inetOrgPerson", "person", "organizationalPerson"],
                "uid": [user_request.uid],
                "cn": [user_request.cn],
                "sn": [user_request.sn],
            }

            if user_request.mail:
                attributes["mail"] = [user_request.mail]
            if user_request.phone:
                attributes["telephoneNumber"] = [user_request.phone]
            if user_request.department:
                attributes["departmentNumber"] = [user_request.department]
            if user_request.title:
                attributes["title"] = [user_request.title]

            # Create entry
            result = await self._client.add_entry(connection_id, user_request.dn, attributes)

            if not result.is_success:
                return FlextResult.fail(f"User creation failed: {result.error}")

            # Create domain entity
            user = FlextLdapUser(
                id=str(uuid4()),
                dn=user_request.dn,
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                mail=user_request.mail,
                phone=user_request.phone,
                department=user_request.department,
                title=user_request.title,
                object_classes=attributes["objectClass"],
                attributes=attributes,
            )

            logger.info("User created", extra={"user_dn": user_request.dn})
            return FlextResult.ok(user)

        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"User creation error: {e}")

    async def update_user(
        self,
        session_id: str,
        user_dn: str | FlextLdapDistinguishedName,
        updates: dict[str, Any],
    ) -> FlextResult[None]:
        """Update user with LDAP modify operations."""
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            connection_id = self._connections[session_id]
            dn_str = str(user_dn) if isinstance(user_dn, FlextLdapDistinguishedName) else user_dn

            # Convert updates to LDAP modify format
            modifications = {}
            for attr, value in updates.items():
                if isinstance(value, list):
                    modifications[attr] = [(3, value)]  # MODIFY_REPLACE
                else:
                    modifications[attr] = [(3, [str(value)])]  # MODIFY_REPLACE

            result = await self._client.modify_entry(connection_id, dn_str, modifications)

            if result.is_success:
                logger.info("User updated", extra={"user_dn": dn_str})

            return result

        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"User update error: {e}")

    async def delete_user(
        self,
        session_id: str,
        user_dn: str | FlextLdapDistinguishedName,
    ) -> FlextResult[None]:
        """Delete user from LDAP directory."""
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            connection_id = self._connections[session_id]
            dn_str = str(user_dn) if isinstance(user_dn, FlextLdapDistinguishedName) else user_dn

            result = await self._client.delete_entry(connection_id, dn_str)

            if result.is_success:
                logger.info("User deleted", extra={"user_dn": dn_str})

            return result

        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"User deletion error: {e}")

    async def create_group(
        self,
        session_id: str,
        dn: str | FlextLdapDistinguishedName,
        cn: str,
        description: str | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        """Create LDAP group with domain validation."""
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            connection_id = self._connections[session_id]
            dn_str = str(dn) if isinstance(dn, FlextLdapDistinguishedName) else dn

            # Prepare attributes
            attributes = {
                "objectClass": ["groupOfNames"],
                "cn": [cn],
            }

            if description:
                attributes["description"] = [description]

            # Groups require at least one member initially
            attributes["member"] = [""]  # Empty member initially

            result = await self._client.add_entry(connection_id, dn_str, attributes)

            if not result.is_success:
                return FlextResult.fail(f"Group creation failed: {result.error}")

            # Create domain entity
            group = FlextLdapGroup(
                id=str(uuid4()),
                dn=dn_str,
                cn=cn,
                description=description,
                members=[],
                object_classes=attributes["objectClass"],
                attributes=attributes,
            )

            logger.info("Group created", extra={"group_dn": dn_str})
            return FlextResult.ok(group)

        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Group creation error: {e}")

    def health(self) -> FlextResult[dict[str, Any]]:
        """Health check with connection status."""
        try:
            health_data = {
                "status": "healthy",
                "active_sessions": len(self._connections),
                "container_registered": self._container.get("ldap_api").is_success,
                "version": "0.8.0",
                "features": [
                    "unified_api",
                    "domain_entities",
                    "session_management",
                    "flext_core_integration",
                ],
            }
            return FlextResult.ok(health_data)
        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Health check failed: {e}")

    async def add_entry(
        self,
        session_id: str,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[bool]:
        """Generic add entry method for LDAP operations.

        Args:
            session_id: Active session identifier
            dn: Distinguished name for the new entry
            attributes: Dictionary of attribute name to values list

        Returns:
            FlextResult containing success status

        """
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            # Extract objectClass from attributes
            object_classes = attributes.get("objectClass", ["top"])
            if not isinstance(object_classes, list):
                object_classes = [str(object_classes)]

            # Use the client add method with correct signature
            self._connections[session_id]
            result = await self._client.add(dn, object_classes, attributes)

            if result.is_success:
                logger.debug("Added entry: %s", dn)
                return FlextResult.ok(data=True)
            return FlextResult.fail(f"Failed to add entry: {result.error}")

        except (ConnectionError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Add entry failed: {e}")

    async def modify_entry(
        self,
        session_id: str,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[bool]:
        """Generic modify entry method for LDAP operations.

        Args:
            session_id: Active session identifier
            dn: Distinguished name for the entry to modify
            attributes: Dictionary of attribute name to values list for modification

        Returns:
            FlextResult containing success status

        """
        try:
            if session_id not in self._connections:
                return FlextResult.fail(f"Session {session_id} not found")

            # Use the client modify method with correct signature
            self._connections[session_id]
            result = await self._client.modify(dn, attributes)

            if result.is_success:
                logger.debug("Modified entry: %s", dn)
                return FlextResult.ok(data=True)
            return FlextResult.fail(f"Failed to modify entry: {result.error}")

        except (ConnectionError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Modify entry failed: {e}")


# Factory function for easy instantiation
def get_ldap_api(config: FlextLdapConnectionConfig | None = None) -> FlextLdapApi:
    """Get or create LDAP API instance with dependency injection."""
    container = get_flext_container()

    # Try to get existing instance
    existing_result = container.get("ldap_api")
    if existing_result.is_success:
        return existing_result.data

    # Create new instance
    return FlextLdapApi(config)


__all__ = ["FlextLdapApi", "get_ldap_api"]
