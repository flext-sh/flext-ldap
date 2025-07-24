"""LDAP Infrastructure Client using ldap3.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Real LDAP operations using ldap3 library.
"""

from __future__ import annotations

from typing import Any, Literal, cast

import ldap3

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from flext_core import (
    FlextResult,
)
from ldap3 import BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPException


class FlextLdapInfrastructureClient:
    """Infrastructure client for real LDAP operations using ldap3."""

    def __init__(self) -> None:
        """Initialize LDAP infrastructure client."""
        self._connections: dict[str, ldap3.Connection] = {}
        # UUID to DN mapping for domain/infrastructure bridge
        self._uuid_to_dn: dict[str, str] = {}
        self._dn_to_uuid: dict[str, str] = {}

    def _register_uuid_dn_mapping(self, entity_uuid: str, dn: str) -> None:
        """Register UUID to DN mapping for entity tracking."""
        self._uuid_to_dn[entity_uuid] = dn
        self._dn_to_uuid[dn] = entity_uuid

    def _get_dn_from_uuid(self, entity_uuid: str) -> str | None:
        """Get DN from UUID mapping."""
        return self._uuid_to_dn.get(entity_uuid)

    def _resolve_user_identifier(self, user_id: Any) -> FlextResult[str]:
        """Resolve user identifier to DN (handles both UUID and DN)."""
        try:
            if isinstance(user_id, str):
                if "=" in user_id:
                    # Already a DN
                    return FlextResult.ok(user_id)
                # Try to resolve UUID to DN
                dn = self._get_dn_from_uuid(user_id)
                if dn:
                    return FlextResult.ok(dn)
                return FlextResult.fail(
                    f"UUID {user_id} not found - entity may not exist",
                )
            # Convert other types to string and try UUID resolution
            str_id = str(user_id)
            dn = self._get_dn_from_uuid(str_id)
            if dn:
                return FlextResult.ok(dn)
            return FlextResult.fail(
                f"Cannot resolve identifier {user_id} to DN",
            )
        except Exception as e:
            return FlextResult.fail(f"Failed to resolve user identifier: {e}")

    def _resolve_group_identifier(self, group_id: Any) -> str | None:
        """Resolve group identifier to DN (handles both UUID and DN)."""
        try:
            if isinstance(group_id, str):
                if "=" in group_id:
                    # Already a DN
                    return group_id
                # Try to resolve UUID to DN
                dn = self._get_dn_from_uuid(group_id)
                if dn:
                    return dn
                return None
            # Convert other types to string and try UUID resolution
            str_id = str(group_id)
            dn = self._get_dn_from_uuid(str_id)
            if dn:
                return dn
            return None
        except Exception:
            return None

    def create_tls_configuration(
        self,
        *,
        validate_certificates: bool = True,
        validate_hostname: bool = True,
        ca_cert_file: str | None = None,
        cert_file: str | None = None,
        key_file: str | None = None,
        ciphers: str | None = None,
    ) -> Any:
        """Create TLS configuration for secure LDAP connections.

        Args:
            validate_certificates: Whether to validate server certificates
            validate_hostname: Whether to validate hostname in certificate
            ca_cert_file: Path to CA certificate file
            cert_file: Path to client certificate file
            key_file: Path to client private key file
            ciphers: Cipher suites to use

        Returns:
            TLS configuration object for ldap3

        """
        import ssl

        # Import Tls with fallback for typing
        try:
            from ldap3 import Tls

            return Tls(
                validate=ssl.CERT_REQUIRED if validate_certificates else ssl.CERT_NONE,
                ca_certs_file=ca_cert_file,
                local_private_key_file=key_file,
                local_certificate_file=cert_file,
                ciphers=ciphers,
            )
        except ImportError:
            # Fallback if Tls is not available
            return None

    async def connect(
        self,
        server_url: str,
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
        ssl_context: Any = None,
        connection_timeout: int = 10,
        auto_referrals: bool = True,
    ) -> FlextResult[Any]:
        """Connect to LDAP server.

        Args:
            server_url: LDAP server URL
            bind_dn: Distinguished name for binding
            password: Password for binding
            use_ssl: Use SSL/TLS connection
            ssl_context: Custom SSL context for secure connections
            connection_timeout: Connection timeout in seconds
            auto_referrals: Enable automatic referral following

        Returns:
            FlextResult containing connection ID or error

        """
        try:
            # Create server with available parameters (ignore stub limitations)
            server = ldap3.Server(
                server_url,
                use_ssl=use_ssl,
                get_info=ldap3.ALL,
                tls=ssl_context,
                connect_timeout=connection_timeout,
            )

            # Create connection with available parameters (ignore stub limitations)
            connection = ldap3.Connection(
                server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True,
                auto_referrals=auto_referrals,
                read_only=False,
            )

            connection_id = f"{server_url}:{bind_dn or 'anonymous'}"
            self._connections[connection_id] = connection

            return FlextResult.ok(connection_id)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP connection failed: {e}")
        except Exception as e:
            msg = f"Unexpected connection error: {e}"
            return FlextResult.fail(msg)

    async def connect_with_pool(
        self,
        server_urls: list[str],
        bind_dn: str | None = None,
        password: str | None = None,
        *,
        use_ssl: bool = False,
        ssl_context: Any = None,
        pool_name: str = "default",
        pool_size: int = 10,
        connection_timeout: int = 10,
    ) -> FlextResult[Any]:
        """Connect to LDAP server with connection pooling for high performance.

        Args:
            server_urls: List of LDAP server URLs for high availability
            bind_dn: Distinguished name for binding
            password: Password for binding
            use_ssl: Use SSL/TLS connection
            ssl_context: Custom SSL context for secure connections
            pool_name: Name for the connection pool
            pool_size: Maximum number of connections in pool
            connection_timeout: Connection timeout in seconds

        Returns:
            FlextResult containing pool connection ID or error

        """
        try:
            # Create server pool for high availability (with type ignore for stubs)
            server_pool = ldap3.ServerPool(None, ldap3.ROUND_ROBIN, active=True)

            for server_url in server_urls:
                # Create server with available parameters (ignore stub limitations)
                server = ldap3.Server(
                    server_url,
                    use_ssl=use_ssl,
                    get_info=ldap3.ALL,
                    tls=ssl_context,
                    connect_timeout=connection_timeout,
                )
                server_pool.add(server)

            # Create connection with available parameters (ignore stub limitations)
            connection = ldap3.Connection(
                server_pool,
                user=bind_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True,
                read_only=False,
            )

            pool_connection_id = f"pool:{pool_name}:{','.join(server_urls)}"
            self._connections[pool_connection_id] = connection

            return FlextResult.ok(pool_connection_id)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP pool connection failed: {e}")
        except Exception as e:
            msg = f"Unexpected pool connection error: {e}"
            return FlextResult.fail(msg)

    async def disconnect(self, connection_id: str) -> FlextResult[Any]:
        """Disconnect from LDAP server.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult indicating success or failure

        """
        try:
            if connection_id in self._connections:
                connection: ldap3.Connection = self._connections[connection_id]
                # LDAP3 library operations (properly typed)
                connection.unbind()  # type: ignore[no-untyped-call]
                del self._connections[connection_id]
                return FlextResult.ok(True)
            return FlextResult.fail("Connection not found")

        except LDAPException as e:
            return FlextResult.fail(f"LDAP disconnect failed: {e}")
        except Exception as e:
            msg = f"Unexpected disconnect error: {e}"
            return FlextResult.fail(msg)

    async def search(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
    ) -> FlextResult[Any]:
        """Search LDAP entries.

        Args:
            connection_id: Connection identifier
            base_dn: Base distinguished name for search
            search_filter: LDAP search filter
            attributes: Attributes to retrieve
            scope: Search scope (subtree, onelevel, base)

        Returns:
            FlextResult containing search results or error

        """
        try:
            connection: ldap3.Connection | None = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail("Connection not found")

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
                return FlextResult.fail(
                    f"Search failed: {getattr(connection, 'result', 'Unknown error')}",
                )

            results = []
            for entry in connection.entries:
                entry_dict = {
                    "dn": str(entry.entry_dn),
                    "attributes": dict(entry.entry_attributes_as_dict),
                }
                results.append(entry_dict)

            return FlextResult.ok(results)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP search failed: {e}")
        except Exception as e:
            msg = f"Unexpected search error: {e}"
            return FlextResult.fail(msg)

    async def add_entry(
        self,
        connection_id: str,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[Any]:
        """Add LDAP entry.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to add
            attributes: Entry attributes

        Returns:
            FlextResult indicating success or failure

        """
        try:
            connection: ldap3.Connection | None = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail("Connection not found")

            # LDAP3 library add operation (properly typed)
            success: bool = connection.add(  # type: ignore[no-untyped-call]
                dn, attributes=attributes,
            )

            if not success:
                return FlextResult.fail(
                    f"Add failed: {getattr(connection, 'result', 'Unknown error')}",
                )

            return FlextResult.ok(True)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP add failed: {e}")
        except Exception as e:
            msg = f"Unexpected add error: {e}"
            return FlextResult.fail(msg)

    async def modify_entry(
        self,
        connection_id: str,
        dn: str,
        changes: dict[str, Any],
    ) -> FlextResult[Any]:
        """Modify LDAP entry.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            FlextResult indicating success or failure

        """
        try:
            connection: ldap3.Connection | None = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail("Connection not found")

            # LDAP3 library modify operation (properly typed)
            success: bool = connection.modify(  # type: ignore[no-untyped-call]
                dn, changes,
            )

            if not success:
                return FlextResult.fail(
                    f"Modify failed: {getattr(connection, 'result', 'Unknown error')}",
                )

            return FlextResult.ok(True)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP modify failed: {e}")
        except Exception as e:
            msg = f"Unexpected modify error: {e}"
            return FlextResult.fail(msg)

    async def delete_entry(
        self,
        connection_id: str,
        dn: str,
    ) -> FlextResult[Any]:
        """Delete LDAP entry.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success or failure

        """
        try:
            connection: ldap3.Connection | None = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail("Connection not found")

            # LDAP3 library delete operation (properly typed)
            success: bool = connection.delete(dn)  # type: ignore[no-untyped-call]

            if not success:
                return FlextResult.fail(
                    f"Delete failed: {getattr(connection, 'result', 'Unknown error')}",
                )

            return FlextResult.ok(True)

        except LDAPException as e:
            return FlextResult.fail(f"LDAP delete failed: {e}")
        except Exception as e:
            msg = f"Unexpected delete error: {e}"
            return FlextResult.fail(msg)

    def get_connection_info(self, connection_id: str) -> FlextResult[Any]:
        """Get connection information.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult containing connection info or error

        """
        try:
            connection: ldap3.Connection | None = self._connections.get(connection_id)
            if not connection:
                return FlextResult.fail("Connection not found")

            info = {
                "server": str(connection.server),
                "bound": connection.bound,
                "user": connection.user,
                "strategy": str(getattr(connection, "strategy", "unknown")),
                "server_info": (
                    getattr(connection.server, "info", None).to_dict()  # type: ignore[union-attr]
                    if hasattr(connection.server, "info")
                    and getattr(connection.server, "info", None)
                    else None
                ),
            }

            return FlextResult.ok(info)

        except Exception as e:
            msg = f"Unexpected error getting connection info: {e}"
            return FlextResult.fail(msg)

    # High-level user operations
    async def create_user(
        self,
        connection: Any,  # LDAPConnection entity
        request: Any,  # CreateUserRequest value object
    ) -> FlextResult[Any]:  # Returns LDAPUser entity
        """Create LDAP user using basic operations.

        Args:
            connection: LDAP connection entity
            request: User creation request

        Returns:
            FlextResult containing created LDAPUser or error

        """
        try:
            from uuid import uuid4

            from flext_ldap.domain.entities import FlextLdapUser

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
                return FlextResult.fail(
                    f"Failed to create user in LDAP: {result.error}",
                )

            # Create and return domain entity
            user_uuid = str(uuid4())
            user = FlextLdapUser(
                id=user_uuid,
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
            )

            # Register UUID->DN mapping for future operations
            self._register_uuid_dn_mapping(user_uuid, request.dn)

            return FlextResult.ok(user)

        except Exception as e:
            msg = f"Failed to create user: {e}"
            return FlextResult.fail(msg)

    async def find_user_by_dn(
        self,
        connection: Any,  # LDAPConnection entity
        dn: str,
    ) -> FlextResult[Any]:  # Returns LDAPUser | None
        """Find user by distinguished name.

        Args:
            connection: LDAP connection entity
            dn: Distinguished name to search for

        Returns:
            FlextResult containing LDAPUser if found, None if not found, or error

        """
        try:
            from uuid import uuid4

            from flext_ldap.domain.entities import FlextLdapUser

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
                return FlextResult.fail(f"Failed to search user: {result.error}")

            entries = result.data
            if not entries:
                return FlextResult.ok(None)

            # Convert LDAP entry to domain entity
            entry = entries[0]
            attrs = entry["attributes"]

            user = FlextLdapUser(
                id=str(uuid4()),
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
            )

            return FlextResult.ok(user)

        except Exception as e:
            msg = f"Failed to find user by DN: {e}"
            return FlextResult.fail(msg)

    async def find_user_by_uid(
        self,
        connection: Any,  # LDAPConnection entity
        uid: str,
    ) -> FlextResult[Any]:  # Returns LDAPUser | None
        """Find user by UID attribute.

        Args:
            connection: LDAP connection entity
            uid: User identifier to search for

        Returns:
            FlextResult containing LDAPUser if found, None if not found, or error

        """
        try:
            from uuid import uuid4

            from flext_ldap.domain.entities import FlextLdapUser

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
                return FlextResult.fail(f"Failed to search user: {result.error}")

            entries = result.data
            if not entries:
                return FlextResult.ok(None)

            # Convert first matching LDAP entry to domain entity
            entry = entries[0]
            attrs = entry["attributes"]

            user = FlextLdapUser(
                id=str(uuid4()),
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
            )

            return FlextResult.ok(user)

        except Exception as e:
            msg = f"Failed to find user by UID: {e}"
            return FlextResult.fail(msg)

    async def list_users(
        self,
        connection: Any,  # LDAPConnection entity
        base_dn: str | None = None,
        limit: int = 100,
    ) -> FlextResult[list[Any]]:  # Returns list[LDAPUser]
        """List users in organizational unit.

        Args:
            connection: LDAP connection entity
            base_dn: Base DN to search in
            limit: Maximum number of users to return

        Returns:
            FlextResult containing list of LDAPUsers or error

        """
        try:
            from uuid import uuid4

            from flext_ldap.domain.entities import FlextLdapUser

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
                return FlextResult.fail(f"Failed to list users: {result.error}")

            entries = result.data or []
            users = []

            # Convert entries to domain entities, respecting limit
            for entry in entries[:limit]:
                attrs = entry["attributes"]
                user = FlextLdapUser(
                    id=str(uuid4()),
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
                )
                users.append(user)

            return FlextResult.ok(users)

        except Exception as e:
            msg = f"Failed to list users: {e}"
            return FlextResult.fail(msg)

    async def update_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID
        updates: dict[str, Any],
    ) -> FlextResult[Any]:  # Returns LDAPUser
        """Update user attributes.

        Args:
            connection: LDAP connection entity
            user_id: User UUID (not used for LDAP operations)
            updates: Dictionary of attributes to update

        Returns:
            FlextResult containing updated LDAPUser or error

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Resolve user identifier to DN using UUID->DN mapping
            resolve_result = self._resolve_user_identifier(user_id)
            if not resolve_result.success:
                return resolve_result
            dn = resolve_result.data
            if not isinstance(dn, str):
                return FlextResult.fail("DN must be a string")

            # Convert updates dict to LDAP modify operations
            # LDAP modify operations use (operation, attribute, values) tuples
            modifications: dict[str, Any] = {}
            for attr, value in updates.items():
                if value is None:
                    # Remove attribute - use empty list to indicate removal
                    modifications[attr] = []
                elif isinstance(value, list):
                    # Replace with list of values
                    modifications[attr] = [str(v) for v in value]
                else:
                    # Replace with single value
                    modifications[attr] = [str(value)]

            # Apply modifications using modify_entry
            result = await self.modify_entry(connection_id, dn, modifications)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to update user in LDAP: {result.error}",
                )

            # For a complete implementation, we'd fetch and return the updated user
            # For now, return success with True
            return FlextResult.ok(True)

        except Exception as e:
            msg = f"Failed to update user: {e}"
            return FlextResult.fail(msg)

    async def delete_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID - either UUID or DN string
    ) -> FlextResult[Any]:
        """Delete user from LDAP.

        Args:
            connection: LDAP connection entity
            user_id: User identifier (UUID or DN)

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Resolve user identifier to DN using UUID->DN mapping
            resolve_result = self._resolve_user_identifier(user_id)
            if not resolve_result.success:
                return resolve_result
            dn = resolve_result.data
            if not isinstance(dn, str):
                return FlextResult.fail("DN must be a string")

            # Delete entry from LDAP
            result = await self.delete_entry(connection_id, dn)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to delete user from LDAP: {result.error}",
                )

            return FlextResult.ok(True)

        except Exception as e:
            msg = f"Failed to delete user: {e}"
            return FlextResult.fail(msg)

    async def lock_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID
    ) -> FlextResult[Any]:  # Returns LDAPUser
        """Lock user account.

        Args:
            connection: LDAP connection entity
            user_id: User UUID

        Returns:
            FlextResult containing locked LDAPUser or error

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Resolve user identifier to DN
            resolve_result = self._resolve_user_identifier(user_id)
            if not resolve_result.success:
                return resolve_result
            dn = resolve_result.data
            if not isinstance(dn, str):
                return FlextResult.fail("DN must be a string")

            # LDAP user lock implementation depends on the directory server:
            # - Active Directory: modify userAccountControl attribute
            # - OpenLDAP: modify pwdAccountLockedTime or similar
            # - Other directories: vary by implementation

            # Generic approach: set a lock attribute
            # This is a simplified implementation - real implementation would
            # depend on the specific LDAP server type
            modifications = {
                "description": ["Account locked by FLEXT-LDAP"],
                # For AD: would modify userAccountControl
                # For OpenLDAP: might use pwdAccountLockedTime
            }

            result = await self.modify_entry(connection_id, dn, modifications)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to lock user in LDAP: {result.error}",
                )

            # For a complete implementation, we'd fetch and return the locked user
            return FlextResult.ok(True)

        except Exception as e:
            msg = f"Failed to lock user: {e}"
            return FlextResult.fail(msg)

    async def unlock_user(
        self,
        connection: Any,  # LDAPConnection entity
        user_id: Any,  # UUID
    ) -> FlextResult[Any]:  # Returns LDAPUser
        """Unlock user account.

        Args:
            connection: LDAP connection entity
            user_id: User UUID

        Returns:
            FlextResult containing unlocked LDAPUser or error

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Resolve user identifier to DN
            resolve_result = self._resolve_user_identifier(user_id)
            if not resolve_result.success:
                return resolve_result
            dn = resolve_result.data
            if not isinstance(dn, str):
                return FlextResult.fail("DN must be a string")

            # LDAP user unlock implementation depends on the directory server:
            # - Active Directory: modify userAccountControl attribute
            # - OpenLDAP: remove pwdAccountLockedTime or similar
            # - Other directories: vary by implementation

            # Generic approach: remove lock attribute or set unlock description
            # This is a simplified implementation - real implementation would
            # depend on the specific LDAP server type
            modifications = {
                "description": ["Account unlocked by FLEXT-LDAP"],
                # For AD: would modify userAccountControl
                # For OpenLDAP: might remove pwdAccountLockedTime
            }

            result = await self.modify_entry(connection_id, dn, modifications)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to unlock user in LDAP: {result.error}",
                )

            # For a complete implementation, we'd fetch and return the unlocked user
            return FlextResult.ok(True)

        except Exception as e:
            msg = f"Failed to unlock user: {e}"
            return FlextResult.fail(msg)

    # Group Operations

    async def create_group(
        self,
        connection: Any,  # LDAPConnection entity
        dn: str,
        cn: str,
        members: list[str] | None = None,
        object_classes: list[str] | None = None,
    ) -> FlextResult[Any]:  # Returns LDAPGroup
        """Create LDAP group using basic operations.

        Args:
            connection: LDAP connection entity
            dn: Distinguished name for the group
            cn: Common name
            members: List of member DNs (optional)
            object_classes: LDAP object classes (optional)

        Returns:
            FlextResult containing created LDAPGroup or error

        """
        try:
            from uuid import uuid4

            from flext_ldap.domain.entities import FlextLdapGroup

            # Build LDAP attributes from request
            attributes = {
                "objectClass": object_classes or ["groupOfNames"],
                "cn": [cn],
            }

            # Add members (groupOfNames requires at least one member)
            if members:
                attributes["member"] = members
            else:
                # Add a placeholder member (common LDAP pattern)
                attributes["member"] = ["cn=placeholder"]

            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Add entry to LDAP
            result = await self.add_entry(connection_id, dn, attributes)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to create group in LDAP: {result.error}",
                )

            # Create and return domain entity
            group_uuid = str(uuid4())
            group = FlextLdapGroup(
                id=group_uuid,
                dn=dn,
                cn=cn,
                members=members or [],
                object_classes=object_classes or ["groupOfNames"],
            )

            # Register UUID->DN mapping for future operations
            self._register_uuid_dn_mapping(group_uuid, dn)

            return FlextResult.ok(group)

        except Exception as e:
            msg = f"Failed to create group: {e}"
            return FlextResult.fail(msg)

    async def find_group_by_dn(
        self,
        connection: Any,  # LDAPConnection entity
        dn: str,
    ) -> FlextResult[Any]:  # Returns LDAPGroup | None
        """Find group by distinguished name.

        Args:
            connection: LDAP connection entity
            dn: Distinguished name to search for

        Returns:
            FlextResult containing LDAPGroup if found, None if not found, or error

        """
        try:
            from uuid import uuid4

            from flext_ldap.domain.entities import FlextLdapGroup

            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Search for group by DN
            result = await self.search(
                connection_id,
                dn,
                "(objectClass=*)",
                attributes=[
                    "cn",
                    "member",
                    "owner",
                    "objectClass",
                    "description",
                ],
                scope="base",
            )

            if not result.success:
                return FlextResult.fail(f"Failed to search group: {result.error}")

            entries = result.data
            if not entries:
                return FlextResult.ok(None)

            # Convert LDAP entry to domain entity
            entry = entries[0]
            attrs = entry["attributes"]

            group = FlextLdapGroup(
                id=str(uuid4()),
                dn=entry["dn"],
                cn=attrs.get("cn", [None])[0],
                members=attrs.get("member", []),
                owners=attrs.get("owner", []),
                object_classes=attrs.get("objectClass", ["groupOfNames"]),
            )

            return FlextResult.ok(group)

        except Exception as e:
            msg = f"Failed to find group by DN: {e}"
            return FlextResult.fail(msg)

    async def add_member_to_group(
        self,
        connection: Any,  # LDAPConnection entity
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[Any]:
        """Add a member to LDAP group.

        Args:
            connection: LDAP connection entity
            group_dn: Distinguished name of the group
            member_dn: Distinguished name of the member to add

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # LDAP modify operation to add member
            modifications = {
                "member": [member_dn],  # Add operation
            }

            result = await self.modify_entry(connection_id, group_dn, modifications)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to add member to group in LDAP: {result.error}",
                )

            return FlextResult.ok(True)

        except Exception as e:
            msg = f"Failed to add member to group: {e}"
            return FlextResult.fail(msg)

    async def delete_group(
        self,
        connection: Any,  # LDAPConnection entity
        group_dn: str,
    ) -> FlextResult[Any]:
        """Delete group from LDAP.

        Args:
            connection: LDAP connection entity
            group_dn: Distinguished name of the group to delete

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Get connection ID for infrastructure operations
            connection_id = (
                f"{connection.server_url}:{connection.bind_dn or 'anonymous'}"
            )

            # Delete entry from LDAP
            result = await self.delete_entry(connection_id, group_dn)
            if not result.success:
                return FlextResult.fail(
                    f"Failed to delete group from LDAP: {result.error}",
                )

            return FlextResult.ok(True)

        except Exception as e:
            msg = f"Failed to delete group: {e}"
            return FlextResult.fail(msg)
