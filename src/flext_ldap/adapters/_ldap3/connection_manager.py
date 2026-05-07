"""LDAP3 adapter — ConnectionManager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from ldap3 import Connection, Server

from flext_ldap import c, m, p
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from flext_ldif import e, r


class ConnectionManager:
    """Connection management logic (SRP)."""

    @staticmethod
    def create_connection(
        server: p.Ldap.Ldap3Server,
        settings: m.Ldap.ConnectionConfig,
    ) -> p.Ldap.Ldap3Connection:
        """Create ldap3 p.Ldap.Ldap3Connection t.JsonValue.

        Business Rules:
            - Bind credentials (user, password) from settings
            - auto_bind from settings controls automatic binding
            - auto_range from settings controls automatic range handling
            - Receive timeout uses settings.timeout value
            - p.Ldap.Ldap3Connection is created but may not be bound yet

        Architecture:
            - Uses ldap3 p.Ldap.Ldap3Connection() constructor directly
            - Returns p.Ldap.Ldap3Connection instance (may need bind() call)
            - No network calls if auto_bind=False

        Args:
            server: ldap3 Server t.JsonValue from create_server().
            settings: p.Ldap.Ldap3Connection configuration with bind credentials.

        Returns:
            ldap3 p.Ldap.Ldap3Connection t.JsonValue (bound if auto_bind=True).

        """
        if not isinstance(server, Server):
            msg = f"Expected ldap3.Server, got {type(server).__name__}"
            raise TypeError(msg)
        return Connection(
            server=server,
            user=settings.bind_dn,
            password=settings.bind_password,
            auto_bind=settings.auto_bind,
            auto_range=settings.auto_range,
            check_names=False,
            receive_timeout=settings.timeout,
        )

    @staticmethod
    def create_server(settings: m.Ldap.ConnectionConfig) -> p.Ldap.Ldap3Server:
        """Create ldap3 Server t.JsonValue.

        Business Rules:
            - SSL connections use use_ssl=True (port 636 default)
            - Non-SSL connections use use_ssl=False (port 389 default)
            - Connect timeout uses settings.timeout value
            - Server t.JsonValue is created without connection attempt

        Architecture:
            - Uses ldap3 Server() constructor directly
            - Returns Server instance for Connection creation
            - No network calls - object creation only

        Args:
            settings: Connection configuration with host, port, SSL/TLS settings.

        Returns:
            ldap3 Server t.JsonValue configured for connection.

        """
        if settings.use_ssl:
            return Server(
                host=settings.host,
                port=settings.port,
                use_ssl=True,
                connect_timeout=settings.timeout,
            )
        return Server(
            host=settings.host,
            port=settings.port,
            connect_timeout=settings.timeout,
        )

    @staticmethod
    def handle_tls(
        connection: p.Ldap.Ldap3Connection,
        settings: m.Ldap.ConnectionConfig,
    ) -> p.Result[bool]:
        """Handle STARTTLS if requested.

        Business Rules:
            - STARTTLS is only used if use_tls=True and use_ssl=False
            - SSL connections (use_ssl=True) skip STARTTLS
            - Calls connection.start_tls() for protocol-level TLS negotiation
            - Returns success if STARTTLS not needed or succeeds
            - Returns failure if STARTTLS fails

        Audit Implications:
            - STARTTLS failures are logged with error details
            - TLS negotiation is critical for security compliance

        Architecture:
            - Uses ldap3 Connection.start_tls() for protocol-level operation
            - Returns r pattern - no exceptions raised
            - LDAPException is caught and converted to failure

        Args:
            connection: Active ldap3.Connection instance.
            settings: Connection configuration with TLS settings.

        Returns:
            r[bool]: Success if STARTTLS not needed or succeeds.

        """
        if not settings.use_tls or settings.use_ssl:
            return r[bool].ok(value=True)
        try:
            if not FlextLdapLdap3Wrappers.start_tls(connection):
                return e.fail_operation("start TLS")
            return r[bool].ok(value=True)
        except c.EXC_BROAD_IO_TYPE as tls_error:
            error_msg = f"Failed to start TLS: {tls_error}"
            return r[bool].fail(error_msg)


__all__: list[str] = ["ConnectionManager"]
