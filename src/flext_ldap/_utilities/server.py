"""LDAP server and connection utility methods."""

from __future__ import annotations

from typing import Literal

import ldap3

from flext_ldap import c, p


class FlextLdapUtilitiesServer:
    """LDAP server and connection construction helpers."""

    @staticmethod
    def resolve_get_info(
        get_info: c.Ldap.Ldap3GetInfo,
    ) -> Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]:
        """Resolve Ldap3GetInfo enum to typed literal for ldap3 stubs."""
        match get_info:
            case c.Ldap.Ldap3GetInfo.DSA:
                return "DSA"
            case c.Ldap.Ldap3GetInfo.NO_INFO:
                return "NO_INFO"
            case c.Ldap.Ldap3GetInfo.SCHEMA:
                return "SCHEMA"
            case _:
                return "ALL"

    @staticmethod
    def create_server(
        host: str,
        port: int = c.Ldap.PORT,
        *,
        use_ssl: bool = False,
        get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
    ) -> p.Ldap.Ldap3Server:
        """Create an ldap3 Server instance."""
        scheme = "ldaps" if use_ssl else "ldap"
        server: p.Ldap.Ldap3Server = ldap3.Server(
            f"{scheme}://{host}:{port}",
            get_info=FlextLdapUtilitiesServer.resolve_get_info(get_info),
        )
        return server

    @staticmethod
    def create_server_from_url(
        server_url: str,
        *,
        get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
    ) -> p.Ldap.Ldap3Server:
        """Create an ldap3 Server instance from a URL string."""
        server: p.Ldap.Ldap3Server = ldap3.Server(
            server_url,
            get_info=FlextLdapUtilitiesServer.resolve_get_info(get_info),
        )
        return server

    @staticmethod
    def create_connection(
        server: p.Ldap.Ldap3Server,
        *,
        user: str,
        password: str,
        auto_bind: bool = True,
        receive_timeout: int | None = None,
    ) -> p.Ldap.Ldap3Connection:
        """Create an ldap3 Connection instance."""
        if not isinstance(server, ldap3.Server):
            msg = f"Expected ldap3.Server, got {type(server).__name__}"
            raise TypeError(msg)
        return ldap3.Connection(
            server,
            user=user,
            password=password,
            auto_bind=auto_bind,
            receive_timeout=receive_timeout,
        )

    @staticmethod
    def create_bare_server(
        host: str,
        *,
        port: int = c.Ldap.PORT,
        get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.NO_INFO,
    ) -> p.Ldap.Ldap3Server:
        """Create an ldap3 Server with minimal info retrieval."""
        server: p.Ldap.Ldap3Server = ldap3.Server(
            host,
            port=port,
            get_info=FlextLdapUtilitiesServer.resolve_get_info(get_info),
        )
        return server


__all__: list[str] = ["FlextLdapUtilitiesServer"]
