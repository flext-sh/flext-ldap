"""LDAP server and connection utility methods.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

import ldap3

from flext_ldap._utilities import FlextLdapUtilitiesBase
from flext_ldap.constants import c
from flext_ldap.protocols import p


class FlextLdapUtilitiesServer(FlextLdapUtilitiesBase):
    """LDAP server and connection construction helpers."""

    @staticmethod
    def resolve_get_info(
        get_info: c.Ldap.Ldap3GetInfo,
    ) -> Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]:
        """Resolve Ldap3GetInfo enum to typed literal for ldap3 stubs.

        Returns:
            The resulting ``Literal['ALL', 'DSA', 'NO_INFO', 'SCHEMA']``.

        """
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
    ) -> p.Ldif.Ldap3Server:
        """Create an ldap3 Server instance.

        Returns:
            The resulting ``p.Ldif.Ldap3Server``.

        """
        scheme = "ldaps" if use_ssl else "ldap"
        server: p.Ldif.Ldap3Server = ldap3.Server(
            f"{scheme}://{host}:{port}",
            get_info=FlextLdapUtilitiesServer.resolve_get_info(get_info),
        )
        return server

    @staticmethod
    def create_connection_server(
        settings: p.Ldap.ConnectionConfig,
    ) -> p.Ldap.Ldap3TlsServer:
        """Create the ldap3 Server for a connection configuration.

        LDAPS and StartTLS always carry an explicit TLS policy: the peer
        certificate is verified against ``ca_certs_file`` (or the system trust
        store) and the certificate must match ``host`` or ``server_name``
        unless ``tls_validate`` is the explicit ``NONE`` mode. No network call
        happens during construction.

        Returns:
            The resulting ``p.Ldap.Ldap3TlsServer``.

        """
        tls: ldap3.Tls | None = None
        if settings.use_ssl or settings.use_tls:
            tls = ldap3.Tls(
                validate=c.Ldap.TLS_VERIFY_MODE_BY_VALIDATION[settings.tls_validate],
                ca_certs_file=(
                    None
                    if settings.ca_certs_file is None
                    else str(settings.ca_certs_file)
                ),
                valid_names=(
                    None if settings.server_name is None else [settings.server_name]
                ),
                sni=settings.server_name,
            )
        server: p.Ldap.Ldap3TlsServer = ldap3.Server(
            host=settings.host,
            port=settings.port,
            use_ssl=settings.use_ssl,
            tls=tls,
            connect_timeout=settings.timeout,
            get_info=FlextLdapUtilitiesServer.resolve_get_info(c.Ldap.Ldap3GetInfo.ALL),
        )
        return server

    @staticmethod
    def create_server_from_url(
        server_url: str,
        *,
        get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
    ) -> p.Ldif.Ldap3Server:
        """Create an ldap3 Server instance from a URL string.

        Returns:
            The resulting ``p.Ldif.Ldap3Server``.

        """
        server: p.Ldif.Ldap3Server = ldap3.Server(
            server_url,
            get_info=FlextLdapUtilitiesServer.resolve_get_info(get_info),
        )
        return server

    @staticmethod
    def create_connection(
        server: p.Ldif.Ldap3Server,
        *,
        user: str,
        password: str,
        auto_bind: bool = True,
        receive_timeout: int | None = None,
    ) -> p.Ldap.Ldap3Connection:
        """Create an ldap3 Connection instance.

        Returns:
            The resulting ``p.Ldap.Ldap3Connection``.

        Raises:
            TypeError: If Expected ldap3.Server, got.

        """
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
    ) -> p.Ldif.Ldap3Server:
        """Create an ldap3 Server with minimal info retrieval.

        Returns:
            The resulting ``p.Ldif.Ldap3Server``.

        """
        server: p.Ldif.Ldap3Server = ldap3.Server(
            host,
            port=port,
            get_info=FlextLdapUtilitiesServer.resolve_get_info(get_info),
        )
        return server


__all__: list[str] = ["FlextLdapUtilitiesServer"]
