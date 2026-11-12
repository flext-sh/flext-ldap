"""Tests utilitiies for flext-ldap.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from flext_tests import FlextTestsUtilities
from flext_tests.docker import FlextTestsDocker

from flext_ldap import FlextLdapUtilities, settings
from tests import c, m, p, t, tk, tm


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests."""

    class Ldap(FlextLdapUtilities.Ldap):
        """Provide the test double for ldap."""

        class Tests(FlextTestsUtilities.Tests):
            """Direct test utility surface for flext-ldap.

            Assertion matchers (``that``/``fail``/``ok``/``check``) are inherited
            from the composed ``FlextTestsUtilities.Tests`` root; no local
            re-publication is needed.

            """

            @staticmethod
            def create_ldap3_server(
                ldap_container: Mapping[str, t.Scalar],
            ) -> p.Ldif.Ldap3Server:
                """Create an ldap3 server from container metadata.

                Returns:
                    The resulting ``p.Ldif.Ldap3Server``.

                """
                server_url = ldap_container["server_url"]
                server: p.Ldif.Ldap3Server = u.Ldap.create_server_from_url(
                    str(server_url),
                )
                return server

            @staticmethod
            def create_ldap3_connection(
                server: p.Ldif.Ldap3Server,
                ldap_container: Mapping[str, t.Scalar],
            ) -> p.Ldap.Ldap3Connection:
                """Create an ldap3 connection from container metadata.

                Returns:
                    The resulting ``p.Ldap.Ldap3Connection``.

                """
                connection: p.Ldap.Ldap3Connection = u.Ldap.create_connection(
                    server,
                    user=str(ldap_container["bind_dn"]),
                    password=str(ldap_container["password"]),
                )
                return connection

            @staticmethod
            def create_connection_config(
                ldap_container: Mapping[str, t.Scalar],
            ) -> p.Ldap.ConnectionConfig:
                """Build a typed connection settings from container metadata.

                Returns:
                    The resulting ``m.Ldap.ConnectionConfig``.

                Raises:
                    TypeError: If ldap_container port must be int, str or float, got.

                """
                port = ldap_container["port"]
                port_value = (
                    port
                    if isinstance(port, int)
                    else int(port)
                    if isinstance(port, (str, float))
                    else c.Ldap.PORT
                )
                if isinstance(port, int):
                    port_value = port
                elif isinstance(port, (str, float)):
                    port_value = int(port)
                else:
                    message = (
                        "ldap_container port must be int, str or float, "
                        f"got {type(port).__name__}"
                    )
                    raise TypeError(message)
                return m.Ldap.ConnectionConfig(
                    host=str(ldap_container["host"]),
                    port=port_value,
                    use_ssl=bool(ldap_container["use_ssl"]),
                    bind_dn=str(ldap_container["bind_dn"]),
                    bind_password=str(ldap_container["password"]),
                )

            @staticmethod
            def create_tls_connection_config(
                *,
                ca_file_var: str,
                server_name_var: str | None,
            ) -> p.Ldap.ConnectionConfig:
                """Build an LDAPS config from the local test environment.

                The endpoint comes from ``c.Ldap.Tests.TLS_URL_VAR``; the CA bundle
                and the expected certificate name come from the named variables.
                Missing variables propagate unchanged.

                Returns:
                    The resulting ``m.Ldap.ConnectionConfig``.

                """
                endpoint = urlsplit(os.environ[c.Ldap.Tests.TLS_URL_VAR])
                return m.Ldap.ConnectionConfig(
                    host=tm.not_none(endpoint.hostname),
                    port=tm.not_none(endpoint.port),
                    use_ssl=True,
                    ca_certs_file=Path(os.environ[ca_file_var]),
                    server_name=(
                        None if server_name_var is None else os.environ[server_name_var]
                    ),
                    bind_dn=os.environ["FLEXT_LDAP_BIND_DN"],
                    bind_password=os.environ["FLEXT_LDAP_BIND_PASSWORD"],
                )

            @staticmethod
            def assert_connection_bound(connection: p.Ldap.Ldap3Connection) -> None:
                """Assert that an LDAP connection is bound."""
                tm.that(
                    connection.bound,
                    eq=True,
                    msg="LDAP server not responding to bind",
                )

            @staticmethod
            def assert_server_info_available(
                connection: p.Ldap.Ldap3Connection,
            ) -> None:
                """Assert that server info is available on the connection."""
                server = connection.server
                info = tm.not_none(server.info)
                tm.that(info.naming_contexts, none=False)

            @staticmethod
            def assert_models_accessible() -> None:
                """Assert that the project models facade is available."""
                tm.that(m, none=False)

            @staticmethod
            def assert_connection_success(result: p.Result[bool]) -> None:
                """Assert that a connection result succeeded."""
                tm.ok(result)

            @staticmethod
            def get_docker_control() -> FlextTestsDocker:
                """Resolve the packaged service through its canonical owner.

                Returns:
                    The native shared LDAP controller, without executing it.

                """
                return tk.shared(c.Ldap.Tests.DOCKER_CONTAINER_NAME)

            @staticmethod
            def get_admin_credentials() -> tuple[str, str]:
                """Read explicitly configured LDAP credentials without probing.

                Both environment keys are required; missing keys propagate unchanged.

                Returns:
                    The resulting ``tuple[str, str]``.

                """
                configured = settings.clone(
                    Ldap={
                        "bind_dn": os.environ["FLEXT_LDAP_BIND_DN"],
                        "bind_password": os.environ["FLEXT_LDAP_BIND_PASSWORD"],
                    },
                )
                return configured.Ldap.bind_dn, configured.Ldap.bind_password

            @staticmethod
            def single_phase_cb(
                _a: int,
                _b: int,
                _c: str,
                _d: p.Ldap.LdapBatchStats,
            ) -> None:
                """Test callback with 4 parameters."""

            @staticmethod
            def multi_phase_cb(
                _a: str,
                _b: int,
                _c: int,
                _d: str,
                _e: p.Ldap.LdapBatchStats,
            ) -> None:
                """Test callback with 5 parameters."""

            @staticmethod
            def invalid_phase_cb(_a: int, _b: int) -> None:
                """Invalid callback with unsupported arity for sync callbacks."""


u = TestsFlextLdapUtilities

__all__: list[str] = ["TestsFlextLdapUtilities", "u"]
