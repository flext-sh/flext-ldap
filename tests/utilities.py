"""Tests utilitiies for flext-ldap.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from flext_tests import FlextTestsUtilities
from flext_tests.docker import FlextTestsDocker

from flext_ldap import FlextLdapUtilities, settings
from tests import c, m, p, t, tk, tm


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests."""

    class Ldap(FlextLdapUtilities.Ldap):
        """Provide the test double for ldap."""

        class Tests(FlextTestsUtilities.Tests):
            """Direct test utility surface for flext-ldap."""

            @staticmethod
            def that[SubjectT](
                value: SubjectT,
                *,
                where: Callable[[SubjectT], bool] | None = None,
                **kwargs: p.Tests.MatcherOption,
            ) -> None:
                """Provide that."""
                tm.that(value, where=where, **kwargs)

            @staticmethod
            def fail[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
                **kwargs: p.AttributeProbe,
            ) -> str:
                """Provide fail.

                Returns:
                    The resulting ``str``.

                """
                failure_message: str = tm.fail(result, **kwargs)
                return failure_message

            @staticmethod
            def ok[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
            ) -> TResult:
                """Provide ok.

                Returns:
                    The resulting ``TResult``.

                """
                return tm.ok(result)

            @staticmethod
            def check[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
            ) -> m.Tests.Chain[TResult]:
                """Provide check.

                Returns:
                    The resulting ``m.Tests.Chain[TResult]``.

                """
                return tm.check(result)

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
            ) -> m.Ldap.ConnectionConfig:
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
            def repository_root() -> Path:
                """Resolve the workspace root that owns the shared LDAP compose.

                Walks ancestors for the shared ``docker/`` compose asset so the
                resolver is independent of test-file nesting depth. In-workspace
                this returns the monorepo root that holds the shared compose; run
                standalone (submodule checkout without the shared compose) it
                returns the submodule root, where the compose is absent so the
                container fixture skips instead of faking the service.

                Returns:
                    The resulting ``Path``.

                """
                rel: str = c.Ldap.Tests.DOCKER_COMPOSE_FILE_REL
                here: Path = Path(__file__).resolve()
                for parent in here.parents:
                    if (parent / rel).exists():
                        return parent
                return here.parents[1]

            @staticmethod
            def get_docker_control(
                _worker_id: str = c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID,
            ) -> FlextTestsDocker:
                """Create Docker test infrastructure controller.

                Returns:
                    The resulting ``FlextTestsDocker``.

                """
                return tk.compose(
                    compose_file=c.Ldap.Tests.DOCKER_COMPOSE_FILE_REL,
                    target=m.Tests.ContainerConfig(
                        container_name=c.Ldap.Tests.DOCKER_CONTAINER_NAME,
                        service=c.Ldap.Tests.DOCKER_SERVICE_NAME,
                        host=c.LOCALHOST,
                        port=c.Ldap.Tests.DOCKER_CONTAINER_PORT,
                        startup_timeout=c.Ldap.Tests.DOCKER_STARTUP_TIMEOUT,
                    ),
                    repository_root=TestsFlextLdapUtilities.Ldap.Tests.repository_root(),
                )

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

            @classmethod
            def ensure_basic_ldap_structure(cls) -> None:
                """Ensure the base organizational units exist for smoke tests.

                Raises:
                    RuntimeError: If Failed to create.

                """
                admin_dn, admin_password = cls.get_admin_credentials()
                connection = u.Ldap.create_connection(
                    u.Ldap.create_server_from_url(
                        f"ldap://{c.LOCALHOST}:{c.Ldap.Tests.DOCKER_PORT}",
                        get_info=c.Ldap.Ldap3GetInfo.NO_INFO,
                    ),
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                try:
                    for ou_name in c.Ldap.Tests.DOCKER_OU_NAMES:
                        dn = f"ou={ou_name},{c.Ldap.Tests.DOCKER_BASE_DN}"
                        created = connection.add(
                            dn,
                            ["top", "organizationalUnit"],
                            {"ou": ou_name},
                        )
                        if created:
                            continue
                        result_payload = connection.result
                        description = (
                            ""
                            if result_payload is None
                            else str(result_payload.get("description", ""))
                        )
                        if description != "entryAlreadyExists":
                            message = f"Failed to create {dn}: {description}"
                            raise RuntimeError(message)
                finally:
                    connection.unbind()

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
