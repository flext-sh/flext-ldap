"""Tests utilitiies for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, overload

from flext_tests import FlextTestsUtilities, tk, tm

from flext_ldap import u
from tests import c, m, t

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdapUtilities(FlextTestsUtilities, u):
    """Utilities for flext-ldap tests."""

    class Ldap(u.Ldap):
        class Tests:
            """Direct test utility surface for flext-ldap."""

            _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [
                None,
            ]

            @staticmethod
            def that(
                value: t.Tests.Testobject,
                **kwargs: t.Tests.MatcherCallKwargValue,
            ) -> None:
                tm.that(value, **kwargs)

            @staticmethod
            def fail[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> str:
                failure_message: str = tm.fail(result, **kwargs)
                return failure_message

            @staticmethod
            @overload
            def ok[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
            ) -> TResult: ...

            @staticmethod
            @overload
            def ok[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> TResult | t.Tests.TestobjectSerializable: ...

            @staticmethod
            def ok[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> TResult | t.Tests.TestobjectSerializable:
                return tm.ok(result, **kwargs)

            @staticmethod
            def check[TResult: t.Tests.TestResultValue](
                result: p.Result[TResult],
            ) -> m.Tests.Chain[TResult]:
                return tm.check(result)

            @staticmethod
            def create_ldap3_server(
                ldap_container: t.MappingKV[
                    str,
                    t.Scalar,
                ],
            ) -> p.Ldap.Ldap3Server:
                """Create an ldap3 server from container metadata."""
                server_url = ldap_container["server_url"]
                server: p.Ldap.Ldap3Server = u.Ldap.create_server_from_url(
                    str(server_url),
                )
                return server

            @staticmethod
            def create_ldap3_connection(
                server: p.Ldap.Ldap3Server,
                ldap_container: t.MappingKV[
                    str,
                    t.Scalar,
                ],
            ) -> p.Ldap.Ldap3Connection:
                """Create an ldap3 connection from container metadata."""
                connection: p.Ldap.Ldap3Connection = u.Ldap.create_connection(
                    server,
                    user=str(ldap_container["bind_dn"]),
                    password=str(ldap_container["password"]),
                )
                return connection

            @staticmethod
            def create_connection_config(
                ldap_container: t.MappingKV[
                    str,
                    t.Scalar,
                ],
            ) -> m.Ldap.ConnectionConfig:
                """Build a typed connection settings from container metadata."""
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
                    raise TypeError(
                        f"ldap_container port must be int, str or float, "
                        f"got {type(port).__name__}",
                    )
                return m.Ldap.ConnectionConfig(
                    host=str(ldap_container["host"]),
                    port=port_value,
                    use_ssl=bool(ldap_container["use_ssl"]),
                    bind_dn=str(ldap_container["bind_dn"]),
                    bind_password=str(ldap_container["password"]),
                )

            @staticmethod
            def assert_connection_bound(
                connection: p.Ldap.Ldap3Connection,
            ) -> None:
                """Assert that an LDAP connection is bound."""
                assert connection.bound, "LDAP server not responding to bind"

            @staticmethod
            def assert_server_info_available(
                connection: p.Ldap.Ldap3Connection,
            ) -> None:
                """Assert that server info is available on the connection."""
                server = connection.server
                info = server.info
                assert info is not None
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
            def get_docker_control(
                worker_id: str = c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID,
            ) -> tk:
                """Create Docker test infrastructure controller."""
                return tk.compose(
                    compose_file=c.Ldap.Tests.DOCKER_COMPOSE_FILE_REL,
                    target=m.Tests.ContainerConfig(
                        container_name=c.Ldap.Tests.DOCKER_CONTAINER_NAME,
                        service=c.Ldap.Tests.DOCKER_SERVICE_NAME,
                        host=c.LOCALHOST,
                        port=c.Ldap.Tests.DOCKER_PORT,
                        startup_timeout=c.Ldap.Tests.DOCKER_STARTUP_TIMEOUT,
                    ),
                    workspace_root=Path(__file__).resolve().parents[1],
                )

            FileLock = FlextTestsUtilities.Tests.FileLock

            @staticmethod
            def _admin_credentials_from_candidate(
                candidate_dn: str,
                candidate_password: str,
            ) -> tuple[str, str] | None:
                try:
                    server = u.Ldap.create_server_from_url(
                        f"ldap://{c.LOCALHOST}:{c.Ldap.Tests.DOCKER_PORT}",
                        get_info=c.Ldap.Ldap3GetInfo.NO_INFO,
                    )
                    connection = u.Ldap.create_connection(
                        server,
                        user=candidate_dn,
                        password=candidate_password,
                        auto_bind=True,
                        receive_timeout=1,
                    )
                    if not connection.bound:
                        return None
                    connection.unbind()
                    return candidate_dn, candidate_password
                except (
                    ConnectionError,
                    OSError,
                    ValueError,
                    t.Ldap.LDAPException,
                ):
                    return None

            @classmethod
            def get_admin_credentials(cls) -> tuple[str, str]:
                """Resolve working LDAP admin credentials."""
                cache = cls._resolved_admin_credentials
                if cache[0] is not None:
                    return cache[0]
                env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
                env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
                candidates: list[tuple[str, str]] = []
                if env_dn and env_password:
                    candidates.append((env_dn, env_password))
                candidates.extend(
                    [
                        (
                            c.Ldap.Tests.DOCKER_ADMIN_DN,
                            c.Ldap.Tests.DOCKER_ADMIN_PASSWORD,
                        ),
                        (
                            c.Ldap.Tests.DOCKER_LEGACY_ADMIN_DN,
                            c.Ldap.Tests.DOCKER_LEGACY_ADMIN_PASSWORD,
                        ),
                    ],
                )
                for candidate_dn, candidate_password in candidates:
                    resolved = cls._admin_credentials_from_candidate(
                        candidate_dn,
                        candidate_password,
                    )
                    if resolved is None:
                        continue
                    cache[0] = resolved
                    return resolved
                error_message = (
                    "Failed to resolve a valid LDAP admin credential for test "
                    "LDAP container. Check that the LDAP container is running "
                    "and credentials are correct."
                )
                raise RuntimeError(error_message)

            @classmethod
            def ensure_basic_ldap_structure(cls) -> None:
                """Ensure the base organizational units exist for smoke tests."""
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
                            raise RuntimeError(
                                f"Failed to create {dn}: {description}",
                            )
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
