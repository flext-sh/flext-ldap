from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar, overload

from flext_tests import FlextTestsUtilities, tk
from ldap3 import Connection

from flext_ldap import u
from tests import c, m, p, t


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
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> None:
                FlextTestsUtilities.Tests.Matchers.that(value, **kwargs)

            @staticmethod
            def fail[TResult](
                result: p.Result[TResult],
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> str:
                return FlextTestsUtilities.Tests.Matchers.fail(result, **kwargs)

            @staticmethod
            @overload
            def ok[TResult](
                result: p.Result[TResult],
            ) -> TResult: ...

            @staticmethod
            @overload
            def ok[TResult](
                result: p.Result[TResult],
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> TResult | t.Tests.TestobjectSerializable: ...

            @staticmethod
            def ok[TResult](
                result: p.Result[TResult],
                **kwargs: t.Tests.MatcherKwargValue,
            ) -> TResult | t.Tests.TestobjectSerializable:
                return FlextTestsUtilities.Tests.Matchers.ok(result, **kwargs)

            @staticmethod
            def check[TResult](
                result: p.Result[TResult],
            ) -> m.Tests.Chain[TResult]:
                return FlextTestsUtilities.Tests.Matchers.check(result)

            @staticmethod
            def create_ldap3_server(
                ldap_container: t.MappingKV[
                    str,
                    t.Scalar,
                ],
            ) -> p.Ldap.Ldap3Server:
                """Create an ldap3 server from container metadata."""
                server_url = ldap_container["server_url"]
                return u.Ldap.create_server_from_url(str(server_url))

            @staticmethod
            def create_ldap3_connection(
                server: p.Ldap.Ldap3Server,
                ldap_container: t.MappingKV[
                    str,
                    t.Scalar,
                ],
            ) -> Connection:
                """Create an ldap3 connection from container metadata."""
                return u.Ldap.create_connection(
                    server,
                    user=str(ldap_container["bind_dn"]),
                    password=str(ldap_container["password"]),
                )

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
                return m.Ldap.ConnectionConfig(
                    host=str(ldap_container["host"]),
                    port=port_value,
                    use_ssl=bool(ldap_container["use_ssl"]),
                    bind_dn=str(ldap_container["bind_dn"]),
                    bind_password=str(ldap_container["password"]),
                )

            @staticmethod
            def assert_connection_bound(connection: Connection) -> None:
                """Assert that an LDAP connection is bound."""
                assert connection.bound, "LDAP server not responding to bind"

            @staticmethod
            def assert_server_info_available(
                connection: Connection,
            ) -> None:
                """Assert that server info is available on the connection."""
                server = connection.server
                assert server.info is not None, "LDAP server info not available"
                assert server.info.naming_contexts is not None, (
                    "LDAP naming contexts not available"
                )

            @staticmethod
            def assert_models_accessible() -> None:
                """Assert that the project models facade is available."""
                assert m is not None, "m (m) not accessible"

            @staticmethod
            def assert_connection_success(result: p.Result[bool]) -> None:
                """Assert that a connection result succeeded."""
                assert result.success, f"Connection failed: {result.error}"

            @staticmethod
            def get_docker_control(
                worker_id: str = c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID,
            ) -> tk:
                """Create Docker test infrastructure controller."""
                return tk(
                    workspace_root=Path(__file__).resolve().parents[1],
                    worker_id=worker_id,
                )

            FileLock = FlextTestsUtilities.Tests.FileLock

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
                        if connection.bound:
                            connection.unbind()
                            resolved = (candidate_dn, candidate_password)
                            cache[0] = resolved
                            return resolved
                    except (
                        ConnectionError,
                        OSError,
                        ValueError,
                        t.Ldap.LDAPException,
                    ):
                        continue
                fallback = (
                    c.Ldap.Tests.DOCKER_ADMIN_DN,
                    c.Ldap.Tests.DOCKER_ADMIN_PASSWORD,
                )
                cache[0] = fallback
                return fallback

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
                        description = str(connection.result.get("description", ""))
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


u = TestsFlextLdapUtilities

__all__: list[str] = ["TestsFlextLdapUtilities", "u"]
