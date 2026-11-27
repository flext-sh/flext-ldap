"""Behavioral unit tests for flext_ldap.adapters.ldap3.FlextLdapLdap3Adapter.

Asserts observable public contract only: r[T] outcomes of the public
operations, public properties, idempotence of ``disconnect``, and the
configuration of the ldap3 ``Server`` produced by ``create_server``. No
private attribute/method access, no internal-collaborator spying.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique

import pytest

from flext_ldap.adapters import FlextLdapAdapterHost, FlextLdapLdap3Adapter
from tests import c, m, tm, u

pytestmark = pytest.mark.unit


class TestsFlextLdapLdap3Adapter:
    """Public-contract behavior of ``FlextLdapLdap3Adapter``.

    All test data comes from ``c.Tests.*`` / ``m.Ldap.*`` — no inline
    constants. Behavior only: return values, ``r[T]`` outcomes, public
    property state, invariants, and idempotence.
    """

    @unique
    class DisconnectedOp(StrEnum):
        """Public operations that must fail while the adapter is unbound."""

        EXECUTE = "execute"
        ADD = "add"
        DELETE = "delete"
        MODIFY = "modify"
        SEARCH = "search"

    @pytest.fixture
    @staticmethod
    def adapter() -> FlextLdapLdap3Adapter:
        """Return a freshly constructed, never-connected adapter."""
        return FlextLdapLdap3Adapter()

    @staticmethod
    def test_fresh_adapter_reports_not_connected(
        adapter: FlextLdapLdap3Adapter,
    ) -> None:
        """Verify fresh adapter reports not connected."""
        # Arrange / Act / Assert — public property contract on a new adapter.
        u.Tests.that(adapter.is_connected, eq=False)
        u.Tests.that(adapter.connection, eq=None)

    @pytest.mark.parametrize("op", list(DisconnectedOp))
    def test_operations_fail_when_not_connected(
        self,
        adapter: FlextLdapLdap3Adapter,
        op: DisconnectedOp,
    ) -> None:
        """Verify operations fail when not connected."""
        # Every public fallible operation returns a failed r[T] carrying the
        # "Not connected" contract message while the adapter is unbound.
        needle = c.Tests.LDAP3_ADAPTER_NOT_CONNECTED_ERROR
        match op:
            case self.DisconnectedOp.EXECUTE:
                u.Tests.fail(adapter.execute(), has=needle)
            case self.DisconnectedOp.ADD:
                entry = m.Ldif.Entry(
                    dn=m.Ldif.DN(value=c.Tests.RFC_DEFAULT_BASE_DN),
                    attributes=m.Ldif.Attributes(attributes={}),
                    domain_events=[],
                )
                u.Tests.fail(adapter.add(entry), has=needle)
            case self.DisconnectedOp.DELETE:
                u.Tests.fail(
                    adapter.delete(c.Tests.RFC_DEFAULT_BASE_DN),
                    has=needle,
                )
            case self.DisconnectedOp.MODIFY:
                u.Tests.fail(
                    adapter.modify(c.Tests.RFC_DEFAULT_BASE_DN, {}),
                    has=needle,
                )
            case self.DisconnectedOp.SEARCH:
                options = m.Ldap.SearchOptions(
                    base_dn=c.Tests.RFC_DEFAULT_BASE_DN,
                    filter_str=c.Tests.SEARCH_FILTER_CN,
                    scope=c.Ldap.SearchScope.SUBTREE,
                )
                u.Tests.fail(adapter.search_many([options]), has=needle)

    @staticmethod
    def test_disconnect_is_idempotent_and_keeps_state_unbound(
        adapter: FlextLdapLdap3Adapter,
    ) -> None:
        """Verify disconnect is idempotent and keeps state unbound."""
        # Disconnecting a never-connected adapter is a no-op that raises
        # nothing and leaves the observable state unbound; repeat is safe.
        adapter.disconnect()
        adapter.disconnect()
        u.Tests.that(adapter.is_connected, eq=False)
        u.Tests.that(adapter.connection, eq=None)

    @pytest.mark.parametrize("case", list(c.Tests.Ldap3ServerCase))
    @staticmethod
    def test_create_server_configures_host_and_port(
        case: c.Tests.Ldap3ServerCase,
    ) -> None:
        """Verify create server configures host and port."""
        # create_server is public via the ConnectionManager ClassVar; its
        # contract is a Server object addressing the requested host/port
        # across plain / SSL / TLS transport modes.
        port, use_ssl, use_tls = c.Tests.LDAP3_SERVER_SCENARIOS[case]
        settings = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=port,
            use_ssl=use_ssl,
            use_tls=use_tls,
            timeout=c.Tests.LDAP3_ADAPTER_DEFAULT_TIMEOUT,
        )

        server = FlextLdapLdap3Adapter.ConnectionManager.create_server(settings)

        tm.that(server, none=False)
        u.Tests.that(
            getattr(server, c.Tests.FIELD_HOST, c.Tests.STRING_EMPTY),
            eq=c.LOCALHOST,
        )
        u.Tests.that(
            getattr(
                server,
                c.Tests.FIELD_PORT,
                c.Tests.SYNC_DEFAULT_ZERO_COUNT,
            ),
            eq=port,
        )

    @staticmethod
    def test_adapter_host_reports_unbound_before_use() -> None:
        """Verify adapter host reports unbound before use."""
        # FlextLdapAdapterHost exposes is_connected without eagerly building
        # an adapter; before any use it must observe an unbound state.
        host = FlextLdapAdapterHost()
        u.Tests.that(host.is_connected, eq=False)
