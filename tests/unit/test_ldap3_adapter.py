"""Behavioral unit tests for flext_ldap.adapters.ldap3.FlextLdapLdap3Adapter.

Asserts observable public contract only: r[T] outcomes of the public
operations, public properties, idempotence of ``disconnect``, and the
configuration of the ldap3 ``Server`` produced by ``create_server``. No
private attribute/method access, no internal-collaborator spying.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, unique

import pytest
from flext_tests import tm

from flext_ldap import c
from flext_ldap.adapters.ldap3 import FlextLdapAdapterHost, FlextLdapLdap3Adapter
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapLdap3Adapter:
    """Public-contract behavior of ``FlextLdapLdap3Adapter``.

    All test data comes from ``c.Ldap.Tests.*`` / ``m.Ldap.*`` — no inline
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
    def adapter(self) -> FlextLdapLdap3Adapter:
        """Return a freshly constructed, never-connected adapter."""
        return FlextLdapLdap3Adapter()

    def test_fresh_adapter_reports_not_connected(
        self,
        adapter: FlextLdapLdap3Adapter,
    ) -> None:
        # Arrange / Act / Assert — public property contract on a new adapter.
        u.Ldap.Tests.that(adapter.is_connected, eq=False)
        u.Ldap.Tests.that(adapter.connection, eq=None)

    @pytest.mark.parametrize("op", list(DisconnectedOp))
    def test_operations_fail_when_not_connected(
        self,
        adapter: FlextLdapLdap3Adapter,
        op: DisconnectedOp,
    ) -> None:
        # Every public fallible operation returns a failed r[T] carrying the
        # "Not connected" contract message while the adapter is unbound.
        needle = c.Ldap.Tests.LDAP3_ADAPTER_NOT_CONNECTED_ERROR
        match op:
            case self.DisconnectedOp.EXECUTE:
                u.Ldap.Tests.fail(adapter.execute(), has=needle)
            case self.DisconnectedOp.ADD:
                entry = m.Ldif.Entry(
                    dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
                    attributes=m.Ldif.Attributes(attributes={}),
                )
                u.Ldap.Tests.fail(adapter.add(entry), has=needle)
            case self.DisconnectedOp.DELETE:
                u.Ldap.Tests.fail(
                    adapter.delete(c.Ldap.Tests.RFC_DEFAULT_BASE_DN),
                    has=needle,
                )
            case self.DisconnectedOp.MODIFY:
                u.Ldap.Tests.fail(
                    adapter.modify(c.Ldap.Tests.RFC_DEFAULT_BASE_DN, {}),
                    has=needle,
                )
            case self.DisconnectedOp.SEARCH:
                options = m.Ldap.SearchOptions(
                    base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
                    filter_str=c.Ldap.Tests.SEARCH_FILTER_CN,
                    scope=c.Ldap.SearchScope.SUBTREE,
                )
                u.Ldap.Tests.fail(adapter.search(options), has=needle)

    def test_disconnect_is_idempotent_and_keeps_state_unbound(
        self,
        adapter: FlextLdapLdap3Adapter,
    ) -> None:
        # Disconnecting a never-connected adapter is a no-op that raises
        # nothing and leaves the observable state unbound; repeat is safe.
        adapter.disconnect()
        adapter.disconnect()
        u.Ldap.Tests.that(adapter.is_connected, eq=False)
        u.Ldap.Tests.that(adapter.connection, eq=None)

    @pytest.mark.parametrize("case", list(c.Ldap.Tests.Ldap3ServerCase))
    def test_create_server_configures_host_and_port(
        self,
        case: c.Ldap.Tests.Ldap3ServerCase,
    ) -> None:
        # create_server is public via the ConnectionManager ClassVar; its
        # contract is a Server object addressing the requested host/port
        # across plain / SSL / TLS transport modes.
        port, use_ssl, use_tls = c.Ldap.Tests.LDAP3_SERVER_SCENARIOS[case]
        settings = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=port,
            use_ssl=use_ssl,
            use_tls=use_tls,
            timeout=c.Ldap.Tests.LDAP3_ADAPTER_DEFAULT_TIMEOUT,
        )

        server = FlextLdapLdap3Adapter.ConnectionManager.create_server(settings)

        tm.that(server, none=False)
        u.Ldap.Tests.that(
            getattr(server, c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.STRING_EMPTY),
            eq=c.LOCALHOST,
        )
        u.Ldap.Tests.that(
            getattr(
                server,
                c.Ldap.Tests.FIELD_PORT,
                c.Ldap.Tests.SYNC_DEFAULT_ZERO_COUNT,
            ),
            eq=port,
        )

    def test_adapter_host_reports_unbound_before_use(self) -> None:
        # FlextLdapAdapterHost exposes is_connected without eagerly building
        # an adapter; before any use it must observe an unbound state.
        host = FlextLdapAdapterHost()
        u.Ldap.Tests.that(host.is_connected, eq=False)
