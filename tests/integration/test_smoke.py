"""Behavioral smoke tests for the ``flext_ldap.ldap`` public API.

These tests exercise the observable public contract of :class:`FlextLdap`
against a real LDAP container (REGRA 5: 100% REAL, NO MOCKS):

1. The external LDAP container is reachable through the ldap3 boundary.
2. ``ldap.connect`` returns a successful ``r[bool]`` and the public
   ``is_connected`` state reflects the connection lifecycle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap import ldap
from tests import t, u

pytestmark = pytest.mark.smoke


class TestsFlextLdapSmoke:
    """Smoke tests asserting the public behaviour of ``flext_ldap.ldap``."""

    def test_container_reachable_through_ldap3_boundary(
        self, ldap_container: t.MappingKV[str, t.Scalar]
    ) -> None:
        """The real LDAP container binds and exposes server info (precondition)."""
        # Arrange
        server = u.Ldap.Tests.create_ldap3_server(ldap_container)

        # Act
        connection = u.Ldap.Tests.create_ldap3_connection(server, ldap_container)

        # Assert - external boundary is healthy before exercising the unit
        try:
            u.Ldap.Tests.assert_connection_bound(connection)
            u.Ldap.Tests.assert_server_info_available(connection)
        finally:
            connection.unbind()

    def test_connect_succeeds_and_toggles_public_connected_state(
        self, ldap_container: t.MappingKV[str, t.Scalar]
    ) -> None:
        """``connect`` yields a successful result and drives ``is_connected``."""
        # Arrange
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        tm.that(ldap.is_connected, eq=False)

        # Act
        result = ldap.connect(conn_config)

        # Assert - public r[bool] contract and observable connected state
        try:
            tm.ok(result)
            tm.that(result.value, eq=True)
            tm.that(ldap.is_connected, eq=True)
        finally:
            ldap.disconnect()

        # Assert - disconnect is observable through the public API
        tm.that(ldap.is_connected, eq=False)

    def test_disconnect_is_idempotent_when_not_connected(self) -> None:
        """Disconnecting an unconnected client leaves ``is_connected`` False."""
        # Arrange - ensure a clean, disconnected client
        ldap.disconnect()
        tm.that(ldap.is_connected, eq=False)

        # Act - a second disconnect must not raise and must not connect
        ldap.disconnect()

        # Assert - idempotent, observable public state unchanged
        tm.that(ldap.is_connected, eq=False)
