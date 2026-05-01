"""Unit tests for LDAP connection lifecycle through the public facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import ldap
from tests import c, m, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapConnection:
    """Connection lifecycle tests through public API only."""

    def test_connect_execute_disconnect_cycle(
        self,
        connection_config: m.Ldap.ConnectionConfig,
    ) -> None:
        u.Ldap.Tests.assert_connection_success(ldap.connect(connection_config))
        assert ldap.is_connected

        u.Ldap.Tests.ok(ldap.execute())

        ldap.disconnect()
        assert not ldap.is_connected
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )

    @pytest.mark.parametrize(
        "invalid_password",
        c.Ldap.Tests.CONNECTION_INVALID_PASSWORDS,
    )
    def test_connect_with_invalid_password_fails(
        self,
        connection_config: m.Ldap.ConnectionConfig,
        invalid_password: str,
    ) -> None:
        bad_config = connection_config.model_copy(
            update={
                c.Ldap.Tests.FIELD_BIND_PASSWORD: invalid_password,
            },
        )

        error = u.Ldap.Tests.fail(ldap.connect(bad_config))
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.CONNECTION_FAILED).lower(),
        )
        assert not ldap.is_connected

    def test_context_manager_disconnects_after_successful_connect(
        self,
        connection_config: m.Ldap.ConnectionConfig,
    ) -> None:
        with ldap as client:
            u.Ldap.Tests.assert_connection_success(client.connect(connection_config))
            assert client.is_connected

        assert not ldap.is_connected
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )


__all__: list[str] = ["TestsFlextLdapConnection"]
