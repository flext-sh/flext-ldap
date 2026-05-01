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

    @pytest.mark.parametrize(
        "invalid_password",
        c.Ldap.Tests.CONNECTION_INVALID_PASSWORDS,
    )
    def test_connect_with_invalid_password_fails(
        self,
        invalid_password: str,
    ) -> None:
        connection_config = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.DOCKER_PORT,
            use_ssl=False,
            bind_dn=c.Ldap.Tests.ENTRY_DN_ADMIN_EXAMPLE,
            bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )

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

    def test_context_manager_keeps_disconnected_state_when_not_connected(self) -> None:
        with ldap as client:
            assert not client.is_connected

        assert not ldap.is_connected
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )


__all__: list[str] = ["TestsFlextLdapConnection"]
