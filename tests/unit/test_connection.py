"""Unit tests for LDAP connection lifecycle through the public facade.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import ldap
from tests import c, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapConnection:
    """Connection lifecycle tests through public API only."""

    def test_is_connected_default_false(self) -> None:
        """Test that is_connected is False by default."""
        u.Ldap.Tests.that(not ldap.is_connected, eq=True)

    def test_execute_without_connection_returns_failure(self) -> None:
        """Test execute fails when not connected."""
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )

    def test_context_manager_keeps_disconnected_state_when_not_connected(self) -> None:
        """Test context manager preserves disconnected state."""
        with ldap as client:
            assert not client.is_connected

        assert not ldap.is_connected
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )


__all__: list[str] = ["TestsFlextLdapConnection"]
