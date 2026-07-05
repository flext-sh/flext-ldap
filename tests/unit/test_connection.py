"""Behavioral unit tests for the LDAP connection lifecycle facade.

Exercises the public contract of ``flext_ldap.ldap`` (connect / disconnect /
execute / is_connected / context manager) through observable return values,
``r[T]`` outcomes, and public state only. No private attributes, collaborator
spying, or internal patching.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from flext_ldap import ldap
from tests.constants import c
from tests.models import m
from tests.utilities import u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapConnection:
    """Connection lifecycle contract, asserted through the public API only."""

    @pytest.fixture(autouse=True)
    def _isolated_disconnected_facade(self) -> Iterator[None]:
        """Guarantee each test starts and ends from a disconnected facade."""
        ldap.disconnect()
        yield
        ldap.disconnect()

    def _invalid_config(self) -> m.Ldap.ConnectionConfig:
        """Build a typed config pointing at an unreachable host."""
        return m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.CONFIG_INVALID_HOST,
            port=c.Ldap.PORT,
            bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
            bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )

    def test_is_connected_is_false_before_any_connection(self) -> None:
        """A freshly obtained facade reports no active connection."""
        u.Ldap.Tests.that(ldap.is_connected, eq=False)

    def test_execute_without_connection_fails_with_not_connected(self) -> None:
        """execute() surfaces a NOT_CONNECTED failure when unbound."""
        error = u.Ldap.Tests.fail(ldap.execute())

        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )

    @pytest.mark.parametrize("auto_retry", [False, True])
    def test_connect_invalid_host_fails_and_stays_disconnected(
        self,
        *,
        auto_retry: bool,
    ) -> None:
        """connect() to an unreachable host fails without binding the facade.

        The failure path is identical whether or not automatic retry is
        requested: the returned ``r[bool]`` is a failure and ``is_connected``
        remains ``False`` (no partial-success invention).
        """
        result = ldap.connect(
            self._invalid_config(),
            auto_retry=auto_retry,
            max_retries=1,
            retry_delay=0.0,
        )

        error = u.Ldap.Tests.fail(result)
        u.Ldap.Tests.that(error, none=False)
        u.Ldap.Tests.that(ldap.is_connected, eq=False)

    def test_disconnect_is_idempotent_and_preserves_failure_semantics(
        self,
    ) -> None:
        """Repeated disconnect() calls are safe and keep execute() failing."""
        ldap.disconnect()
        ldap.disconnect()

        u.Ldap.Tests.that(ldap.is_connected, eq=False)
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )

    def test_context_manager_yields_same_facade(self) -> None:
        """The context manager binds the facade itself as the ``as`` target."""
        with ldap as client:
            assert client is ldap

    def test_context_manager_exit_leaves_facade_disconnected(self) -> None:
        """Leaving the context disconnects and keeps NOT_CONNECTED semantics."""
        with ldap as client:
            u.Ldap.Tests.that(client.is_connected, eq=False)

        u.Ldap.Tests.that(ldap.is_connected, eq=False)
        error = u.Ldap.Tests.fail(ldap.execute())
        u.Ldap.Tests.that(
            error.lower(),
            contains=str(c.Ldap.ErrorMessage.NOT_CONNECTED).lower(),
        )


__all__: list[str] = ["TestsFlextLdapConnection"]
