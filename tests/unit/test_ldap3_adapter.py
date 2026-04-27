"""Unit tests for flext_ldap.adapters.ldap3.Ldap3Adapter.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapLdap3Adapter as Ldap3Adapter
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapLdap3Adapter:
    """Comprehensive tests for Ldap3Adapter.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    @classmethod
    def _create_connection_config(cls) -> m.Ldap.ConnectionConfig:
        return m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=c.Ldap.PORT,
            use_ssl=False,
            use_tls=False,
            timeout=c.Ldap.Tests.LDAP3_ADAPTER_DEFAULT_TIMEOUT,
        )

    def test_adapter_initialization(self) -> None:
        adapter = Ldap3Adapter()
        u.Ldap.Tests.that(adapter, is_=Ldap3Adapter, none=False)

    def test_execute_returns_success(self) -> None:
        adapter = Ldap3Adapter()
        result = adapter.execute()
        u.Ldap.Tests.fail(result, has=c.Ldap.Tests.LDAP3_ADAPTER_NOT_CONNECTED_ERROR)

    def test_connection_manager_create_server_with_ssl(self) -> None:
        settings = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            use_ssl=True,
            use_tls=False,
            timeout=c.Ldap.Tests.LDAP3_ADAPTER_DEFAULT_TIMEOUT,
        )
        server = Ldap3Adapter.ConnectionManager.create_server(settings)
        assert server is not None
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
            eq=c.Ldap.Tests.CONFIG_LDAPS_PORT,
        )

    def test_connection_manager_create_server_without_ssl(self) -> None:
        settings = self._create_connection_config()
        server = Ldap3Adapter.ConnectionManager.create_server(settings)
        assert server is not None
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
            eq=c.Ldap.PORT,
        )

    def test_connection_manager_create_server_with_tls(self) -> None:
        settings = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=c.Ldap.PORT,
            use_ssl=False,
            use_tls=True,
            timeout=c.Ldap.Tests.LDAP3_ADAPTER_DEFAULT_TIMEOUT,
        )
        server = Ldap3Adapter.ConnectionManager.create_server(settings)
        assert server is not None
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
            eq=c.Ldap.PORT,
        )

    def test_connection_manager_create_server_api_is_callable(self) -> None:
        u.Ldap.Tests.that(
            callable(Ldap3Adapter.ConnectionManager.create_server), eq=True
        )

    def test_adapter_methods_exist(self) -> None:
        adapter = Ldap3Adapter()
        u.Ldap.Tests.that(hasattr(adapter, "execute"), eq=True)
        u.Ldap.Tests.that(callable(adapter.execute), eq=True)
