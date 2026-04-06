"""Unit tests for flext_ldap.adapters.ldap3.Ldap3Adapter.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapLdap3Adapter as Ldap3Adapter
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdap3Adapter:
    """Comprehensive tests for Ldap3Adapter.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    @classmethod
    def _create_connection_config(cls) -> m.Ldap.ConnectionConfig:
        return m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=c.Ldap.ConnectionDefaults.PORT,
            use_ssl=False,
            use_tls=False,
            timeout=c.Ldap.Tests.Ldap3Adapter.DEFAULT_TIMEOUT,
        )

    def test_adapter_initialization(self) -> None:
        adapter = Ldap3Adapter()
        u.Tests.Matchers.that(adapter, is_=Ldap3Adapter, none=False)

    def test_execute_returns_success(self) -> None:
        adapter = Ldap3Adapter()
        result = adapter.execute()
        u.Tests.Matchers.fail(result, has=c.Ldap.Tests.Ldap3Adapter.NOT_CONNECTED_ERROR)

    def test_connection_manager_create_server_with_ssl(self) -> None:
        config = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=c.Ldap.Tests.Config.LDAPS_PORT,
            use_ssl=True,
            use_tls=False,
            timeout=c.Ldap.Tests.Ldap3Adapter.DEFAULT_TIMEOUT,
        )
        server = Ldap3Adapter.ConnectionManager.create_server(config)
        assert server is not None
        u.Tests.Matchers.that(
            getattr(
                server, c.Ldap.Tests.FieldNames.HOST, c.Ldap.Tests.StringValues.EMPTY
            ),
            eq=c.LOCALHOST,
        )
        u.Tests.Matchers.that(
            getattr(
                server,
                c.Ldap.Tests.FieldNames.PORT,
                c.Ldap.Tests.Sync.Defaults.ZERO_COUNT,
            ),
            eq=c.Ldap.Tests.Config.LDAPS_PORT,
        )

    def test_connection_manager_create_server_without_ssl(self) -> None:
        config = self._create_connection_config()
        server = Ldap3Adapter.ConnectionManager.create_server(config)
        assert server is not None
        u.Tests.Matchers.that(
            getattr(
                server, c.Ldap.Tests.FieldNames.HOST, c.Ldap.Tests.StringValues.EMPTY
            ),
            eq=c.LOCALHOST,
        )
        u.Tests.Matchers.that(
            getattr(
                server,
                c.Ldap.Tests.FieldNames.PORT,
                c.Ldap.Tests.Sync.Defaults.ZERO_COUNT,
            ),
            eq=c.Ldap.ConnectionDefaults.PORT,
        )

    def test_connection_manager_create_server_with_tls(self) -> None:
        config = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=c.Ldap.ConnectionDefaults.PORT,
            use_ssl=False,
            use_tls=True,
            timeout=c.Ldap.Tests.Ldap3Adapter.DEFAULT_TIMEOUT,
        )
        server = Ldap3Adapter.ConnectionManager.create_server(config)
        assert server is not None
        u.Tests.Matchers.that(
            getattr(
                server, c.Ldap.Tests.FieldNames.HOST, c.Ldap.Tests.StringValues.EMPTY
            ),
            eq=c.LOCALHOST,
        )
        u.Tests.Matchers.that(
            getattr(
                server,
                c.Ldap.Tests.FieldNames.PORT,
                c.Ldap.Tests.Sync.Defaults.ZERO_COUNT,
            ),
            eq=c.Ldap.ConnectionDefaults.PORT,
        )

    def test_adapter_inner_classes_exist(self) -> None:
        assert (
            c.Ldap.Tests.Ldap3Adapter.INNER_CLASS_CONNECTION_MANAGER
            in Ldap3Adapter.__dict__
        )
        assert (
            c.Ldap.Tests.Ldap3Adapter.INNER_CLASS_RESULT_CONVERTER
            in Ldap3Adapter.__dict__
        )
        assert isinstance(Ldap3Adapter.ConnectionManager, type)
        assert isinstance(Ldap3Adapter.ResultConverter, type)

    def test_connection_manager_static_methods_exist(self) -> None:
        assert (
            c.Ldap.Tests.Ldap3Adapter.CREATE_SERVER_METHOD
            in Ldap3Adapter.ConnectionManager.__dict__
        )
        u.Tests.Matchers.that(
            callable(Ldap3Adapter.ConnectionManager.create_server), eq=True
        )

    def test_adapter_methods_exist(self) -> None:
        adapter = Ldap3Adapter()
        u.Tests.Matchers.that(hasattr(adapter, "execute"), eq=True)
        u.Tests.Matchers.that(callable(adapter.execute), eq=True)
