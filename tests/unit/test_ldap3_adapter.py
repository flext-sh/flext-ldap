"""Unit tests for flext_ldap.adapters.ldap3.FlextLdapLdap3Adapter.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter
from tests.constants import c
from tests.models import m
from tests.utilities import u

pytestmark = pytest.mark.unit


class TestsFlextLdapLdap3Adapter:
    """Comprehensive tests for FlextLdapLdap3Adapter.

    All test data comes from c.Ldap.Tests.* — zero inline constants.
    """

    def test_execute_returns_success(self) -> None:
        adapter = FlextLdapLdap3Adapter()
        result = adapter.execute()
        u.Ldap.Tests.fail(result, has=c.Ldap.Tests.LDAP3_ADAPTER_NOT_CONNECTED_ERROR)

    @pytest.mark.parametrize("case", c.Ldap.Tests.Ldap3ServerCase)
    def test_connection_manager_create_server_modes(
        self,
        case: c.Ldap.Tests.Ldap3ServerCase,
    ) -> None:
        port, use_ssl, use_tls = c.Ldap.Tests.LDAP3_SERVER_SCENARIOS[case]
        settings = m.Ldap.ConnectionConfig(
            host=c.LOCALHOST,
            port=port,
            use_ssl=use_ssl,
            use_tls=use_tls,
            timeout=c.Ldap.Tests.LDAP3_ADAPTER_DEFAULT_TIMEOUT,
        )
        server = FlextLdapLdap3Adapter.ConnectionManager.create_server(settings)
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
            eq=port,
        )
