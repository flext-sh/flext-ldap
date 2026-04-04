"""Smoke tests for LDAP container connectivity (REGRA 5: 100% REAL, NO MOCKS).

Tests verify:
1. LDAP container is running and responsive
2. ldap API imports correctly
3. Basic connection works

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldap import ldap
from tests import t, u

pytestmark = pytest.mark.smoke


class TestsFlextLdapSmoke:
    """Smoke tests for flext-ldap using single class architecture.

    All factories and assertions use u.Ldap.Tests.SmokeFactories
    and u.Ldap.Tests.SmokeAssertions from the canonical namespace.
    """

    def test_ldap_container_health(
        self,
        ldap_container: t.Ldap.Tests.LdapContainerDict,
    ) -> None:
        """SMOKE TEST: LDAP container is responsive (REGRA 5: REAL connection)."""
        server = u.Ldap.Tests.SmokeFactories.create_ldap3_server(ldap_container)
        connection = u.Ldap.Tests.SmokeFactories.create_ldap3_connection(
            server,
            ldap_container,
        )
        u.Ldap.Tests.SmokeAssertions.assert_connection_bound(connection)
        u.Ldap.Tests.SmokeAssertions.assert_server_info_available(connection)
        connection.unbind()

    def test_flext_ldap_api_imports(self) -> None:
        """SMOKE TEST: ldap API imports without errors (REGRA 5: REAL code)."""
        api = ldap()
        u.Ldap.Tests.SmokeAssertions.assert_api_instantiated(api)
        u.Ldap.Tests.SmokeAssertions.assert_models_accessible()

    def test_flext_ldap_basic_connection(
        self,
        ldap_container: t.Ldap.Tests.LdapContainerDict,
    ) -> None:
        """SMOKE TEST: ldap can connect to container (REGRA 5: REAL operations)."""
        client = ldap()
        conn_config = u.Ldap.Tests.SmokeFactories.create_connection_config(
            ldap_container,
        )
        result = client.connect(conn_config)
        u.Ldap.Tests.SmokeAssertions.assert_connection_success(result)
        client.disconnect()
