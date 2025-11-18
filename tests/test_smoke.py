"""Smoke tests for LDAP container connectivity (REGRA 5: 100% REAL, NO MOCKS).

These minimal tests verify:
1. LDAP container is running and responsive
2. FlextLdap API imports correctly
3. Basic connection works

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from ldap3 import Connection, Server

# Mark entire module as smoke tests
pytestmark = pytest.mark.smoke


def test_ldap_container_health(ldap_container: dict[str, object]) -> None:
    """SMOKE TEST: LDAP container is responsive (REGRA 5: REAL connection).

    This is the minimal test that must pass for ANY other test to work.
    Uses REAL ldap3 Connection (NO MOCKS).

    Args:
        ldap_container: Container connection info from fixture

    """
    # Create REAL ldap3 Server object
    server = Server(str(ldap_container["server_url"]), get_info="ALL")

    # Create REAL ldap3 Connection
    connection = Connection(
        server,
        user=str(ldap_container["bind_dn"]),
        password=str(ldap_container["password"]),
        auto_bind=True,  # REAL bind attempt
    )

    # Verify REAL connection is bound
    assert connection.bound, "LDAP server not responding to bind"

    # Verify REAL server info is available (schema loaded)
    assert connection.server.info is not None, "LDAP server info not available"
    assert connection.server.info.naming_contexts is not None, (
        "LDAP naming contexts not available"
    )

    # REAL unbind
    connection.unbind()


def test_flext_ldap_api_imports() -> None:
    """SMOKE TEST: FlextLdap API imports without errors (REGRA 5: REAL code).

    Verifies that the API can be imported and instantiated.
    Does NOT test connection - that's in test_ldap_container_health.
    """
    # Import REAL FlextLdap API (NO MOCKS)
    from flext_ldap import FlextLdap, FlextLdapModels

    # Instantiate REAL FlextLdap object (without connection)
    api = FlextLdap()
    assert api is not None, "FlextLdap API instantiation failed"

    # Verify models are accessible
    assert FlextLdapModels is not None, "FlextLdapModels not accessible"


def test_flext_ldap_basic_connection(ldap_container: dict[str, object]) -> None:
    """SMOKE TEST: FlextLdap can connect to container (REGRA 5: REAL operations).

    Tests basic connectivity through FlextLdap API.
    Uses REAL LDAP container and connection (NO MOCKS).

    Args:
        ldap_container: Container connection info

    """
    from flext_ldap import FlextLdap, FlextLdapModels
    from flext_ldap.config import FlextLdapConfig

    # Create REAL config from container info
    config = FlextLdapConfig(
        ldap_host=str(ldap_container["host"]),
        ldap_port=int(ldap_container["port"]),
        ldap_use_ssl=False,
        ldap_bind_dn=str(ldap_container["bind_dn"]),
        ldap_bind_password=str(ldap_container["password"]),
    )

    # Create REAL FlextLdap instance
    client = FlextLdap(config=config)

    # Create REAL connection config
    conn_config = FlextLdapModels.ConnectionConfig(
        host=str(ldap_container["host"]),
        port=int(ldap_container["port"]),
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )

    # Attempt REAL connection
    result = client.connect(conn_config)

    # Verify success
    assert result.is_success, f"Connection failed: {result.error}"

    # REAL disconnect
    client.disconnect()
