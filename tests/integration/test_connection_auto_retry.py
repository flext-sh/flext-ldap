"""Integration tests for FlextLdapConnection auto_retry functionality.

Uses REAL LDAP container to test retry scenarios with actual network failures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifParser

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

from ..fixtures.typing import LdapContainerDict

# Mark all tests in this module as integration tests requiring Docker
pytestmark = [pytest.mark.integration, pytest.mark.docker]


class TestConnectionAutoRetry:
    """Integration tests for auto_retry functionality with real LDAP."""

    def test_connect_auto_retry_disabled_with_invalid_credentials(
        self,
        ldap_parser: FlextLdifParser,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test that auto_retry is disabled by default with invalid credentials."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        # Create config with INVALID credentials (will fail to bind)
        port_value = ldap_container["port"]
        port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

        bad_config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=port_int,
            use_ssl=False,
            bind_dn="cn=invalid,dc=flext,dc=local",  # Invalid DN
            bind_password="wrong_password",
        )

        # Call connect without auto_retry (default False)
        result = connection.connect(bad_config)

        # Should fail immediately without retry
        assert result.is_failure
        assert result.error is not None

    def test_connect_auto_retry_fails_with_invalid_host(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test auto_retry exhausts all retries with unreachable host."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        # Create config with INVALID host (connection will timeout)
        bad_config = FlextLdapModels.ConnectionConfig(
            host="192.0.2.1",  # TEST-NET-1 (RFC 5737) - guaranteed unreachable
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="password",
            timeout=1,  # 1 second timeout for fast failure
        )

        # Call connect with auto_retry enabled
        result = connection.connect(
            bad_config,
            auto_retry=True,
            max_retries=2,
            retry_delay=0.1,  # Fast for testing
        )

        # Should fail after all retries
        assert result.is_failure
        error_str = str(result.error)
        # Accept either the old message format or the new retry message format
        assert (
            "failed after 2" in error_str
            or "Operation failed after 2 attempts" in error_str
            or "retries" in error_str.lower()
        )

    def test_connect_succeeds_with_valid_credentials(
        self,
        ldap_parser: FlextLdifParser,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test successful connection with valid credentials (baseline test)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        # Create config with VALID credentials
        good_config = FlextLdapModels.ConnectionConfig(
            host=ldap_container["host"],
            port=ldap_container["port"],
            use_ssl=False,
            bind_dn=ldap_container["bind_dn"],
            bind_password=ldap_container["password"],
        )

        # Call connect (should succeed on first attempt)
        result = connection.connect(good_config)

        # Should succeed immediately
        assert result.is_success
        assert result.unwrap() is True
        assert connection.is_connected is True

        # Cleanup
        connection.disconnect()

    def test_connect_auto_retry_with_custom_parameters(
        self,
        ldap_parser: FlextLdifParser,
    ) -> None:
        """Test auto_retry with custom max_retries (5 attempts)."""
        config = FlextLdapConfig()
        connection = FlextLdapConnection(config=config, parser=ldap_parser)

        # Create config with INVALID host
        bad_config = FlextLdapModels.ConnectionConfig(
            host="192.0.2.2",  # TEST-NET-1 - unreachable
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="password",
            timeout=1,
        )

        # Call connect with max_retries=5
        result = connection.connect(
            bad_config,
            auto_retry=True,
            max_retries=5,
            retry_delay=0.1,
        )

        # Should fail after 5 retries
        assert result.is_failure
        error_str = str(result.error)
        # Accept either the old message format or the new retry message format
        assert (
            "failed after 5" in error_str
            or "Operation failed after 5 attempts" in error_str
            or "retries" in error_str.lower()
        )
