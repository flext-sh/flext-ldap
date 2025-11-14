"""Integration tests for FlextLdap API coverage with real LDAP server.

Tests API methods that need coverage, using real LDAP operations.
All tests use real LDAP server from fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdap
from flext_ldap.models import FlextLdapModels

pytestmark = pytest.mark.integration


class TestFlextLdapAPICoverage:
    """Tests for FlextLdap API methods needing coverage."""

    def test_operations_access(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test operations access via client property."""
        # Operations are accessed via client property
        operations = ldap_client.client
        assert operations is not None
        assert hasattr(operations, "search")
        assert hasattr(operations, "add")
        assert hasattr(operations, "modify")
        assert hasattr(operations, "delete")

    def test_context_manager_enter_exit(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager enter and exit."""
        with FlextLdap() as client:
            assert client is not None
            connect_result = client.connect(connection_config)
            assert connect_result.is_success
            assert client.is_connected is True

        # After exit, connection should be closed
        assert not client.is_connected

    def test_context_manager_with_exception(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager with exception handling."""
        client = FlextLdap()
        try:
            with client:
                connect_result = client.connect(connection_config)
                assert connect_result.is_success
                # Simulate exception
                test_exception = ValueError("Test exception")
                raise test_exception
        except ValueError:
            pass

        # Connection should still be closed after exception
        assert not client.is_connected

    def test_execute_method(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute method for health check."""
        result = ldap_client.execute()
        assert result.is_success
        search_result = result.unwrap()
        assert search_result is not None
        assert hasattr(search_result, "entries")
        assert hasattr(search_result, "total_count")
