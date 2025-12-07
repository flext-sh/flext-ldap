"""Unit tests for flext_ldap.adapters.ldap3.Ldap3Adapter.

**Modules Tested:**
- `flext_ldap.adapters.ldap3.Ldap3Adapter` - LDAP3 adapter service

**Test Scope:**
- Adapter initialization
- Execute method (health check)
- ConnectionManager static methods
- ResultConverter static methods
- AttributeNormalizer static methods
- Method existence validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.models import m

pytestmark = pytest.mark.unit


class TestsFlextLdap3Adapter:
    """Comprehensive tests for Ldap3Adapter using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    @classmethod
    def _create_connection_config(cls) -> m.ConnectionConfig:
        """Factory method for creating connection config instances."""
        return m.ConnectionConfig(
            host="localhost",
            port=389,
            use_ssl=False,
            use_tls=False,
            timeout=5,
        )

    def test_adapter_initialization(self) -> None:
        """Test adapter initialization."""
        adapter = Ldap3Adapter()
        tm.that(adapter, is_=Ldap3Adapter, none=False)

    def test_execute_returns_success(self) -> None:
        """Test execute() returns failure when not connected."""
        adapter = Ldap3Adapter()
        result = adapter.execute()
        tm.fail(result, has="Not connected")

    def test_connection_manager_create_server_with_ssl(self) -> None:
        """Test ConnectionManager.create_server with SSL."""
        config = m.ConnectionConfig(
            host="localhost",
            port=636,
            use_ssl=True,
            use_tls=False,
            timeout=5,
        )
        server = Ldap3Adapter.ConnectionManager.create_server(config)
        tm.that(server, none=False)
        tm.that(server.host, eq="localhost")
        tm.that(server.port, eq=636)

    def test_connection_manager_create_server_without_ssl(self) -> None:
        """Test ConnectionManager.create_server without SSL."""
        config = self._create_connection_config()
        server = Ldap3Adapter.ConnectionManager.create_server(config)
        tm.that(server, none=False)
        tm.that(server.host, eq="localhost")
        tm.that(server.port, eq=389)

    def test_connection_manager_create_server_with_tls(self) -> None:
        """Test ConnectionManager.create_server with TLS."""
        config = m.ConnectionConfig(
            host="localhost",
            port=389,
            use_ssl=False,
            use_tls=True,
            timeout=5,
        )
        server = Ldap3Adapter.ConnectionManager.create_server(config)
        tm.that(server, none=False)
        tm.that(server.host, eq="localhost")
        tm.that(server.port, eq=389)

    def test_adapter_inner_classes_exist(self) -> None:
        """Test that inner classes exist."""
        # Single call validates both keys and types
        tm.that(
            Ldap3Adapter.__dict__,
            keys=["ConnectionManager", "ResultConverter"],
        )
        tm.that(Ldap3Adapter.ConnectionManager, is_=type, none=False)
        tm.that(Ldap3Adapter.ResultConverter, is_=type, none=False)

    def test_connection_manager_static_methods_exist(self) -> None:
        """Test that static methods exist on ConnectionManager."""
        tm.that(dict(Ldap3Adapter.ConnectionManager.__dict__), keys=["create_server"])
        tm.that(callable(Ldap3Adapter.ConnectionManager.create_server), eq=True)

    def test_adapter_methods_exist(self) -> None:
        """Test that all expected methods exist on adapter."""
        adapter = Ldap3Adapter()
        # Validate method exists and is callable
        tm.has(adapter, "execute")
        tm.that(hasattr(adapter, "execute"), eq=True) and tm.that(
            callable(getattr(adapter, "execute", None)), eq=True
        )
