"""Unit tests for FlextLdap singleton methods.

**Modules Tested:**
- flext_ldap.api.FlextLdap: Singleton pattern implementation

**Scope:**
- get_instance method creates and returns singleton instance
- get_instance with config and parser parameters
- _reset_instance method clears singleton for test isolation
- Singleton pattern behavior with multiple calls

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif import FlextLdif

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None]:
    """Auto-reset singleton before and after each test for isolation."""
    FlextLdap._reset_instance()
    yield
    FlextLdap._reset_instance()


@pytest.fixture
def ldif_instance() -> FlextLdif:
    """Provide FlextLdif singleton instance for testing."""
    return FlextLdif.get_instance()


@pytest.fixture
def ldap_instance(ldif_instance: FlextLdif) -> FlextLdap:
    """Provide FlextLdap singleton instance with FlextLdif."""
    return FlextLdap.get_instance(ldif=ldif_instance)


class TestFlextLdapSingleton:
    """Tests for FlextLdap singleton pattern methods."""

    def test_get_instance_creates_singleton(
        self,
        ldap_instance: FlextLdap,
    ) -> None:
        """Test get_instance creates singleton instance.

        Tests that get_instance() creates a singleton and returns the same instance
        on subsequent calls, even with different config (singleton pattern).
        """
        # Instance provided by fixture is singleton
        instance1 = ldap_instance
        assert instance1 is not None

        # Second call should return same instance
        instance2 = FlextLdap.get_instance()
        assert instance2 is instance1

        # Third call with different config should still return same instance
        # (singleton pattern - config is only used on first creation)
        config = FlextLdapConfig(host="different.example.com")
        instance3 = FlextLdap.get_instance(config=config)
        assert instance3 is instance1

    def test_get_instance_with_config_and_parser(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test get_instance with both config and parser."""
        config = FlextLdapConfig(host="test.example.com", port=389)
        instance = FlextLdap.get_instance(config=config, ldif=ldif_instance)

        assert instance is not None
        assert instance._config == config
        assert instance._ldif == ldif_instance

    def test_reset_instance_clears_singleton(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test _reset_instance clears singleton for test isolation."""
        # Create instance
        instance1 = FlextLdap.get_instance(ldif=ldif_instance)
        assert instance1 is not None

        # Reset singleton
        FlextLdap._reset_instance()

        # New call should create new instance
        ldif2 = FlextLdif.get_instance()
        instance2 = FlextLdap.get_instance(ldif=ldif2)
        assert instance2 is not None
        # Should be different instance (singleton was reset)
        assert instance2 is not instance1
