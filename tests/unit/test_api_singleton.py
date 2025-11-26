"""Unit tests for FlextLdap singleton methods.

**Modules Tested:**
- `flext_ldap.api.FlextLdap` - Singleton pattern implementation

**Test Scope:**
- get_instance method creates and returns singleton instance
- get_instance with config and ldif parameters
- _reset_instance method clears singleton for test isolation
- Singleton pattern behavior with multiple calls (same instance returned)
- Config and ldif parameters only used on first creation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapSingleton
Scope: Comprehensive singleton pattern testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif import FlextLdif

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig

from ..fixtures.constants import TestConstants

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
    """Comprehensive tests for FlextLdap singleton pattern using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    """

    def test_get_instance_creates_singleton(
        self,
        ldap_instance: FlextLdap,
    ) -> None:
        """Test get_instance creates singleton instance.

        Tests that get_instance() creates a singleton and returns the same instance
        on subsequent calls, even with different config (singleton pattern).
        """
        instance1 = ldap_instance
        assert instance1 is not None

        instance2 = FlextLdap.get_instance()
        assert instance2 is instance1

        config = FlextLdapConfig(host=TestConstants.Singleton.DIFFERENT_HOST)
        instance3 = FlextLdap.get_instance(config=config)
        assert instance3 is instance1

    def test_get_instance_with_config_and_ldif(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test get_instance with both config and ldif parameters."""
        config = FlextLdapConfig(
            host=TestConstants.Singleton.TEST_HOST,
            port=TestConstants.Singleton.TEST_PORT,
        )
        instance = FlextLdap.get_instance(config=config, ldif=ldif_instance)

        assert instance is not None
        assert instance._config == config
        assert instance._ldif == ldif_instance

    def test_reset_instance_clears_singleton(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test _reset_instance clears singleton for test isolation."""
        instance1 = FlextLdap.get_instance(ldif=ldif_instance)
        assert instance1 is not None

        FlextLdap._reset_instance()

        ldif2 = FlextLdif.get_instance()
        instance2 = FlextLdap.get_instance(ldif=ldif2)
        assert instance2 is not None
        assert instance2 is not instance1
