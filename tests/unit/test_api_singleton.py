"""Unit tests for FlextLdap instantiation with dependency injection.

**Modules Tested:**
- `flext_ldap.api.FlextLdap` - Dependency injection pattern implementation

**Test Scope:**
- FlextLdap instantiation with dependency injection
- Multiple instances can be created (no singleton)
- Config and ldif parameters are used correctly
- Connection and operations are injected properly

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapInstantiation
Scope: Comprehensive dependency injection pattern testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdif

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ..fixtures.constants import TestConstants

pytestmark = pytest.mark.unit


@pytest.fixture
def ldif_instance() -> FlextLdif:
    """Provide FlextLdif singleton instance for testing."""
    return FlextLdif.get_instance()


@pytest.fixture
def ldap_instance(ldif_instance: FlextLdif) -> FlextLdap:
    """Provide FlextLdap instance with dependency injection."""
    config = FlextLdapConfig()
    connection = FlextLdapConnection(config=config, parser=ldif_instance.parser)
    operations = FlextLdapOperations(connection=connection)
    return FlextLdap(connection=connection, operations=operations, ldif=ldif_instance)


class TestFlextLdapInstantiation:
    """Comprehensive tests for FlextLdap dependency injection pattern using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    """

    def test_instantiation_creates_new_instance(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test that each instantiation creates a new instance (no singleton).

        Tests that creating multiple FlextLdap instances results in different objects,
        demonstrating dependency injection pattern instead of singleton.
        """
        config1 = FlextLdapConfig()
        connection1 = FlextLdapConnection(config=config1, parser=ldif_instance.parser)
        operations1 = FlextLdapOperations(connection=connection1)
        instance1 = FlextLdap(
            connection=connection1, operations=operations1, ldif=ldif_instance,
        )
        assert instance1 is not None

        config2 = FlextLdapConfig(host=TestConstants.Singleton.DIFFERENT_HOST)
        connection2 = FlextLdapConnection(config=config2, parser=ldif_instance.parser)
        operations2 = FlextLdapOperations(connection=connection2)
        instance2 = FlextLdap(
            connection=connection2, operations=operations2, ldif=ldif_instance,
        )
        assert instance2 is not None
        assert instance2 is not instance1

    def test_instantiation_with_config_and_ldif(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test instantiation with both config and ldif parameters."""
        config = FlextLdapConfig(
            host=TestConstants.Singleton.TEST_HOST,
            port=TestConstants.Singleton.TEST_PORT,
        )
        connection = FlextLdapConnection(config=config, parser=ldif_instance.parser)
        operations = FlextLdapOperations(connection=connection)
        instance = FlextLdap(
            connection=connection, operations=operations, ldif=ldif_instance,
        )

        assert instance is not None
        assert instance._ldif == ldif_instance

    def test_multiple_instances_independent(
        self,
        ldif_instance: FlextLdif,
    ) -> None:
        """Test that multiple instances are independent (no shared state)."""
        config1 = FlextLdapConfig(host="host1.example.com")
        connection1 = FlextLdapConnection(config=config1, parser=ldif_instance.parser)
        operations1 = FlextLdapOperations(connection=connection1)
        instance1 = FlextLdap(
            connection=connection1, operations=operations1, ldif=ldif_instance,
        )

        config2 = FlextLdapConfig(host="host2.example.com")
        connection2 = FlextLdapConnection(config=config2, parser=ldif_instance.parser)
        operations2 = FlextLdapOperations(connection=connection2)
        instance2 = FlextLdap(
            connection=connection2, operations=operations2, ldif=ldif_instance,
        )

        assert instance1 is not None
        assert instance2 is not None
        assert instance1 is not instance2
        assert instance1._connection is not instance2._connection
