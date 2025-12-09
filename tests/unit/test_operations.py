"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

**Modules Tested:**
- `flext_ldap.services.operations.FlextLdapOperations` - LDAP operations service

**Test Scope:**
- Operations service initialization and configuration access
- Fast-fail pattern for disconnected operations
- Error handling and validation
- Entry comparison functionality
- Method existence validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest
from flext_core import FlextConfig
from flext_tests import tm

from flext_ldap import m
from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests import c

pytestmark = pytest.mark.unit


class TestsFlextLdapOperations:
    """Comprehensive tests for FlextLdapOperations using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    # Error detection scenarios using mapping for DRY
    _ERROR_DETECTION_SCENARIOS: ClassVar[Mapping[str, bool]] = {
        "Entry already exists": True,
        "already exists": True,
        "ALREADY EXISTS": True,
        "entryAlreadyExists": True,
        "ldap_already_exists": True,
        "Connection failed": False,
        "": False,
    }

    # Entry comparison scenarios
    _ENTRY_SCENARIOS: ClassVar[Mapping[str, dict[str, list[str]]]] = {
        "identical": {"cn": ["test"], "sn": ["User"]},
        "different": {"cn": ["test"], "sn": ["Different"]},
    }

    @classmethod
    def _create_connection(cls) -> FlextLdapConnection:
        """Factory method for creating connection instances."""
        # but services pass complex objects via __init__ which are validated at runtime
        return FlextLdapConnection(config=FlextLdapConfig())

    @classmethod
    def _create_operations(
        cls,
        connection: FlextLdapConnection | None = None,
    ) -> FlextLdapOperations:
        """Factory method for creating operations service instances."""
        conn = connection or cls._create_connection()
        return FlextLdapOperations(connection=conn)

    def test_init_without_connection_raises_type_error(self) -> None:
        """Test that __init__ raises TypeError when connection is not provided."""
        cls = __import__(
            "flext_ldap.services.operations",
            fromlist=["FlextLdapOperations"],
        ).FlextLdapOperations
        with pytest.raises(TypeError, match="missing 1 required positional argument"):
            cls()

    def test_init_with_connection_succeeds(self) -> None:
        """Test that __init__ succeeds when connection is provided."""
        connection = self._create_connection()
        operations = self._create_operations(connection)
        tm.that(operations, none=False)
        tm.that(operations._connection, eq=connection)

    def test_operations_initialization(self) -> None:
        """Test operations service initialization."""
        operations = self._create_operations()
        tm.that(operations, none=False)
        tm.that(operations._connection, none=False)
        tm.that(operations.logger, none=False)

    def test_config_property(self) -> None:
        """Test config property returns FlextConfig with ldap namespace."""
        operations = self._create_operations()
        tm.that(operations.config, is_=FlextConfig, none=False)

    def test_is_connected_not_connected(self) -> None:
        """Test is_connected returns False when not connected."""
        operations = self._create_operations()
        tm.that(operations.is_connected, eq=False)

    @pytest.mark.parametrize(
        ("error_message", "expected"),
        [(msg, expected) for msg, expected in _ERROR_DETECTION_SCENARIOS.items()],
    )
    def test_is_already_exists_error_detection(
        self,
        error_message: str,
        expected: bool,
    ) -> None:
        """Test is_already_exists_error detects various 'already exists' patterns."""
        result = FlextLdapOperations.is_already_exists_error(error_message)
        tm.that(result, eq=expected)

    def test_execute_method_returns_result(self) -> None:
        """Test execute method returns a FlextResult."""
        operations = self._create_operations()
        result = operations.execute()
        tm.fail(result)

    def test_search_method_exists(self) -> None:
        """Test that search method exists and can be called."""
        operations = self._create_operations()
        # Use constants directly from TestsFlextLdapConstants.RFC
        rfc_constants = c.RFC
        search_options = m.Ldap.SearchOptions(
            base_dn=rfc_constants.DEFAULT_BASE_DN,
            filter_str=rfc_constants.DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        result = operations.search(search_options)
        tm.fail(result)
