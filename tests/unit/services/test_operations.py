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

Module: TestFlextLdapOperations
Scope: Comprehensive operations testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest
from flext_core import FlextConfig
from flext_tests import FlextTestsMatchers

from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations

from ...fixtures.constants import TestConstants
from ...helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.unit


class TestFlextLdapOperations:
    """Comprehensive tests for FlextLdapOperations using factories and DRY principles.

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
        return FlextLdapConnection(config=FlextLdapConfig.get_instance())

    @classmethod
    def _create_operations(
        cls, connection: FlextLdapConnection | None = None
    ) -> FlextLdapOperations:
        """Factory method for creating operations service instances."""
        conn = connection or cls._create_connection()
        return FlextLdapOperations(connection=conn)

    def test_init_without_connection_raises_type_error(self) -> None:
        """Test that __init__ raises TypeError when connection is not provided."""
        cls = __import__(
            "flext_ldap.services.operations", fromlist=["FlextLdapOperations"]
        ).FlextLdapOperations
        with pytest.raises(TypeError, match="missing 1 required positional argument"):
            cls()

    def test_init_with_connection_succeeds(self) -> None:
        """Test that __init__ succeeds when connection is provided."""
        connection = self._create_connection()
        operations = self._create_operations(connection)
        assert operations is not None
        assert operations._connection is connection

    def test_operations_initialization(self) -> None:
        """Test operations service initialization."""
        operations = self._create_operations()
        assert operations is not None
        assert operations._connection is not None
        assert operations.logger is not None

    def test_config_property(self) -> None:
        """Test config property returns FlextConfig with ldap namespace."""
        operations = self._create_operations()
        config = operations.config
        assert config is not None
        assert isinstance(config, FlextConfig)

    def test_is_connected_not_connected(self) -> None:
        """Test is_connected returns False when not connected."""
        operations = self._create_operations()
        assert operations.is_connected is False

    @pytest.mark.parametrize(
        ("error_message", "expected"),
        [(msg, expected) for msg, expected in _ERROR_DETECTION_SCENARIOS.items()],
    )
    def test_is_already_exists_error_detection(
        self, error_message: str, expected: bool
    ) -> None:
        """Test is_already_exists_error detects various 'already exists' patterns."""
        result = FlextLdapOperations.is_already_exists_error(error_message)
        assert result is expected

    @pytest.mark.parametrize(
        "scenario",
        ["identical", "different"],
    )
    def test_entry_comparison(self, scenario: str) -> None:
        """Test EntryComparison.compare with identical/different entries."""
        attrs = self._ENTRY_SCENARIOS[scenario]
        entry1 = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN, self._ENTRY_SCENARIOS["identical"]
        )
        entry2 = EntryTestHelpers.create_entry(TestConstants.Operations.TEST_DN, attrs)
        changes = FlextLdapOperations.EntryComparison.compare(entry1, entry2)
        if scenario == "identical":
            assert changes is None
        else:
            assert changes is not None
            assert isinstance(changes, dict)
            assert "sn" in changes

    def test_execute_method_returns_result(self) -> None:
        """Test execute method returns a FlextResult."""
        operations = self._create_operations()
        result = operations.execute()
        FlextTestsMatchers.assert_failure(result)

    def test_upsert_method_calls_internal(self) -> None:
        """Test upsert method calls internal implementation."""
        operations = self._create_operations()
        entry = EntryTestHelpers.create_entry(
            TestConstants.Operations.TEST_DN,
            {"cn": ["test"], "objectClass": ["person"]},
        )
        result = operations.upsert(entry)
        FlextTestsMatchers.assert_failure(result)

    def test_batch_upsert_method_exists(self) -> None:
        """Test batch_upsert method exists."""
        operations = self._create_operations()
        entries = [
            EntryTestHelpers.create_entry(
                TestConstants.Operations.TEST_DN_1, {"cn": ["test1"]}
            )
        ]
        result = operations.batch_upsert(entries)
        FlextTestsMatchers.assert_failure(result)

    def test_search_method_exists(self) -> None:
        """Test that search method exists and can be called."""
        operations = self._create_operations()
        search_options = FlextLdapModels.SearchOptions(
            base_dn=TestConstants.Operations.BASE_DN,
            filter_str=TestConstants.Operations.DEFAULT_FILTER,
            scope="SUBTREE",
        )
        result = operations.search(search_options)
        FlextTestsMatchers.assert_failure(result)
