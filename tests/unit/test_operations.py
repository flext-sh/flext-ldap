"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

**Modules Tested:**
- `flext_ldap.services.operations.FlextLdapOperations` - LDAP operations service

**Test Scope:**
- Operations service initialization (MRO-based, no constructor args)
- Fast-fail pattern for disconnected operations
- Error handling and validation
- Entry comparison functionality
- Method existence validation

All tests use real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest
from flext_core import FlextSettings
from flext_tests import tm

from flext_ldap import FlextLdapOperations
from tests import c, m, t

pytestmark = pytest.mark.unit


class TestsFlextLdapOperations:
    """Tests for FlextLdapOperations MRO mixin.

    Operations is now an MRO mixin inheriting from FlextLdapConnection.
    Instantiate with FlextLdapOperations() — no constructor args needed.
    """

    _ERROR_DETECTION_SCENARIOS: ClassVar[Mapping[str, bool]] = {
        "Entry already exists": True,
        "already exists": True,
        "ALREADY EXISTS": True,
        "entryAlreadyExists": True,
        "Connection failed": False,
        "": False,
    }
    _ENTRY_SCENARIOS: ClassVar[Mapping[str, Mapping[str, t.StrSequence]]] = {
        "identical": {"cn": ["test"], "sn": ["User"]},
        "different": {"cn": ["test"], "sn": ["Different"]},
    }

    @classmethod
    def _create_operations(cls) -> FlextLdapOperations:
        """Factory — MRO-based, no constructor args."""
        return FlextLdapOperations()

    def test_operations_initialization(self) -> None:
        """Test operations service initializes via MRO (no args)."""
        operations = self._create_operations()
        tm.that(operations, none=False)
        tm.that(operations.logger, none=False)

    def test_config_property(self) -> None:
        """Test config property returns FlextSettings with ldap namespace."""
        operations = self._create_operations()
        assert isinstance(operations.config, FlextSettings)

    def test_is_connected_not_connected(self) -> None:
        """Test is_connected returns False when not connected."""
        operations = self._create_operations()
        tm.that(not operations.is_connected, eq=True)

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
        """Test execute method returns a r (fail when not connected)."""
        operations = self._create_operations()
        result = operations.execute()
        tm.fail(result)

    def test_search_method_exists(self) -> None:
        """Test that search method exists and returns fail when not connected."""
        operations = self._create_operations()
        rfc_constants = c.Ldap.Tests.RFC
        search_options = m.Ldap.SearchOptions(
            base_dn=rfc_constants.DEFAULT_BASE_DN,
            filter_str=rfc_constants.DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        result = operations.search(search_options)
        tm.fail(result)
