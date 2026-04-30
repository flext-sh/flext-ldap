"""Unit tests for flext_ldap.services.operations.FlextLdapOperations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapOperations
from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapOperations:
    """Tests for FlextLdapOperations MRO mixin.

    Operations is now an MRO mixin inheriting from FlextLdapConnection.
    Instantiate with FlextLdapOperations() — no constructor args needed.
    """

    def test_is_connected_not_connected(self) -> None:
        """Test is_connected returns False when not connected."""
        operations = FlextLdapOperations()
        u.Ldap.Tests.that(not operations.is_connected, eq=True)

    @pytest.mark.parametrize(
        ("error_message", "expected"),
        list(c.Ldap.Tests.OPERATIONS_ERROR_DETECTION_SCENARIOS.items()),
    )
    def test_already_exists_error_detection(
        self,
        error_message: str,
        expected: bool,
    ) -> None:
        """Test already_exists_error detects various 'already exists' patterns."""
        result = FlextLdapOperations.already_exists_error(error_message)
        u.Ldap.Tests.that(result, eq=expected)

    def test_execute_method_returns_result(self) -> None:
        """Test execute method returns a r (fail when not connected)."""
        operations = FlextLdapOperations()
        result = operations.execute()
        u.Ldap.Tests.fail(result)

    def test_search_without_connection_returns_failure(self) -> None:
        """search() must return a fail r when no connection is bound."""
        operations = FlextLdapOperations()
        search_options = m.Ldap.SearchOptions(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            scope=c.Ldap.SearchScope.SUBTREE.value,
        )
        result = operations.search(search_options)
        u.Ldap.Tests.fail(result)
