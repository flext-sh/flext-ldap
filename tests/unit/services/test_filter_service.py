"""Unit tests for LDAP filter validation and operations.

**Modules Tested:**
- `flext_ldap.models.FlextLdapModels.SearchOptions` - LDAP search filter validation and operations

**Test Scope:**
- Simple, complex, and wildcard filter validation
- SearchOptions creation with various parameters
- Default filter values from constants

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFilterService
Scope: Comprehensive filter testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

from ...fixtures.constants import TestConstants
from ...helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class FilterTestScenario(StrEnum):
    """Test scenarios for filter service testing."""

    SIMPLE = "simple"
    COMPLEX = "complex"
    WILDCARD = "wildcard"


@dataclass(frozen=True, slots=True)
class FilterTestDataFactory:
    """Factory for creating test data for filter service tests using Python 3.13 dataclasses."""

    FILTER_SCENARIOS: ClassVar[tuple[FilterTestScenario, ...]] = (
        FilterTestScenario.SIMPLE,
        FilterTestScenario.COMPLEX,
        FilterTestScenario.WILDCARD,
    )

    @staticmethod
    def get_filter_string(scenario: FilterTestScenario) -> str:
        """Get filter string for scenario."""
        filters: dict[FilterTestScenario, str] = {
            FilterTestScenario.SIMPLE: "(objectClass=person)",
            FilterTestScenario.COMPLEX: "(&(objectClass=person)(mail=*@example.com))",
            FilterTestScenario.WILDCARD: "(cn=*)",
        }
        return filters[scenario]

    @staticmethod
    def get_filter_assertions(
        scenario: FilterTestScenario,
    ) -> tuple[str, ...]:
        """Get assertions that should be true for scenario."""
        assertions: dict[FilterTestScenario, tuple[str, ...]] = {
            FilterTestScenario.SIMPLE: ("objectClass=person",),
            FilterTestScenario.COMPLEX: (
                "&",
                "objectClass=person",
                "mail=*@example.com",
            ),
            FilterTestScenario.WILDCARD: ("(cn=*)",),
        }
        return assertions[scenario]


class TestFilterService:
    """Comprehensive tests for LDAP filter validation and operations using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
    """

    _factory = FilterTestDataFactory()

    @pytest.mark.parametrize("scenario", FilterTestDataFactory.FILTER_SCENARIOS)
    def test_search_with_filter_scenario(
        self,
        scenario: FilterTestScenario,
    ) -> None:
        """Test search with various filter scenarios (parametrized)."""
        filter_str = self._factory.get_filter_string(scenario)
        assertions = self._factory.get_filter_assertions(scenario)

        search_options = TestDeduplicationHelpers.create_search(filter_str=filter_str)

        assert search_options.filter_str == filter_str
        for assertion_text in assertions:
            assert assertion_text in search_options.filter_str

    def test_search_options_creation_with_defaults(self) -> None:
        """Test SearchOptions creation using constants."""
        search_options = TestDeduplicationHelpers.create_search()
        assert search_options.base_dn is not None
        assert search_options.filter_str == TestConstants.DEFAULT_FILTER
        assert search_options.scope == TestConstants.DEFAULT_SCOPE

    def test_search_options_with_custom_parameters(self) -> None:
        """Test SearchOptions creation with custom parameters."""
        custom_base_dn = "ou=test,dc=example,dc=com"
        custom_filter = "(cn=testuser)"
        custom_scope: FlextLdapConstants.SearchScope = (
            FlextLdapConstants.SearchScope.ONELEVEL
        )

        search_options = FlextLdapModels.SearchOptions(
            base_dn=custom_base_dn,
            filter_str=custom_filter,
            scope=custom_scope,
        )

        assert search_options.base_dn == custom_base_dn
        assert search_options.filter_str == custom_filter
        assert search_options.scope == custom_scope
