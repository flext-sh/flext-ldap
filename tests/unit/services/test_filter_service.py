"""Unit tests for LDAP filter validation and operations.

This module tests filter-related functionality using deduplication helpers
to reduce code duplication.

Tested modules:
- LDAP filter validation and search options

Test scope:
- Simple, complex, and wildcard filter validation
- SearchOptions creation with various parameters

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import pytest

from ...helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class FilterTestScenario(StrEnum):
    """Test scenarios for filter service testing."""

    SIMPLE = "simple"
    COMPLEX = "complex"
    WILDCARD = "wildcard"
    DEFAULT = "default"


class FilterTestCategory(StrEnum):
    """Test categories for filter operations."""

    BASIC = "basic"
    VALIDATION = "validation"
    OPTIONS = "options"


@dataclass(frozen=True, slots=True)
class FilterTestDataFactory:
    """Factory for creating test data for filter service tests."""

    # Filter test scenarios for parametrization
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
    """Tests for LDAP filter validation and operations.

    Single class with flat test methods covering:
    - Simple, complex, and wildcard filter validation
    - SearchOptions creation with defaults and custom parameters

    Previously flat test class enhanced with factory pattern and parametrization.
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
        assert search_options.filter_str is not None
        assert search_options.scope is not None
