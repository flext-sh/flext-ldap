"""Unit tests for flext_ldap.utilities.FlextLdapUtilities.

**Modules Tested:**
- `flext_ldap.utilities.FlextLdapUtilities` - LDAP-specific utilities

**Test Scope:**
- Utility method functionality
- String conversion and normalization
- List operations
- Filtering and mapping operations
- Callable finding with variance/covariance patterns

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import ClassVar

import pytest
from flext_core import t as core_t_flex
from flext_tests import tm

from tests import u

pytestmark = pytest.mark.unit


class TestsFlextLdapUtilities:
    """Comprehensive tests for FlextLdapUtilities using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

    Uses parametrized tests and constants for maximum code reuse.
    All helper logic is nested within this single class following FLEXT patterns.
    """

    # Test data scenarios
    _STRING_VALUES: ClassVar[Mapping[str, str]] = {
        "simple": "test",
        "empty": "",
        "whitespace": "  test  ",
        "unicode": "café",
    }

    _LIST_VALUES: ClassVar[Mapping[str, object]] = {
        "list_str": ["a", "b", "c"],
        "list_mixed": ["a", 1, True],
        "tuple": ("a", "b"),
        "single": "single",
        "none": None,
    }

    def test_to_str_simple(self) -> None:
        """Test to_str with simple string value."""
        result = u.to_str("test")
        tm.that(result, eq="test")

    def test_to_str_none(self) -> None:
        """Test to_str with None value."""
        result = u.to_str(None)
        tm.that(result, eq="")

    def test_to_str_with_default(self) -> None:
        """Test to_str with custom default."""
        result = u.to_str(None, default="default")
        tm.that(result, eq="default")

    def test_to_str_list_from_list(self) -> None:
        """Test to_str_list with list input."""
        result = u.to_str_list(["a", "b", "c"])
        tm.that(result, eq=["a", "b", "c"])

    def test_to_str_list_from_single(self) -> None:
        """Test to_str_list with single value."""
        result = u.to_str_list("single")
        tm.that(result, eq=["single"])

    def test_to_str_list_from_none(self) -> None:
        """Test to_str_list with None."""
        result = u.to_str_list(None)
        tm.that(result, eq=[])

    def test_norm_str_lowercase(self) -> None:
        """Test norm_str with lowercase."""
        result = u.Ldap.norm_str("TEST", case="lower")
        tm.that(result, eq="test")

    def test_norm_str_uppercase(self) -> None:
        """Test norm_str with uppercase."""
        result = u.Ldap.norm_str("test", case="upper")
        tm.that(result, eq="TEST")

    def test_norm_join(self) -> None:
        """Test norm_join with list."""
        result = u.Ldap.norm_join(["A", "B", "C"], case="lower")
        tm.that(result, eq="a b c")

    def test_filter_truthy(self) -> None:
        """Test filter_truthy removes falsy values."""
        result = u.Ldap.filter_truthy({"a": "value", "b": "", "c": None, "d": "value2"})
        tm.that(result, keys=["a", "d"], lacks_keys=["b", "c"])

    def test_map_str(self) -> None:
        """Test map_str converts list values to strings."""
        result = u.Ldap.map_str(["a", "b", "c"], case="upper")
        tm.that(result, eq=["A", "B", "C"])

    def test_find_callable_with_mapping(self) -> None:
        """Test find_callable with Mapping (covariant pattern)."""
        handlers: Mapping[str, Callable[[], core_t_flex.FlexibleValue]] = {
            "handler1": lambda: "value1",
            "handler2": lambda: False,
        }
        # find_callable returns key of first truthy callable result
        result = u.Ldap.find_callable(handlers)
        tm.that(result, eq="handler1")

    def test_find_callable_not_found(self) -> None:
        """Test find_callable when no handler returns truthy."""
        handlers: Mapping[str, Callable[[], core_t_flex.FlexibleValue]] = {
            "handler1": lambda: False,
            "handler2": lambda: None,
            "handler3": lambda: "",
        }
        # All handlers return falsy values
        result = u.Ldap.find_callable(handlers)
        tm.that(result, none=True)

    def test_dn_str_with_string(self) -> None:
        """Test dn_str with string DN."""
        result = u.Ldap.dn_str("cn=test,dc=example,dc=com")
        tm.that(result, eq="cn=test,dc=example,dc=com")

    def test_dn_str_with_none(self) -> None:
        """Test dn_str with None."""
        result = u.Ldap.dn_str(None)
        tm.that(result, eq="unknown")

    def test_dn_str_with_custom_default(self) -> None:
        """Test dn_str with custom default."""
        result = u.Ldap.dn_str(None, default="default")
        tm.that(result, eq="default")
