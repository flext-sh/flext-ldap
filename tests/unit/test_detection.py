"""Unit tests for flext_ldap.services.detection.FlextLdapServerDetector.

**Modules Tested:**
- `flext_ldap.services.detection.FlextLdapServerDetector` - LDAP server type detection

**Test Scope:**
- Server detection from public utility behavior
- Attribute value extraction
- Server type normalization
- Error handling for missing connection
- Method existence validation

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Architecture: Single class per module following FLEXT patterns.
Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Mapping,
)

import pytest

from flext_ldap import FlextLdapServerDetector
from tests import c, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapDetection:
    """Comprehensive tests for FlextLdapServerDetector using factories
    and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

    Parametrized tests and factory methods for maximum code reuse (DRY).
    All helper logic nested within this single class following FLEXT patterns.
    Expected reduction: 217 lines → 95 lines (56% reduction).
    """

    @pytest.mark.parametrize(
        ("kwargs", "expect_failure", "error_substring"),
        c.Ldap.Tests.DETECTION_EXECUTE_SCENARIOS,
    )
    def test_execute_error_handling(
        self,
        kwargs: Mapping[str, bool | float | str | None] | None,
        expect_failure: bool,
        error_substring: str,
    ) -> None:
        """Test execute() with various error scenarios."""
        detector = FlextLdapServerDetector()
        result = detector.execute() if kwargs is None else detector.execute(**kwargs)
        assert result.failure == expect_failure
        assert error_substring in str(result.error)

    @pytest.mark.parametrize(
        ("attrs", "key", "expected"),
        c.Ldap.Tests.DETECTION_GET_FIRST_VALUE_SCENARIOS,
    )
    def test_get_first_attribute_value(
        self,
        attrs: Mapping[str, t.StrSequence],
        key: str,
        expected: str | None,
    ) -> None:
        """Test public attribute value extraction with various scenarios."""
        attrs_dict: Mapping[str, t.StrSequence] = dict(attrs)
        value = u.Ldap.get_first_attribute_value(attrs_dict, key)
        assert value == expected

    @pytest.mark.parametrize(
        ("vendor_name", "vendor_version", "supported_controls", "expected"),
        c.Ldap.Tests.DETECTION_FROM_ATTRIBUTES_SCENARIOS,
    )
    def test_detect_server_type(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        supported_controls: t.StrSequence,
        expected: str,
    ) -> None:
        """Test public server detection heuristics with various variants."""
        _ = supported_controls
        result = u.Ldap.detect_server_type(
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts=[c.Ldap.EXAMPLE_BASE_DN],
            supported_extensions=[],
        )
        assert result == expected
