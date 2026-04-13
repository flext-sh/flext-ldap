"""Unit tests for flext_ldap.services.detection.FlextLdapServerDetector.

**Modules Tested:**
- `flext_ldap.services.detection.FlextLdapServerDetector` - LDAP server type detection

**Test Scope:**
- Server detection from attributes (static methods)
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

from collections.abc import Mapping

import pytest

from flext_ldap import FlextLdapServerDetector
from tests import c, t, u

pytestmark = pytest.mark.unit


class TestsFlextLdapDetection:
    """Comprehensive tests for FlextLdapServerDetector using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, p, d, x from flext-core.

    Parametrized tests and factory methods for maximum code reuse (DRY).
    All helper logic nested within this single class following FLEXT patterns.
    Expected reduction: 217 lines → 95 lines (56% reduction).
    """

    def test_detector_initialization(self) -> None:
        """Test detector initialization."""
        detector = FlextLdapServerDetector()
        assert detector is not None
        assert isinstance(detector, FlextLdapServerDetector)

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
    def test_get_first_value(
        self,
        attrs: Mapping[str, t.StrSequence],
        key: str,
        expected: str | None,
    ) -> None:
        """Test _get_first_value with various attribute scenarios."""
        attrs_dict: Mapping[str, t.StrSequence] = dict(attrs)
        value = FlextLdapServerDetector._get_first_value(attrs_dict, key)
        assert value == expected

    @pytest.mark.parametrize(
        ("vendor_name", "vendor_version", "supported_controls", "expected"),
        c.Ldap.Tests.DETECTION_FROM_ATTRIBUTES_SCENARIOS,
    )
    def test_detect_from_attributes(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        supported_controls: t.StrSequence,
        expected: str,
    ) -> None:
        """Test _detect_from_attributes with various server types and variants."""
        result = FlextLdapServerDetector._detect_from_attributes(
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts=[c.Ldap.Defaults.EXAMPLE_BASE_DN],
            _supported_controls=supported_controls,
            supported_extensions=[],
        )
        u.Ldap.Tests.ok(result, eq=expected)
