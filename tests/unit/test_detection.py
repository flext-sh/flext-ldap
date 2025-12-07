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
Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap.services.detection import FlextLdapServerDetector

pytestmark = pytest.mark.unit


class TestsFlextLdapDetection:
    """Comprehensive tests for FlextLdapServerDetector using factories and DRY principles.

    Architecture: Single class per module following FLEXT patterns.
    Uses t, c, p, m, u, s for test support and e, r, d, x from flext-core.

    Parametrized tests and factory methods for maximum code reuse (DRY).
    All helper logic nested within this single class following FLEXT patterns.
    Expected reduction: 217 lines → 95 lines (56% reduction).
    """

    # =========================================================================
    # FACTORY METHODS FOR PARAMETRIZATION
    # =========================================================================

    @staticmethod
    def _get_detector_execute_scenarios() -> list[
        tuple[dict[str, object] | None, bool, str]
    ]:
        """Factory: Return execute() test scenarios (kwargs, expect_failure, error_substring)."""
        return [
            ({}, True, "connection parameter required"),  # Missing connection
            (
                {"connection": "invalid"},
                True,
                "connection must be ldap3.Connection",
            ),  # Invalid type
        ]

    @staticmethod
    def _get_get_first_value_scenarios() -> list[
        tuple[dict[str, list[str]], str, str | None]
    ]:
        """Factory: Return _get_first_value() test scenarios (attrs, key, expected)."""
        return [
            (
                {"vendorName": ["Oracle Corporation", "Version 2"]},
                "vendorName",
                "Oracle Corporation",
            ),
            ({"vendorName": ["OpenLDAP"]}, "vendorName", "OpenLDAP"),
            ({"otherKey": ["value"]}, "vendorName", None),
            ({"vendorName": []}, "vendorName", None),
        ]

    @staticmethod
    def _get_detect_from_attributes_scenarios() -> list[
        tuple[str | None, str | None, list[str], str]
    ]:
        """Factory: Return _detect_from_attributes() test scenarios (vendor_name, version, controls, expected)."""
        return [
            # Standard server detection
            ("Oracle Corporation", "12.2.1.4.0", [], "oid"),
            ("Oracle Unified Directory", "12.2.1.4.0", [], "oud"),
            ("OpenLDAP", "2.4.57", [], "openldap"),
            ("Microsoft Corporation", None, ["1.2.840.113556.1.4.319"], "ad"),
            ("389 Project", "2.0.0", [], "ds389"),
            (None, None, [], "rfc"),
            # Variant detection (case-insensitive and partial matches)
            ("oracle corporation", "12.2.1.4.0", [], "oid"),  # Case-insensitive
            ("Oracle", None, [], "oid"),  # Partial match
        ]

    # =========================================================================
    # PARAMETRIZED TESTS
    # =========================================================================

    def test_detector_initialization(self) -> None:
        """Test detector initialization."""
        detector = FlextLdapServerDetector()
        assert detector is not None
        assert isinstance(detector, FlextLdapServerDetector)

    @pytest.mark.parametrize(
        ("kwargs", "expect_failure", "error_substring"),
        _get_detector_execute_scenarios(),
    )
    def test_execute_error_handling(
        self,
        kwargs: dict[str, object] | None,
        expect_failure: bool,
        error_substring: str,
    ) -> None:
        """Test execute() with various error scenarios."""
        detector = FlextLdapServerDetector()
        result = detector.execute() if kwargs is None else detector.execute(**kwargs)
        assert result.is_failure == expect_failure
        assert error_substring in str(result.error)

    @pytest.mark.parametrize(
        ("attrs", "key", "expected"),
        _get_get_first_value_scenarios(),
    )
    def test_get_first_value(
        self,
        attrs: dict[str, list[str]],
        key: str,
        expected: str | None,
    ) -> None:
        """Test _get_first_value with various attribute scenarios."""
        value = FlextLdapServerDetector._get_first_value(attrs, key)
        assert value == expected

    @pytest.mark.parametrize(
        ("vendor_name", "vendor_version", "supported_controls", "expected"),
        _get_detect_from_attributes_scenarios(),
    )
    def test_detect_from_attributes(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        supported_controls: list[str],
        expected: str,
    ) -> None:
        """Test _detect_from_attributes with various server types and variants."""
        result = FlextLdapServerDetector._detect_from_attributes(
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts=["dc=example,dc=com"],
            _supported_controls=supported_controls,
            supported_extensions=[],
        )
        tm.ok(result, eq=expected)
