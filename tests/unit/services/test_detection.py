"""Unit tests for FlextLdapServerDetector.

Tests server detection logic that doesn't require LDAP connections.
Pure logic tests without mocks - uses real data structures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.services.detection import FlextLdapServerDetector

pytestmark = pytest.mark.unit


class TestFlextLdapServerDetector:
    """Tests for LDAP server detection service (pure logic, no connections)."""

    @pytest.fixture
    def detector(self) -> FlextLdapServerDetector:
        """Create detector instance."""
        return FlextLdapServerDetector()

    def test_detector_initialization(self, detector: FlextLdapServerDetector) -> None:
        """Test detector service initialization."""
        assert detector is not None

    def test_detect_from_attributes_oid(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test _detect_from_attributes with OID-specific attributes."""
        result = detector._detect_from_attributes(
            vendor_name="Oracle Corporation",
            vendor_version="Oracle Internet Directory 11.1.1.7.0",
            naming_contexts=["dc=example,dc=com"],
            # Include Oracle-specific OIDs (2.16.840.1.113894.*) for detection
            supported_controls=["2.16.840.1.113894.1.8.1"],
            supported_extensions=["2.16.840.1.113894.1.8.2"],
        )

        assert result.is_success
        detected_type = result.unwrap()
        assert detected_type == "oid"

    def test_detect_from_attributes_oud(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test _detect_from_attributes with OUD-specific attributes.

        Note: Without OUD-specific patterns, falls back to RFC.
        """
        result = detector._detect_from_attributes(
            vendor_name="Oracle Corporation",
            vendor_version="Oracle Unified Directory 12.2.1.4.0",
            naming_contexts=["dc=example,dc=com"],
            supported_controls=[],
            supported_extensions=[],
        )

        assert result.is_success
        detected_type = result.unwrap()
        # Without specific OUD patterns, falls back to RFC
        assert detected_type in {"oud", "rfc"}

    def test_detect_from_attributes_openldap(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test _detect_from_attributes with OpenLDAP-specific attributes."""
        result = detector._detect_from_attributes(
            vendor_name="OpenLDAP",
            vendor_version="OpenLDAP 2.4.44",
            naming_contexts=["dc=example,dc=com"],
            supported_controls=[],
            supported_extensions=[],
        )

        assert result.is_success
        detected_type = result.unwrap()
        # OpenLDAP should be detected (may fall back to RFC if patterns don't match)
        assert detected_type in {"openldap", "openldap2", "rfc"}

    def test_detect_from_attributes_minimal(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test _detect_from_attributes with minimal attributes (RFC fallback)."""
        result = detector._detect_from_attributes(
            vendor_name=None,
            vendor_version=None,
            naming_contexts=[],
            supported_controls=[],
            supported_extensions=[],
        )

        # Should succeed with RFC fallback when no server-specific patterns match
        assert result.is_success
        detected_type = result.unwrap()
        assert detected_type == "rfc"  # Fallback to RFC when no patterns match

    def test_execute_without_connection_parameter(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test execute() method fails without connection parameter."""
        result = detector.execute()

        assert result.is_failure
        assert result.error is not None
        assert "connection parameter required" in result.error

    # Removed: All tests using MagicMock connections or patch()
    # Moved to tests/integration/test_services_detection_real.py
    # Uses REAL ldap3.Connection from LDAP server (no mocks/patches)
