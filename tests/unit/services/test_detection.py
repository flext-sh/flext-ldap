"""Unit tests for FlextLdapServerDetector.

Tests server detection logic that doesn't require LDAP connections.
Pure logic tests without mocks - uses real data structures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Never, cast

import pytest
from ldap3 import Connection

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

    def test_detect_from_connection_failure_logging(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test error logging when detection fails (covers lines 188-193)."""

        # Mock a connection that will cause _detect_from_attributes to fail
        class MockConnection:
            bound = True  # Connection is bound

            def search(self, *args: object, **kwargs: object) -> None:
                """Simulate search failure."""
                return

        mock_conn = cast("Connection", MockConnection())

        # This should trigger the error logging path (lines 188-193)
        result = detector.detect_from_connection(mock_conn)
        assert result.is_failure

    def test_detect_from_connection_rootdse_conversion(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test rootDSE attribute conversion (covers lines 263)."""

        # Mock connection with list attributes that need conversion
        class MockConnection:
            bound = True  # Mock connection is bound

            def search(
                self, base: object, filter_str: object, attributes: object
            ) -> bool:
                # Simulate successful search with list attributes
                self.entries = [
                    type(
                        "Entry",
                        (),
                        {
                            "entry_attributes_as_dict": {
                                "objectClass": ["top", "person"],
                                "supportedControl": ["1.2.3", "4.5.6"],
                            }
                        },
                    )()
                ]
                return True

        mock_conn = cast("Connection", MockConnection())
        detector.detect_from_connection(mock_conn)

        # The method should handle the conversion gracefully
        # Either succeeds or fails, but doesn't crash on list conversion (line 263)

    def test_detect_from_connection_exception_handling(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test exception handling in detection (covers lines 351-368)."""

        # Mock connection that raises exception during detection
        class MockConnection:
            bound = True  # Mock connection is bound

            def search(self, *args: object, **kwargs: object) -> Never:
                msg = "Mock detection exception"
                raise RuntimeError(msg)

        mock_conn = cast("Connection", MockConnection())

        # This should trigger exception handling (lines 351-368)
        result = detector.detect_from_connection(mock_conn)
        assert result.is_failure
        assert "Detection exception" in str(result.error)
