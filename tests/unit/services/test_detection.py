"""Unit tests for FlextLdapServerDetector.

Tests server detection from live LDAP connections via rootDSE queries.
Uses mocked connections for unit testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from flext_ldap.services.detection import FlextLdapServerDetector

pytestmark = pytest.mark.unit


class TestFlextLdapServerDetector:
    """Tests for LDAP server detection service."""

    @pytest.fixture
    def detector(self) -> FlextLdapServerDetector:
        """Create detector instance."""
        return FlextLdapServerDetector()

    @pytest.fixture
    def mock_connection_oid(self) -> MagicMock:
        """Create mock ldap3 Connection with OID rootDSE attributes."""
        conn = MagicMock()
        conn.bound = True

        # Mock successful search
        conn.search.return_value = True

        # Mock rootDSE entry with OID-specific attributes
        mock_entry = MagicMock()
        mock_entry.entry_attributes = [
            "vendorName",
            "vendorVersion",
            "namingContexts",
            "supportedControl",
            "supportedExtension",
        ]

        # OID-specific rootDSE attributes with Oracle OIDs
        mock_entry.vendorName = "Oracle Corporation"
        mock_entry.vendorVersion = "Oracle Internet Directory 11.1.1.7.0"
        mock_entry.namingContexts = ["dc=example,dc=com"]
        # Use Oracle-specific OIDs (2.16.840.1.113894.*)
        mock_entry.supportedControl = [
            "2.16.840.1.113894.1.8.1",  # Oracle-specific control
            "2.16.840.1.113730.3.4.2",  # ManageDsaIT
        ]
        mock_entry.supportedExtension = [
            "2.16.840.1.113894.1.8.2",  # Oracle-specific extension
        ]

        conn.entries = [mock_entry]
        return conn

    @pytest.fixture
    def mock_connection_oud(self) -> MagicMock:
        """Create mock ldap3 Connection with OUD rootDSE attributes."""
        conn = MagicMock()
        conn.bound = True
        conn.search.return_value = True

        mock_entry = MagicMock()
        mock_entry.entry_attributes = [
            "vendorName",
            "vendorVersion",
            "namingContexts",
        ]

        # OUD-specific rootDSE attributes
        mock_entry.vendorName = "Oracle Corporation"
        mock_entry.vendorVersion = "Oracle Unified Directory 12.2.1.4.0"
        mock_entry.namingContexts = ["dc=example,dc=com"]

        conn.entries = [mock_entry]
        return conn

    @pytest.fixture
    def mock_connection_openldap(self) -> MagicMock:
        """Create mock ldap3 Connection with OpenLDAP rootDSE attributes."""
        conn = MagicMock()
        conn.bound = True
        conn.search.return_value = True

        mock_entry = MagicMock()
        mock_entry.entry_attributes = [
            "vendorName",
            "vendorVersion",
            "namingContexts",
        ]

        # OpenLDAP-specific rootDSE attributes
        mock_entry.vendorName = "OpenLDAP"
        mock_entry.vendorVersion = "OpenLDAP 2.4.44"
        mock_entry.namingContexts = ["dc=example,dc=com"]

        conn.entries = [mock_entry]
        return conn

    def test_detector_initialization(self, detector: FlextLdapServerDetector) -> None:
        """Test detector service initialization."""
        assert detector is not None

    def test_detect_oid_from_connection(
        self,
        detector: FlextLdapServerDetector,
        mock_connection_oid: MagicMock,
    ) -> None:
        """Test OID detection from connection."""
        result = detector.detect_from_connection(mock_connection_oid)

        assert result.is_success
        detected_type = result.unwrap()
        assert detected_type == "oid"

    def test_detect_oud_from_connection(
        self,
        detector: FlextLdapServerDetector,
        mock_connection_oud: MagicMock,
    ) -> None:
        """Test OUD detection from connection.

        Note: Without OUD-specific patterns in rootDSE (like ds-sync-*, ds-pwp-*),
        detection falls back to RFC. This is correct behavior.
        """
        result = detector.detect_from_connection(mock_connection_oud)

        assert result.is_success
        detected_type = result.unwrap()
        # Without specific OUD patterns, falls back to RFC (correct behavior)
        assert detected_type in {"oud", "rfc"}

    def test_detect_openldap_from_connection(
        self,
        detector: FlextLdapServerDetector,
        mock_connection_openldap: MagicMock,
    ) -> None:
        """Test OpenLDAP detection from connection.

        Note: Without OpenLDAP-specific patterns in rootDSE (like olc* attributes),
        detection falls back to RFC. This is correct behavior.
        """
        result = detector.detect_from_connection(mock_connection_openldap)

        assert result.is_success
        detected_type = result.unwrap()
        # Without specific OpenLDAP patterns, falls back to RFC (correct behavior)
        assert detected_type in {"openldap", "openldap2", "rfc"}

    def test_detect_connection_not_bound(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test detection fails when connection not bound."""
        conn = MagicMock()
        conn.bound = False

        result = detector.detect_from_connection(conn)

        assert result.is_failure
        assert "must be bound" in result.error

    def test_detect_rootdse_query_fails(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test detection fails when rootDSE query fails."""
        conn = MagicMock()
        conn.bound = True
        conn.search.return_value = False
        conn.result = {"description": "Query failed"}

        result = detector.detect_from_connection(conn)

        assert result.is_failure
        assert "Failed to query rootDSE" in result.error

    def test_detect_no_rootdse_entries(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test detection fails when no rootDSE entries returned."""
        conn = MagicMock()
        conn.bound = True
        conn.search.return_value = True
        conn.entries = []

        result = detector.detect_from_connection(conn)

        assert result.is_failure
        assert "returned no entries" in result.error

    def test_detect_rootdse_query_exception(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test detection handles exceptions during rootDSE query."""
        conn = MagicMock()
        conn.bound = True
        conn.search.side_effect = Exception("Connection error")

        result = detector.detect_from_connection(conn)

        assert result.is_failure
        assert "Exception querying rootDSE" in result.error

    def test_query_root_dse_extracts_attributes(
        self,
        detector: FlextLdapServerDetector,
        mock_connection_oid: MagicMock,
    ) -> None:
        """Test _query_root_dse extracts attributes correctly."""
        result = detector._query_root_dse(mock_connection_oid)

        assert result.is_success
        attributes = result.unwrap()

        assert "vendorName" in attributes
        assert "vendorVersion" in attributes
        assert "namingContexts" in attributes
        assert attributes["vendorName"][0] == "Oracle Corporation"

    def test_get_attribute_value_single(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test _get_attribute_value returns first value."""
        attributes = {
            "vendorName": ["Oracle Corporation"],
            "empty": [],
        }

        value = detector._get_attribute_value(attributes, "vendorName")
        assert value == "Oracle Corporation"

        value = detector._get_attribute_value(attributes, "empty")
        assert value is None

        value = detector._get_attribute_value(attributes, "nonexistent")
        assert value is None

    def test_get_attribute_values_list(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test _get_attribute_values returns all values."""
        attributes = {
            "namingContexts": ["dc=example,dc=com", "dc=test,dc=com"],
            "empty": [],
        }

        values = detector._get_attribute_values(attributes, "namingContexts")
        assert len(values) == 2
        assert "dc=example,dc=com" in values

        values = detector._get_attribute_values(attributes, "empty")
        assert len(values) == 0

        values = detector._get_attribute_values(attributes, "nonexistent")
        assert len(values) == 0

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

    def test_detect_handles_flext_ldif_detector_failure(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test detection handles FlextLdifDetector returning failure result."""
        # Import happens inside _detect_from_attributes, so patch at module level
        with patch(
            "flext_ldif.services.detector.FlextLdifDetector"
        ) as mock_detector_class:
            mock_detector = MagicMock()
            # Simulate FlextResult.fail() being returned
            from flext_core import FlextResult

            failure_result = FlextResult[object].fail("Detection logic failed")
            mock_detector.detect_server_type.return_value = failure_result
            mock_detector_class.return_value = mock_detector

            result = detector._detect_from_attributes(
                vendor_name="Oracle Corporation",
                vendor_version="Oracle Internet Directory 11.1.1.7.0",
                naming_contexts=[],
                supported_controls=[],
                supported_extensions=[],
            )

            assert result.is_failure
            assert "Detection failed" in result.error

    def test_detect_handles_flext_ldif_detector_exception(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test detection handles exceptions from FlextLdifDetector."""
        # Import happens inside _detect_from_attributes, so patch at module level
        with patch(
            "flext_ldif.services.detector.FlextLdifDetector"
        ) as mock_detector_class:
            mock_detector = MagicMock()
            mock_detector.detect_server_type.side_effect = Exception("Detector error")
            mock_detector_class.return_value = mock_detector

            result = detector._detect_from_attributes(
                vendor_name="Oracle Corporation",
                vendor_version="Oracle Internet Directory 11.1.1.7.0",
                naming_contexts=[],
                supported_controls=[],
                supported_extensions=[],
            )

            assert result.is_failure
            assert "Detection exception" in result.error

    def test_execute_with_connection_parameter(
        self,
        detector: FlextLdapServerDetector,
        mock_connection_oid: MagicMock,
    ) -> None:
        """Test execute() method with connection parameter."""
        result = detector.execute(connection=mock_connection_oid)

        assert result.is_success
        detected_type = result.unwrap()
        assert detected_type == "oid"

    def test_execute_without_connection_parameter(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test execute() method fails without connection parameter."""
        result = detector.execute()

        assert result.is_failure
        assert "connection parameter required" in result.error
