"""Unit tests for flext-ldap schema module.

This module provides comprehensive test coverage for the flext-ldap schema functionality,
following FLEXT standards with real functionality testing and no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.models import FlextLdapModels
from flext_ldap.schema import FlextLdapSchema

from flext_core import FlextResult


class TestFlextLdapSchema:
    """Comprehensive tests for FlextLdapSchema class."""

    def test_schema_initialization(self) -> None:
        """Test schema initialization."""
        # FlextLdapSchema is abstract, test the concrete classes instead
        detector = FlextLdapSchema.GenericQuirksDetector()
        assert detector is not None

    def test_quirks_detector_initialization(self) -> None:
        """Test quirks detector initialization."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        assert detector is not None

    def test_quirks_detector_handle_empty_message(self) -> None:
        """Test quirks detector with empty message."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.handle(None)

        assert isinstance(result, FlextResult)
        assert not result.is_success
        assert result.error is not None
        assert (
            result.error and result.error and "Message cannot be empty" in result.error
        )

    def test_quirks_detector_handle_valid_message(self) -> None:
        """Test quirks detector with valid message."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.handle({"server": "test"})

        assert isinstance(result, FlextResult)
        assert result.is_success
        assert result.data is not None

    def test_detect_server_type_none(self) -> None:
        """Test server type detection with None input."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.detect_server_type(None)
        assert result is None

    def test_detect_server_type_valid(self) -> None:
        """Test server type detection with valid input - returns enum."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.detect_server_type({"server": "test"})
        assert result == FlextLdapModels.LdapServerType.GENERIC

    def test_get_server_quirks_none(self) -> None:
        """Test getting server quirks with None server type."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.get_server_quirks(None)
        assert result is None

    def test_get_server_quirks_valid(self) -> None:
        """Test getting server quirks with valid server type."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.get_server_quirks("GENERIC")

        assert result is not None
        assert hasattr(result, "server_type")
        assert hasattr(result, "case_sensitive_dns")
        assert hasattr(result, "case_sensitive_attributes")
        assert hasattr(result, "supports_paged_results")
        assert hasattr(result, "supports_vlv")
        assert hasattr(result, "supports_sync")
        assert hasattr(result, "max_page_size")
        assert hasattr(result, "default_timeout")
        assert hasattr(result, "supports_start_tls")
        assert hasattr(result, "requires_explicit_bind")

    def test_discovery_initialization(self) -> None:
        """Test discovery initialization."""
        # Discovery is abstract, test that it exists
        assert hasattr(FlextLdapSchema, "Discovery")
        assert FlextLdapSchema.Discovery is not None
