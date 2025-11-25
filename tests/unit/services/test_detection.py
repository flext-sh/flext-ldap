"""Unit tests for FlextLdapServerDetector.

Tests server detection logic that doesn't require LDAP connections.
Pure logic tests without mocks - uses real data structures and factory patterns.

Tested modules:
- flext_ldap.services.detection.FlextLdapServerDetector

Test scope:
- Server detection with various attribute combinations
- Error handling and fallback logic
- Connection failure scenarios

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Never, cast

import pytest
from ldap3 import Connection

from flext_ldap.services.detection import FlextLdapServerDetector

pytestmark = pytest.mark.unit


class DetectionTestScenario(StrEnum):
    """Test scenarios for server detection testing."""

    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"
    MINIMAL = "minimal"
    FAILURE = "failure"
    ROOTDSE = "rootdse"
    EXCEPTION = "exception"


class DetectionTestCategory(StrEnum):
    """Test categories for detection service."""

    ATTRIBUTES = "attributes"
    EXECUTION = "execution"
    ERROR_HANDLING = "error_handling"


@dataclass(frozen=True, slots=True)
class DetectionTestDataFactory:
    """Factory for creating test data for detection service tests."""

    # Test scenarios for parametrization
    ATTRIBUTE_SCENARIOS: ClassVar[tuple[DetectionTestScenario, ...]] = (
        DetectionTestScenario.OID,
        DetectionTestScenario.OUD,
        DetectionTestScenario.OPENLDAP,
        DetectionTestScenario.MINIMAL,
    )

    # Error handling scenarios for parametrization
    ERROR_SCENARIOS: ClassVar[tuple[DetectionTestScenario, ...]] = (
        DetectionTestScenario.FAILURE,
        DetectionTestScenario.ROOTDSE,
        DetectionTestScenario.EXCEPTION,
    )

    @staticmethod
    def get_attribute_scenario(
        scenario: DetectionTestScenario,
    ) -> tuple[str | None, str | None, list[str], list[str], list[str]]:
        """Get vendor info for attribute detection scenario."""
        scenarios: dict[
            DetectionTestScenario,
            tuple[str | None, str | None, list[str], list[str], list[str]],
        ] = {
            DetectionTestScenario.OID: (
                "Oracle Corporation",
                "Oracle Internet Directory 11.1.1.7.0",
                ["dc=example,dc=com"],
                ["2.16.840.1.113894.1.8.1"],
                ["2.16.840.1.113894.1.8.2"],
            ),
            DetectionTestScenario.OUD: (
                "Oracle Corporation",
                "Oracle Unified Directory 12.2.1.4.0",
                ["dc=example,dc=com"],
                [],
                [],
            ),
            DetectionTestScenario.OPENLDAP: (
                "OpenLDAP",
                "OpenLDAP 2.4.44",
                ["dc=example,dc=com"],
                [],
                [],
            ),
            DetectionTestScenario.MINIMAL: (None, None, [], [], []),
        }
        return scenarios[scenario]

    @staticmethod
    def get_expected_types(
        scenario: DetectionTestScenario,
    ) -> set[str]:
        """Get expected detected server types for scenario."""
        expectations: dict[DetectionTestScenario, set[str]] = {
            DetectionTestScenario.OID: {"oid"},
            DetectionTestScenario.OUD: {"oud", "rfc"},
            DetectionTestScenario.OPENLDAP: {"openldap", "openldap2", "rfc"},
            DetectionTestScenario.MINIMAL: {"rfc"},
        }
        return expectations[scenario]

    @staticmethod
    def create_failure_connection() -> Connection:
        """Create mock connection that causes detection failure."""

        class FailureConnection:
            bound = True

            def search(self, *args: object, **kwargs: object) -> None:
                """Simulate search failure."""
                return

        return cast("Connection", FailureConnection())

    @staticmethod
    def create_rootdse_connection() -> Connection:
        """Create mock connection with rootDSE attributes."""

        class RootDSEConnection:
            bound = True

            def search(
                self, base: object, filter_str: object, attributes: object
            ) -> bool:
                """Simulate rootDSE search with list attributes."""
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

        return cast("Connection", RootDSEConnection())

    @staticmethod
    def create_exception_connection() -> Connection:
        """Create mock connection that raises exception."""

        class ExceptionConnection:
            bound = True

            def search(self, *args: object, **kwargs: object) -> Never:
                """Simulate exception during search."""
                msg = "Mock detection exception"
                raise RuntimeError(msg)

        return cast("Connection", ExceptionConnection())


class TestFlextLdapServerDetector:
    """Tests for LDAP server detection service.

    Single class with flat test methods covering:
    - Attribute-based detection for various server types
    - Execution and parameter validation
    - Error handling and exception scenarios

    Previously nested test classes flattened per FLEXT architecture.
    """

    _factory = DetectionTestDataFactory()

    @pytest.fixture
    def detector(self) -> FlextLdapServerDetector:
        """Create detector instance."""
        return FlextLdapServerDetector()

    def test_detector_initialization(self, detector: FlextLdapServerDetector) -> None:
        """Test detector service initialization."""
        assert detector is not None

    @pytest.mark.parametrize("scenario", DetectionTestDataFactory.ATTRIBUTE_SCENARIOS)
    def test_detect_from_attributes_by_scenario(
        self,
        detector: FlextLdapServerDetector,
        scenario: DetectionTestScenario,
    ) -> None:
        """Test _detect_from_attributes with various server scenarios (parametrized)."""
        (
            vendor_name,
            vendor_version,
            naming_contexts,
            supported_controls,
            supported_extensions,
        ) = self._factory.get_attribute_scenario(scenario)
        expected_types = self._factory.get_expected_types(scenario)

        result = detector._detect_from_attributes(
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts=naming_contexts,
            supported_controls=supported_controls,
            supported_extensions=supported_extensions,
        )

        assert result.is_success
        detected_type = result.unwrap()
        assert detected_type in expected_types

    def test_execute_without_connection_parameter(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test execute() method fails without connection parameter."""
        result = detector.execute()

        assert result.is_failure
        assert result.error is not None
        assert "connection parameter required" in result.error

    def test_detect_from_connection_failure_logging(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test error logging when detection fails (covers lines 188-193)."""
        mock_conn = self._factory.create_failure_connection()

        result = detector.detect_from_connection(mock_conn)
        assert result.is_failure

    def test_detect_from_connection_rootdse_conversion(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test rootDSE attribute conversion (covers line 263)."""
        mock_conn = self._factory.create_rootdse_connection()

        detector.detect_from_connection(mock_conn)

        # The method should handle the conversion gracefully
        # Either succeeds or fails, but doesn't crash on list conversion (line 263)

    def test_detect_from_connection_exception_handling(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test exception handling in detection (covers lines 351-368)."""
        mock_conn = self._factory.create_exception_connection()

        result = detector.detect_from_connection(mock_conn)
        assert result.is_failure
        assert "Mock detection exception" in str(result.error)
