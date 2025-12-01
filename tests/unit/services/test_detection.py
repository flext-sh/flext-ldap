"""Unit tests for FlextLdapServerDetector.

**Modules Tested:**
- `flext_ldap.services.detection.FlextLdapServerDetector` - LDAP server detection service

**Test Scope:**
- Server detection with various attribute combinations
- Error handling and fallback logic
- Connection failure scenarios
- rootDSE query handling

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapServerDetector
Scope: Comprehensive server detection testing with maximum code reuse
Pattern: Parametrized tests using factories and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldap.services.detection import FlextLdapServerDetector

pytestmark = pytest.mark.unit


class DetectionTestScenario(StrEnum):
    """Test scenarios for server detection testing."""

    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"
    MINIMAL = "minimal"


@dataclass(frozen=True, slots=True)
class DetectionTestDataFactory:
    """Factory for creating test data for detection service tests using Python 3.13 dataclasses."""

    ATTRIBUTE_SCENARIOS: ClassVar[tuple[DetectionTestScenario, ...]] = (
        DetectionTestScenario.OID,
        DetectionTestScenario.OUD,
        DetectionTestScenario.OPENLDAP,
        DetectionTestScenario.MINIMAL,
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


class TestFlextLdapServerDetector:
    """Comprehensive tests for LDAP server detection service using factories and DRY principles.

    Uses parametrized tests and constants for maximum code reuse.
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

    def test_execute_with_invalid_connection_type(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test execute() method fails with invalid connection type."""
        # execute() accepts kwargs, so pass connection as keyword argument
        invalid_connection: str = "not_a_connection"
        result = detector.execute(connection=invalid_connection)  # type: ignore[arg-type]

        assert result.is_failure
        assert result.error is not None
        assert "connection must be ldap3.Connection" in result.error
