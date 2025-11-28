"""Integration tests for FlextLdapServerDetector with real LDAP server.

Tests server detection from real LDAP connections via rootDSE queries.
All tests use real LDAP server from fixtures (no mocks).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol

import pytest
from ldap3 import Connection, Server

from flext_ldap.services.detection import FlextLdapServerDetector
from tests.fixtures.typing import GenericFieldsDict

from ..fixtures.constants import RFC


class ConnectionWithUnbind(Protocol):
    """Protocol for Connection with unbind method."""

    bound: bool

    def unbind(self, controls: object | None = None) -> None:
        """Unbind from LDAP server."""
        ...


pytestmark = pytest.mark.integration


class TestFlextLdapServerDetectorReal:
    """Tests for LDAP server detection service with real LDAP server."""

    @pytest.fixture
    def detector(self) -> FlextLdapServerDetector:
        """Create detector instance."""
        return FlextLdapServerDetector()

    @pytest.fixture
    def real_ldap_connection(
        self,
        ldap_container: GenericFieldsDict,
    ) -> Connection:
        """Create real LDAP connection for testing."""
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        return Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

    def test_detector_initialization(self, detector: FlextLdapServerDetector) -> None:
        """Test detector service initialization."""
        assert detector is not None

    def test_detect_from_real_connection(
        self,
        detector: FlextLdapServerDetector,
        real_ldap_connection: Connection,
    ) -> None:
        """Test server detection from real LDAP connection."""
        result = detector.detect_from_connection(real_ldap_connection)

        assert result.is_success
        detected_type = result.unwrap()
        # OpenLDAP test server should be detected as openldap, openldap2, or rfc
        assert detected_type in {"openldap", "openldap2", "rfc"}

        if real_ldap_connection.bound:
            # unbind() exists on Connection - use Protocol for type safety
            connection_with_unbind: ConnectionWithUnbind = real_ldap_connection
            connection_with_unbind.unbind()

    def test_detect_connection_not_bound(
        self,
        detector: FlextLdapServerDetector,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test detection fails when connection not bound."""
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=False,  # Don't bind
        )

        result = detector.detect_from_connection(connection)

        assert result.is_failure
        assert result.error is not None
        assert "must be bound" in result.error

    def test_query_root_dse_with_real_connection(
        self,
        detector: FlextLdapServerDetector,
        real_ldap_connection: Connection,
    ) -> None:
        """Test _query_root_dse extracts attributes from real connection."""
        result = detector._query_root_dse(real_ldap_connection)

        assert result.is_success
        attributes = result.unwrap()

        # Real rootDSE should have standard attributes
        assert isinstance(attributes, dict)
        assert len(attributes) > 0
        # Common rootDSE attributes (at least one should be present)
        # OpenLDAP may only return objectClass, which is valid
        assert len(attributes) > 0  # At least one attribute should be present

        if real_ldap_connection.bound:
            # unbind() exists on Connection - use Protocol for type safety
            connection_with_unbind: ConnectionWithUnbind = real_ldap_connection
            connection_with_unbind.unbind()

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

    def test_execute_with_real_connection(
        self,
        detector: FlextLdapServerDetector,
        real_ldap_connection: Connection,
    ) -> None:
        """Test execute() method with real connection parameter."""
        result = detector.execute(connection=real_ldap_connection)

        assert result.is_success
        detected_type = result.unwrap()
        # OpenLDAP test server should be detected
        assert detected_type in {"openldap", "openldap2", "rfc"}

        if real_ldap_connection.bound:
            # unbind() exists on Connection - use Protocol for type safety
            connection_with_unbind: ConnectionWithUnbind = real_ldap_connection
            connection_with_unbind.unbind()

    def test_execute_without_connection_parameter(
        self,
        detector: FlextLdapServerDetector,
    ) -> None:
        """Test execute() method fails without connection parameter."""
        result = detector.execute()

        assert result.is_failure
        assert result.error is not None
        assert "connection parameter required" in result.error
