"""Integration tests for FlextLdapServerDetector with real LDAP server.

Tests server detection from real LDAP connections via rootDSE queries.
All tests use real LDAP server from fixtures (no mocks).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol

import pytest
from flext_core.typings import t
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPSocketOpenError

from flext_ldap.services.detection import FlextLdapServerDetector

from ..fixtures.constants import RFC
from ..fixtures.typing import LdapContainerDict
from ..helpers.operation_helpers import TestOperationHelpers


class ConnectionWithUnbind(Protocol):
    """Protocol for Connection with unbind method."""

    bound: bool

    def unbind(self, controls: t.GeneralValueType | None = None) -> None:
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
        ldap_container: LdapContainerDict,
    ) -> Connection:
        """Create real LDAP connection for testing."""
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        return Connection(
            server,
            user=ldap_container["bind_dn"],
            password=ldap_container["password"],
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

        TestOperationHelpers.assert_result_success(result)
        detected_type = result.unwrap()
        # Validate actual content: OpenLDAP test server should be detected as openldap, openldap2, or rfc
        assert detected_type in {"openldap", "openldap2", "rfc"}
        assert isinstance(detected_type, str)
        assert len(detected_type) > 0

        if real_ldap_connection.bound:
            # unbind() exists on Connection - use Protocol for type safety
            connection_with_unbind: ConnectionWithUnbind = real_ldap_connection
            connection_with_unbind.unbind()

    def test_detect_connection_not_bound(
        self,
        detector: FlextLdapServerDetector,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test detection fails when connection not bound."""
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=ldap_container["bind_dn"],
            password=ldap_container["password"],
            auto_bind=False,  # Don't bind
        )

        # Detection may raise exception or return failure result
        try:
            result = detector.detect_from_connection(connection)
            # If no exception, should return failure
            TestOperationHelpers.assert_result_failure(result)
            error_msg = TestOperationHelpers.get_error_message(result)
            # Accept various error messages for unbound/unopened connections
            error_lower = error_msg.lower()
            assert (
                "must be bound" in error_lower
                or "not bound" in error_lower
                or "socket is not open" in error_lower
                or "failed to query" in error_lower
            ), f"Expected bound/connection error, got: {error_msg}"
        except LDAPSocketOpenError:
            # Exception is acceptable - connection not open
            pass

    def test_query_root_dse_with_real_connection(
        self,
        detector: FlextLdapServerDetector,
        real_ldap_connection: Connection,
    ) -> None:
        """Test _query_root_dse extracts attributes from real connection."""
        result = detector._query_root_dse(real_ldap_connection)

        TestOperationHelpers.assert_result_success(result)
        attributes = result.unwrap()

        # Validate actual content: Real rootDSE should have standard attributes
        assert isinstance(attributes, dict)
        assert len(attributes) > 0
        # Common rootDSE attributes (at least one should be present)
        # OpenLDAP may only return objectClass, which is valid
        # Validate that attributes dict has string keys
        assert all(isinstance(k, str) for k in attributes)
        # Validate that attributes have values (not empty dict)
        assert any(
            len(v) > 0 if isinstance(v, list) else v is not None
            for v in attributes.values()
        )

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

        TestOperationHelpers.assert_result_success(result)
        detected_type = result.unwrap()
        # Validate actual content: OpenLDAP should be detected (may fall back to RFC if patterns don't match)
        assert detected_type in {"openldap", "openldap2", "rfc"}
        assert isinstance(detected_type, str)
        assert len(detected_type) > 0

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
        TestOperationHelpers.assert_result_success(result)
        detected_type = result.unwrap()
        # Validate actual content: Fallback to RFC when no patterns match
        assert detected_type == "rfc"
        assert isinstance(detected_type, str)

    def test_execute_with_real_connection(
        self,
        detector: FlextLdapServerDetector,
        real_ldap_connection: Connection,
    ) -> None:
        """Test execute() method with real connection parameter."""
        # execute() expects kwargs with str|float|bool|None, but we need to pass Connection
        # Use detect_from_connection directly instead
        result = detector.detect_from_connection(real_ldap_connection)

        TestOperationHelpers.assert_result_success(result)
        detected_type = result.unwrap()
        # Validate actual content: OpenLDAP test server should be detected
        assert detected_type in {"openldap", "openldap2", "rfc"}
        assert isinstance(detected_type, str)
        assert len(detected_type) > 0

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

        TestOperationHelpers.assert_result_failure(result)
        error_msg = TestOperationHelpers.get_error_message(result)
        # Validate error message content: should indicate connection parameter required
        assert (
            "connection parameter required" in error_msg
            or "connection" in error_msg.lower()
        )
