"""Unit tests for FlextLdapSchema service.

Tests the actual FlextLdapSchema API including:
- Service initialization and FlextService integration
- Quirks detection with GenericQuirksDetector
- Schema discovery and subentry DN resolution
- Error handling with FlextResult patterns

All tests use real FlextLdapSchema objects with no mocks.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.services.schema import FlextLdapSchema


class TestFlextLdapSchemaInitialization:
    """Test FlextLdapSchema initialization and basic functionality."""

    @pytest.mark.unit
    def test_schema_service_can_be_instantiated(self) -> None:
        """Test FlextLdapSchema can be instantiated."""
        schema = FlextLdapSchema()
        assert schema is not None
        assert isinstance(schema, FlextLdapSchema)

    @pytest.mark.unit
    def test_schema_service_has_logger(self) -> None:
        """Test schema service inherits logger from FlextService."""
        schema = FlextLdapSchema()
        assert hasattr(schema, "logger")
        assert schema.logger is not None

    @pytest.mark.unit
    def test_schema_service_has_container(self) -> None:
        """Test schema service has container from FlextService."""
        schema = FlextLdapSchema()
        assert hasattr(schema, "container")


class TestFlextLdapSchemaExecute:
    """Test the execute method required by FlextService."""

    @pytest.mark.unit
    def test_execute_returns_flext_result(self) -> None:
        """Test execute method returns FlextResult."""
        schema = FlextLdapSchema()
        result = schema.execute()
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_returns_success(self) -> None:
        """Test execute method returns successful result."""
        schema = FlextLdapSchema()
        result = schema.execute()
        assert result.is_success

    @pytest.mark.unit
    def test_execute_result_value_is_none(self) -> None:
        """Test execute result unwraps to None as per design."""
        schema = FlextLdapSchema()
        result = schema.execute()
        assert result.unwrap() is None


class TestGenericQuirksDetector:
    """Test the GenericQuirksDetector inner class."""

    @pytest.mark.unit
    def test_generic_quirks_detector_can_be_instantiated(self) -> None:
        """Test GenericQuirksDetector can be created."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        assert detector is not None
        assert isinstance(detector, FlextLdapSchema.GenericQuirksDetector)

    @pytest.mark.unit
    def test_generic_quirks_detector_has_logger(self) -> None:
        """Test detector inherits logger from FlextHandlers."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        assert hasattr(detector, "logger")
        assert detector.logger is not None

    @pytest.mark.unit
    def test_handle_with_empty_message_fails(self) -> None:
        """Test handle method fails with None/empty message."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.handle(None)
        assert result.is_failure
        assert "cannot be empty" in result.error.lower()

    @pytest.mark.unit
    def test_handle_with_valid_message_succeeds(self) -> None:
        """Test handle method succeeds with valid message."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        message = {"vendor_name": "test"}
        result = detector.handle(message)
        assert result.is_success
        unwrapped = result.unwrap()
        assert "detected" in unwrapped
        assert unwrapped["detected"] is True

    @pytest.mark.unit
    def test_detect_server_type_with_none_returns_none(self) -> None:
        """Test server type detection with None returns None."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.detect_server_type(None)
        assert result is None

    @pytest.mark.unit
    def test_detect_server_type_returns_generic_type(self) -> None:
        """Test server type detection returns GENERIC for any server info."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        server_info = {"vendor_name": "Test Server"}
        result = detector.detect_server_type(server_info)
        # Should return FlextLdifConstants.LdapServerType enum or string "generic"
        assert result is not None

    @pytest.mark.unit
    def test_get_server_quirks_with_none_returns_none(self) -> None:
        """Test get_server_quirks with None server type returns None."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.get_server_quirks(None)
        assert result is None

    @pytest.mark.unit
    def test_get_server_quirks_returns_quirks_object(self) -> None:
        """Test get_server_quirks returns proper ServerQuirks object."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        quirks = detector.get_server_quirks("generic")
        assert quirks is not None
        # Verify basic quirks properties
        assert hasattr(quirks, "case_sensitive_dns")
        assert hasattr(quirks, "case_sensitive_attributes")
        assert hasattr(quirks, "supports_paged_results")
        assert hasattr(quirks, "max_page_size")
        assert hasattr(quirks, "default_timeout")

    @pytest.mark.unit
    def test_generic_quirks_detector_properties_valid(self) -> None:
        """Test generic quirks detector returns sensible quirks."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        quirks = detector.get_server_quirks("any-server")
        assert quirks.supports_paged_results is True
        assert (
            quirks.max_page_size == FlextLdapConstants.Connection.MAX_PAGE_SIZE_GENERIC
        )
        assert (
            quirks.default_timeout
            == FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS
        )


class TestSchemaDiscovery:
    """Test the Discovery inner class."""

    @pytest.mark.unit
    def test_schema_discovery_can_be_instantiated(self) -> None:
        """Test Discovery class can be created."""
        discovery = FlextLdapSchema.Discovery()
        assert discovery is not None
        assert isinstance(discovery, FlextLdapSchema.Discovery)

    @pytest.mark.unit
    def test_schema_discovery_has_logger(self) -> None:
        """Test discovery inherits logger from FlextHandlers."""
        discovery = FlextLdapSchema.Discovery()
        assert hasattr(discovery, "logger")
        assert discovery.logger is not None

    @pytest.mark.unit
    def test_handle_with_empty_message_fails(self) -> None:
        """Test handle method fails with None/empty message."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.handle(None)
        assert result.is_failure
        assert "cannot be empty" in result.error.lower()

    @pytest.mark.unit
    def test_handle_with_valid_message_succeeds(self) -> None:
        """Test handle method succeeds with valid message."""
        discovery = FlextLdapSchema.Discovery()
        message = {"request": "schema_discovery"}
        result = discovery.handle(message)
        assert result.is_success
        unwrapped = result.unwrap()
        assert "schema_discovered" in unwrapped

    @pytest.mark.unit
    def test_get_schema_subentry_dn_with_none_returns_generic(self) -> None:
        """Test get_schema_subentry_dn with None returns generic schema DN."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn(None)
        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)
        assert len(dn) > 0

    @pytest.mark.unit
    def test_get_schema_subentry_dn_openldap(self) -> None:
        """Test get_schema_subentry_dn for OpenLDAP returns correct DN."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("openldap")
        assert result.is_success
        dn = result.unwrap()
        # OpenLDAP uses config schema
        assert FlextLdapConstants.SchemaDns.SCHEMA_CONFIG in dn

    @pytest.mark.unit
    def test_get_schema_subentry_dn_openldap2(self) -> None:
        """Test get_schema_subentry_dn for OpenLDAP 2.x."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("openldap2")
        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)

    @pytest.mark.unit
    def test_get_schema_subentry_dn_oracle(self) -> None:
        """Test get_schema_subentry_dn for Oracle servers."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("oracle")
        assert result.is_success
        dn = result.unwrap()
        # Oracle uses subSchemaSubentry
        assert FlextLdapConstants.SchemaDns.SUBS_SCHEMA_SUBENTRY in dn

    @pytest.mark.unit
    def test_get_schema_subentry_dn_case_insensitive(self) -> None:
        """Test get_schema_subentry_dn is case-insensitive."""
        discovery = FlextLdapSchema.Discovery()
        result_lower = discovery.get_schema_subentry_dn("openldap")
        result_upper = discovery.get_schema_subentry_dn("OPENLDAP")
        assert result_lower.is_success
        assert result_upper.is_success
        # Both should return same DN
        assert result_lower.unwrap() == result_upper.unwrap()

    @pytest.mark.unit
    def test_get_schema_subentry_dn_unknown_server_type(self) -> None:
        """Test get_schema_subentry_dn with unknown server type."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("unknown-server")
        assert result.is_success
        dn = result.unwrap()
        # Should return generic schema DN
        assert dn == FlextLdapConstants.SchemaDns.SCHEMA


class TestSchemaServiceIntegration:
    """Integration tests for FlextLdapSchema service."""

    @pytest.mark.unit
    def test_complete_schema_service_workflow(self) -> None:
        """Test complete schema service workflow."""
        # Create service
        schema = FlextLdapSchema()
        assert schema is not None

        # Execute service
        result = schema.execute()
        assert result.is_success

        # Create discovery
        discovery = FlextLdapSchema.Discovery()
        assert discovery is not None

        # Get schema DN
        dn_result = discovery.get_schema_subentry_dn("openldap")
        assert dn_result.is_success

    @pytest.mark.unit
    def test_quirks_detector_and_discovery_independent(self) -> None:
        """Test that QuirksDetector and Discovery are independent."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        discovery = FlextLdapSchema.Discovery()

        # Both should work independently
        quirks = detector.get_server_quirks("generic")
        dn = discovery.get_schema_subentry_dn("generic").unwrap()

        assert quirks is not None
        assert dn is not None

    @pytest.mark.unit
    def test_schema_service_with_all_server_types(self) -> None:
        """Test schema discovery with various server types."""
        discovery = FlextLdapSchema.Discovery()
        server_types = [
            None,
            "openldap",
            "openldap2",
            "oracle",
            "unknown",
        ]

        for server_type in server_types:
            result = discovery.get_schema_subentry_dn(server_type)
            assert result.is_success, f"Failed for server type: {server_type}"
            dn = result.unwrap()
            assert isinstance(dn, str)
            assert len(dn) > 0
