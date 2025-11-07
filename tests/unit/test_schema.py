"""Comprehensive unit tests for FlextLdapSchema and nested handler classes.

Tests schema quirks detection, discovery operations, and handler behavior.
All tests use actual FlextLdapSchema components with real objects.

Test Categories:
- @pytest.mark.unit - Unit tests with real objects
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif.constants import FlextLdifConstants

from flext_ldap.services.schema import FlextLdapSchema

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestGenericQuirksDetectorInitialization:
    """Test GenericQuirksDetector initialization."""

    @pytest.mark.unit
    def test_initialization_success(self) -> None:
        """Test successful GenericQuirksDetector initialization."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        assert detector is not None
        assert hasattr(detector, "handle")
        assert hasattr(detector, "detect_server_type")
        assert hasattr(detector, "get_servers")

    @pytest.mark.unit
    def test_detector_inherits_from_handlers(self) -> None:
        """Test GenericQuirksDetector inherits from FlextHandlers."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        assert hasattr(detector, "config")
        assert hasattr(detector, "handle")


class TestGenericQuirksDetectorHandle:
    """Test GenericQuirksDetector.handle() method."""

    @pytest.mark.unit
    def test_handle_with_valid_message(self) -> None:
        """Test handle with valid message returns success."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        message = {"server_info": "test"}

        result = detector.handle(message)

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, dict)
        assert unwrapped.get("detected") is True

    @pytest.mark.unit
    def test_handle_with_none_message(self) -> None:
        """Test handle with None message returns failure."""
        detector = FlextLdapSchema.GenericQuirksDetector()

        result = detector.handle(None)

        assert result.is_failure
        assert result.error and "empty" in result.error.lower()

    @pytest.mark.unit
    def test_handle_returns_flext_result(self) -> None:
        """Test handle returns FlextResult type."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        result = detector.handle({"test": "data"})

        assert isinstance(result, FlextResult)


class TestGenericQuirksDetectorDetectServerType:
    """Test GenericQuirksDetector.detect_server_type() method."""

    @pytest.mark.unit
    def test_detect_server_type_with_valid_info(self) -> None:
        """Test server type detection with valid server info."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        server_info = {"vendor": "OpenLDAP"}

        server_type = detector.detect_server_type(server_info)

        assert server_type is not None
        assert server_type == FlextLdifConstants.LdapServerType.GENERIC

    @pytest.mark.unit
    def test_detect_server_type_with_none_info(self) -> None:
        """Test server type detection with None server info."""
        detector = FlextLdapSchema.GenericQuirksDetector()

        server_type = detector.detect_server_type(None)

        assert server_type is None

    @pytest.mark.unit
    def test_detect_server_type_with_empty_info(self) -> None:
        """Test server type detection with empty server info."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        server_info = {}

        server_type = detector.detect_server_type(server_info)

        # Empty dict is falsy, so should return None
        assert server_type is None


class TestGenericQuirksDetectorGetServerQuirks:
    """Test GenericQuirksDetector.get_servers() method."""

    @pytest.mark.unit
    def test_get_servers_with_valid_type(self) -> None:
        """Test getting server quirks with valid server type."""
        detector = FlextLdapSchema.GenericQuirksDetector()

        quirks = detector.get_servers("generic")

        assert quirks is not None
        assert quirks.server_type == FlextLdifConstants.LdapServerType.GENERIC

    @pytest.mark.unit
    def test_get_servers_with_none_type(self) -> None:
        """Test getting server quirks with None server type."""
        detector = FlextLdapSchema.GenericQuirksDetector()

        quirks = detector.get_servers(None)

        assert quirks is None

    @pytest.mark.unit
    def test_get_servers_has_required_fields(self) -> None:
        """Test server quirks has all required fields."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        quirks = detector.get_servers("generic")

        assert hasattr(quirks, "case_sensitive_dns")
        assert hasattr(quirks, "case_sensitive_attributes")
        assert hasattr(quirks, "supports_paged_results")
        assert hasattr(quirks, "max_page_size")
        assert hasattr(quirks, "default_timeout")

    @pytest.mark.unit
    def test_get_servers_values_correct(self) -> None:
        """Test server quirks values are correct for generic server."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        quirks = detector.get_servers("openldap")

        assert quirks.case_sensitive_dns is True
        assert quirks.case_sensitive_attributes is True
        assert quirks.supports_paged_results is True
        assert quirks.max_page_size > 0
        assert quirks.default_timeout > 0


class TestSchemaDiscoveryInitialization:
    """Test FlextLdapSchema.Discovery initialization."""

    @pytest.mark.unit
    def test_initialization_withouts_adapter(self) -> None:
        """Test Discovery initialization without quirks adapter."""
        discovery = FlextLdapSchema.Discovery()
        assert discovery is not None
        assert hasattr(discovery, "handle")
        assert hasattr(discovery, "get_schema_subentry_dn")

    @pytest.mark.unit
    def test_initialization_withs_adapter(self) -> None:
        """Test Discovery initialization with quirks adapter."""
        from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration

        adapter = FlextLdapQuirksIntegration()
        discovery = FlextLdapSchema.Discovery(quirks_adapter=adapter)

        assert discovery is not None

    @pytest.mark.unit
    def test_discovery_inherits_from_handlers(self) -> None:
        """Test Discovery inherits from FlextHandlers."""
        discovery = FlextLdapSchema.Discovery()
        assert hasattr(discovery, "config")
        assert hasattr(discovery, "handle")


class TestSchemaDiscoveryHandle:
    """Test FlextLdapSchema.Discovery.handle() method."""

    @pytest.mark.unit
    def test_handle_with_valid_message(self) -> None:
        """Test handle with valid discovery message."""
        discovery = FlextLdapSchema.Discovery()
        message = {"request": "discover_schema"}

        result = discovery.handle(message)

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, dict)

    @pytest.mark.unit
    def test_handle_with_none_message(self) -> None:
        """Test handle with None discovery message."""
        discovery = FlextLdapSchema.Discovery()

        result = discovery.handle(None)

        assert result.is_failure
        assert result.error and "empty" in result.error.lower()

    @pytest.mark.unit
    def test_handle_returns_flext_result(self) -> None:
        """Test handle returns FlextResult type."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.handle({"test": "data"})

        assert isinstance(result, FlextResult)


class TestSchemaDiscoveryGetSchemaSubentryDn:
    """Test FlextLdapSchema.Discovery.get_schema_subentry_dn() method."""

    @pytest.mark.unit
    def test_get_schema_dn_for_openldap(self) -> None:
        """Test getting schema DN for OpenLDAP."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("openldap")

        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)
        assert len(dn) > 0

    @pytest.mark.unit
    def test_get_schema_dn_for_openldap2(self) -> None:
        """Test getting schema DN for OpenLDAP 2.x."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("openldap2")

        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)

    @pytest.mark.unit
    def test_get_schema_dn_for_oracle(self) -> None:
        """Test getting schema DN for Oracle."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("oracle")

        assert result.is_success
        dn = result.unwrap()
        assert isinstance(dn, str)

    @pytest.mark.unit
    def test_get_schema_dn_for_unknown_type(self) -> None:
        """Test getting schema DN for unknown server type."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("unknown_server")

        assert result.is_success
        dn = result.unwrap()
        # Should fall back to generic schema DN
        assert isinstance(dn, str)

    @pytest.mark.unit
    def test_get_schema_dn_for_none_type(self) -> None:
        """Test getting schema DN for None server type."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn(None)

        assert result.is_success
        dn = result.unwrap()
        # Should use default server type
        assert isinstance(dn, str)

    @pytest.mark.unit
    def test_get_schema_dn_case_insensitive(self) -> None:
        """Test schema DN lookup is case-insensitive."""
        discovery = FlextLdapSchema.Discovery()

        result_lower = discovery.get_schema_subentry_dn("openldap")
        result_upper = discovery.get_schema_subentry_dn("OPENLDAP")

        assert result_lower.is_success
        assert result_upper.is_success
        assert result_lower.unwrap() == result_upper.unwrap()

    @pytest.mark.unit
    def test_get_schema_dn_returns_flext_result(self) -> None:
        """Test get_schema_subentry_dn returns FlextResult type."""
        discovery = FlextLdapSchema.Discovery()
        result = discovery.get_schema_subentry_dn("generic")

        assert isinstance(result, FlextResult)


class TestFlextLdapSchemaExecute:
    """Test FlextLdapSchema.execute() method."""

    @pytest.mark.unit
    def test_execute_returns_flext_result(self) -> None:
        """Test execute method returns FlextResult."""
        schema = FlextLdapSchema()
        result = schema.execute()

        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_execute_returns_success(self) -> None:
        """Test execute method returns success."""
        schema = FlextLdapSchema()
        result = schema.execute()

        assert result.is_success

    @pytest.mark.unit
    def test_execute_result_unwraps_to_none(self) -> None:
        """Test execute result unwraps to None."""
        schema = FlextLdapSchema()
        result = schema.execute()

        assert result.unwrap() is None


class TestFlextLdapSchemaIntegration:
    """Integration tests for FlextLdapSchema."""

    @pytest.mark.unit
    def test_schema_instance_initialization(self) -> None:
        """Test FlextLdapSchema instance initialization."""
        schema = FlextLdapSchema()
        assert schema is not None
        assert hasattr(schema, "execute")

    @pytest.mark.unit
    def test_schema_nested_classes_accessible(self) -> None:
        """Test nested classes are accessible from main class."""
        assert hasattr(FlextLdapSchema, "QuirksDetector")
        assert hasattr(FlextLdapSchema, "GenericQuirksDetector")
        assert hasattr(FlextLdapSchema, "Discovery")

    @pytest.mark.unit
    def tests_detector_and_discovery_independence(self) -> None:
        """Test that QuirksDetector and Discovery work independently."""
        detector = FlextLdapSchema.GenericQuirksDetector()
        discovery = FlextLdapSchema.Discovery()

        # Both should initialize and work independently
        assert detector is not None
        assert discovery is not None

        # Test detector
        result_detect = detector.handle({"test": "data"})
        assert result_detect.is_success

        # Test discovery
        result_discover = discovery.handle({"test": "data"})
        assert result_discover.is_success


__all__ = [
    "TestFlextLdapSchemaExecute",
    "TestFlextLdapSchemaIntegration",
    "TestGenericQuirksDetectorDetectServerType",
    "TestGenericQuirksDetectorGetServerQuirks",
    "TestGenericQuirksDetectorHandle",
    "TestGenericQuirksDetectorInitialization",
    "TestSchemaDiscoveryGetSchemaSubentryDn",
    "TestSchemaDiscoveryHandle",
    "TestSchemaDiscoveryInitialization",
]
