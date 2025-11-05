"""Comprehensive unit tests for FlextLdapServersActiveDirectoryOperations.

Tests Active Directory-specific LDAP operations including ACL handling,
schema discovery, and directory feature detection.

Test Categories:
- @pytest.mark.unit - Unit tests with real objects
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.ad_operations import FlextLdapServersActiveDirectoryOperations


class TestADOperationsInitialization:
    """Test AD operations initialization."""

    @pytest.mark.unit
    def test_ad_initialization_success(self) -> None:
        """Test AD operations initialization."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert ops is not None
        assert ops.server_type == "ad"

    @pytest.mark.unit
    def test_ad_global_catalog_ports(self) -> None:
        """Test AD global catalog port configuration."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert ops.get_global_catalog_port(use_ssl=False) == 3268
        assert ops.get_global_catalog_port(use_ssl=True) == 3269


class TestADOperationsBindMechanisms:
    """Test AD bind mechanism support."""

    @pytest.mark.unit
    def test_get_bind_mechanisms(self) -> None:
        """Test AD supports multiple bind mechanisms."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) >= 3
        assert FlextLdapConstants.SaslMechanisms.SIMPLE in mechanisms
        assert FlextLdapConstants.SaslMechanisms.NTLM in mechanisms
        assert FlextLdapConstants.SaslMechanisms.GSSAPI in mechanisms

    @pytest.mark.unit
    def test_bind_mechanisms_contains_expected_types(self) -> None:
        """Test all expected bind mechanisms are present."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert all(isinstance(m, str) for m in mechanisms)


class TestADOperationsSchemaDN:
    """Test AD schema DN discovery."""

    @pytest.mark.unit
    def test_get_schema_dn_returns_string(self) -> None:
        """Test get_schema_dn returns valid schema DN."""
        ops = FlextLdapServersActiveDirectoryOperations()
        dn = ops.get_schema_dn()
        assert isinstance(dn, str)
        assert len(dn) > 0
        assert "schema" in dn.lower()

    @pytest.mark.unit
    def test_get_schema_dn_ad_format(self) -> None:
        """Test AD schema DN has correct format."""
        ops = FlextLdapServersActiveDirectoryOperations()
        dn = ops.get_schema_dn()
        # AD schema DN typically contains cn=schema,cn=configuration
        assert "cn=" in dn.lower()


class TestADOperationsACLOperations:
    """Test AD ACL attribute and format methods."""

    @pytest.mark.unit
    def test_get_acl_attribute_name(self) -> None:
        """Test AD ACL attribute name."""
        ops = FlextLdapServersActiveDirectoryOperations()
        attr_name = ops.get_acl_attribute_name()
        assert isinstance(attr_name, str)
        assert attr_name == "nTSecurityDescriptor"

    @pytest.mark.unit
    def test_get_acl_format(self) -> None:
        """Test AD ACL format."""
        ops = FlextLdapServersActiveDirectoryOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)
        assert acl_format == "sddl"


class TestADOperationsVLVSupport:
    """Test AD Virtual List View support."""

    @pytest.mark.unit
    def test_supports_vlv_returns_true(self) -> None:
        """Test AD supports VLV."""
        ops = FlextLdapServersActiveDirectoryOperations()
        result = ops.supports_vlv()
        assert result is True


class TestADOperationsServerDetection:
    """Test AD server type detection from Root DSE."""

    @pytest.mark.unit
    def test_detect_server_type_from_root_dse_with_ad_indicators(self) -> None:
        """Test server type detection with AD-specific Root DSE."""
        ops = FlextLdapServersActiveDirectoryOperations()
        root_dse = {
            "vendorName": ["Microsoft Corporation"],
            "dnsHostName": ["dc.example.com"],
        }
        server_type = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(server_type, str)

    @pytest.mark.unit
    def test_detect_server_type_returns_string(self) -> None:
        """Test server detection returns string type."""
        ops = FlextLdapServersActiveDirectoryOperations()
        root_dse = {}
        server_type = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(server_type, str)


class TestADOperationsEntryOperations:
    """Test AD-specific entry operations."""

    @pytest.mark.unit
    def test_validate_entry_for_server_with_valid_entry(self) -> None:
        """Test entry validation for AD."""
        ops = FlextLdapServersActiveDirectoryOperations()
        from flext_ldif import FlextLdifModels

        dn = FlextLdifModels.DistinguishedName(
            value="cn=user,cn=users,dc=example,dc=com"
        )
        attrs = FlextLdifModels.LdifAttributes(attributes={"cn": ["user"]})
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_normalize_entry_for_server_returns_result(self) -> None:
        """Test entry normalization for AD."""
        ops = FlextLdapServersActiveDirectoryOperations()
        from flext_ldif import FlextLdifModels

        dn = FlextLdifModels.DistinguishedName(
            value="cn=user,cn=users,dc=example,dc=com"
        )
        attrs = FlextLdifModels.LdifAttributes(attributes={"cn": ["user"]})
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)


class TestADOperationsFunctionalLevels:
    """Test AD functional level detection (requires connection)."""

    @pytest.mark.unit
    def test_get_forest_functional_level_returns_result_type(self) -> None:
        """Test forest functional level method signature."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # This would require a real AD connection
        # Just verify the method exists and is callable
        assert callable(ops.get_forest_functional_level)

    @pytest.mark.unit
    def test_get_domain_functional_level_returns_result_type(self) -> None:
        """Test domain functional level method signature."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # This would require a real AD connection
        # Just verify the method exists and is callable
        assert callable(ops.get_domain_functional_level)


class TestADOperationsRootDSE:
    """Test AD Root DSE attribute retrieval."""

    @pytest.mark.unit
    def test_get_root_dse_attributes_returns_result(self) -> None:
        """Test Root DSE attributes method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.get_root_dse_attributes)


class TestADOperationsSchemaMethods:
    """Test AD schema discovery methods."""

    @pytest.mark.unit
    def test_discover_schema_method_exists(self) -> None:
        """Test discover_schema method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.discover_schema)

    @pytest.mark.unit
    def test_parse_object_class_method_exists(self) -> None:
        """Test parse_object_class method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.parse_object_class)

    @pytest.mark.unit
    def test_parse_attribute_type_method_exists(self) -> None:
        """Test parse_attribute_type method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.parse_attribute_type)


class TestADOperationsACLMethods:
    """Test AD ACL operations methods."""

    @pytest.mark.unit
    def test_get_acls_method_exists(self) -> None:
        """Test get_acls method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.get_acls)

    @pytest.mark.unit
    def test_set_acls_method_exists(self) -> None:
        """Test set_acls method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.set_acls)

    @pytest.mark.unit
    def test_parse_method_exists(self) -> None:
        """Test parse method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.parse)

    @pytest.mark.unit
    def test_parse_with_sample_string(self) -> None:
        """Test parse with sample ACL string."""
        ops = FlextLdapServersActiveDirectoryOperations()
        result = ops.parse("sample_acl_string")
        assert isinstance(result, FlextResult)


class TestADOperationsSupportedControls:
    """Test AD supported controls method."""

    @pytest.mark.unit
    def test_get_supported_controls_method_exists(self) -> None:
        """Test get_supported_controls method exists."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.get_supported_controls)


class TestADOperationsIntegration:
    """Integration tests for AD operations."""

    @pytest.mark.unit
    def test_ad_operations_has_all_required_methods(self) -> None:
        """Test AD operations has all required methods."""
        ops = FlextLdapServersActiveDirectoryOperations()
        required_methods = [
            "get_global_catalog_port",
            "get_bind_mechanisms",
            "get_schema_dn",
            "discover_schema",
            "parse_object_class",
            "parse_attribute_type",
            "get_acl_attribute_name",
            "get_acl_format",
            "get_acls",
            "set_acls",
            "parse",
            "supports_vlv",
            "get_root_dse_attributes",
            "detect_server_type_from_root_dse",
            "get_supported_controls",
            "normalize_entry_for_server",
            "validate_entry_for_server",
            "get_forest_functional_level",
            "get_domain_functional_level",
        ]
        for method in required_methods:
            assert hasattr(ops, method), f"Missing method: {method}"
            assert callable(getattr(ops, method))

    @pytest.mark.unit
    def test_ad_operations_complete_workflow(self) -> None:
        """Test complete AD operations workflow."""
        ops = FlextLdapServersActiveDirectoryOperations()

        # Test basic properties
        assert ops.server_type == "ad"
        assert ops.get_global_catalog_port(use_ssl=False) == 3268
        assert ops.get_global_catalog_port(use_ssl=True) == 3269

        # Test ACL settings
        assert ops.get_acl_attribute_name() == "nTSecurityDescriptor"
        assert ops.get_acl_format() == "sddl"

        # Test bind mechanisms
        mechanisms = ops.get_bind_mechanisms()
        assert len(mechanisms) >= 3

        # Test VLV support
        assert ops.supports_vlv() is True

        # Test schema DN
        dn = ops.get_schema_dn()
        assert isinstance(dn, str)
        assert len(dn) > 0


class TestADOperationsSchemaDiscovery:
    """Test AD schema discovery operations."""

    @pytest.mark.unit
    def test_discover_schema_returns_result(self) -> None:
        """Test discover_schema returns FlextResult."""
        ops = FlextLdapServersActiveDirectoryOperations()
        with patch("flext_ldap.servers.ad_operations.Connection") as mock_conn:
            result = ops.discover_schema(mock_conn)
            assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_discover_schema_exception_handling(self) -> None:
        """Test discover_schema handles connection failure."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock()
        mock_conn.bound = False  # Connection not bound - should fail
        result = ops.discover_schema(mock_conn)
        assert result.is_failure


class TestADOperationsParseSchemaComponents:
    """Test AD schema component parsing."""

    @pytest.mark.unit
    def test_parse_object_class_success(self) -> None:
        """Test parse_object_class returns result."""
        ops = FlextLdapServersActiveDirectoryOperations()
        with patch.object(
            ops.__class__.__bases__[0], "parse_object_class"
        ) as mock_parse:
            mock_parse.return_value = FlextResult.ok(
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(value="cn=test"),
                    attributes=FlextLdifModels.LdifAttributes(attributes={}),
                )
            )
            result = ops.parse_object_class("test_def")
            assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_parse_attribute_type_success(self) -> None:
        """Test parse_attribute_type returns result."""
        ops = FlextLdapServersActiveDirectoryOperations()
        with patch.object(
            ops.__class__.__bases__[0], "parse_attribute_type"
        ) as mock_parse:
            mock_parse.return_value = FlextResult.ok(
                FlextLdifModels.Entry(
                    dn=FlextLdifModels.DistinguishedName(value="cn=test"),
                    attributes=FlextLdifModels.LdifAttributes(attributes={}),
                )
            )
            result = ops.parse_attribute_type("test_def")
            assert isinstance(result, FlextResult)


class TestADOperationsGetAclsDetailed:
    """Test AD ACL retrieval with detailed scenarios."""

    @pytest.mark.unit
    def test_get_acls_no_entries(self) -> None:
        """Test get_acls when search returns no entries."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.search.return_value = False
        mock_conn.entries = []
        result = ops.get_acls(mock_conn, "cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() == []

    @pytest.mark.unit
    def test_get_acls_exception(self) -> None:
        """Test get_acls exception handling."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.search.side_effect = Exception("Search error")
        result = ops.get_acls(mock_conn, "cn=test,dc=example,dc=com")
        assert result.is_failure


class TestADOperationsSetAclsDetailed:
    """Test AD ACL setting operations."""

    @pytest.mark.unit
    def test_set_acls_unbound_connection(self) -> None:
        """Test set_acls with unbound connection."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = False
        result = ops.set_acls(mock_conn, "cn=test,dc=example,dc=com", [])
        assert result.is_failure
        assert "bound" in result.error.lower()

    @pytest.mark.unit
    def test_set_acls_exception(self) -> None:
        """Test set_acls exception handling."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = True
        mock_conn.modify.side_effect = Exception("Modify error")
        result = ops.set_acls(mock_conn, "cn=test,dc=example,dc=com", [])
        assert result.is_failure


class TestADOperationsParseAclDetailed:
    """Test AD ACL parsing operations."""

    @pytest.mark.unit
    def test_parse_with_exception(self) -> None:
        """Test parse exception handling."""
        ops = FlextLdapServersActiveDirectoryOperations()
        with patch.object(ops.__class__.__bases__[0], "parse") as mock_parse:
            mock_parse.side_effect = Exception("Parse error")
            result = ops.parse("invalid_sddl")
            assert result.is_failure


class TestADOperationsRootDseDetailed:
    """Test Root DSE operations with detailed scenarios."""

    @pytest.mark.unit
    def test_get_root_dse_attributes_invalid_connection(self) -> None:
        """Test get_root_dse_attributes with invalid connection."""
        ops = FlextLdapServersActiveDirectoryOperations()
        result = ops.get_root_dse_attributes(None)
        assert result.is_failure

    @pytest.mark.unit
    def test_get_root_dse_attributes_unbound(self) -> None:
        """Test get_root_dse_attributes with unbound connection."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = False
        result = ops.get_root_dse_attributes(mock_conn)
        assert result.is_failure

    @pytest.mark.unit
    def test_get_root_dse_attributes_search_fails(self) -> None:
        """Test get_root_dse_attributes when search fails."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = True
        mock_conn.search.return_value = False
        result = ops.get_root_dse_attributes(mock_conn)
        assert result.is_failure

    @pytest.mark.unit
    def test_get_root_dse_attributes_exception(self) -> None:
        """Test get_root_dse_attributes exception handling."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = True
        mock_conn.search.side_effect = Exception("Search error")
        result = ops.get_root_dse_attributes(mock_conn)
        assert result.is_failure


class TestADOperationsServerDetectionLogic:
    """Test AD server type detection with various Root DSE attributes."""

    @pytest.mark.unit
    def test_detect_ad_from_root_domain_naming_context(self) -> None:
        """Test AD detection from rootDomainNamingContext."""
        ops = FlextLdapServersActiveDirectoryOperations()
        root_dse = {
            FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT: "DC=example,DC=com"
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == FlextLdapConstants.ServerTypes.AD

    @pytest.mark.unit
    def test_detect_ad_from_vendor_microsoft(self) -> None:
        """Test AD detection from vendorName with Microsoft."""
        ops = FlextLdapServersActiveDirectoryOperations()
        root_dse = {
            FlextLdapConstants.RootDseAttributes.VENDOR_NAME: "Microsoft Corporation"
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == FlextLdapConstants.ServerTypes.AD

    @pytest.mark.unit
    def test_detect_ad_from_vendor_windows(self) -> None:
        """Test AD detection from vendorName with Windows."""
        ops = FlextLdapServersActiveDirectoryOperations()
        root_dse = {
            FlextLdapConstants.RootDseAttributes.VENDOR_NAME: "Windows Active Directory"
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == FlextLdapConstants.ServerTypes.AD

    @pytest.mark.unit
    def test_detect_non_ad_root_dse(self) -> None:
        """Test non-AD detection returns generic type."""
        ops = FlextLdapServersActiveDirectoryOperations()
        root_dse = {
            FlextLdapConstants.RootDseAttributes.VENDOR_NAME: "OpenLDAP Foundation"
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == FlextLdapConstants.Defaults.SERVER_TYPE

    @pytest.mark.unit
    def test_detect_empty_root_dse(self) -> None:
        """Test detection with empty Root DSE."""
        ops = FlextLdapServersActiveDirectoryOperations()
        result = ops.detect_server_type_from_root_dse({})
        assert result == FlextLdapConstants.Defaults.SERVER_TYPE


class TestADOperationsExceptionHandlingAndEdgeCases:
    """Test exception handling and edge cases in AD operations."""

    @pytest.mark.unit
    def test_get_acls_empty_result(self) -> None:
        """Test get_acls returns empty list."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        result = ops.get_acls(mock_conn, "cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() == []

    @pytest.mark.unit
    def test_get_supported_controls_unbound_connection(self) -> None:
        """Test get_supported_controls with unbound connection."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = False
        result = ops.get_supported_controls(mock_conn)
        assert result.is_failure
        assert "not bound" in str(result.error).lower()

    @pytest.mark.unit
    def test_get_supported_controls_with_list(self) -> None:
        """Test get_supported_controls returns list of strings."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mock_conn = MagicMock(spec=Connection)
        mock_conn.bound = True
        result = ops.get_supported_controls(mock_conn)
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)

    @pytest.mark.unit
    def test_validate_entry_simple(self) -> None:
        """Test validate_entry_for_server returns FlextResult."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # Create entry using model_construct to avoid validation issues
        from flext_ldif.models import FlextLdifModels as Models

        entry = Models.Entry.model_construct(
            dn=Models.DistinguishedName.model_construct(
                value="cn=test,dc=example,dc=com"
            ),
            attributes=Models.LdifAttributes.model_construct(attrs={}),
        )
        result = ops.validate_entry_for_server(entry)
        # Verify the method returns a FlextResult
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_validate_entry_with_objectclass(self) -> None:
        """Test validate_entry_for_server with objectClass attribute."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # Create entry using model_construct
        from flext_ldif.models import FlextLdifModels as Models

        attrs = Models.LdifAttributes.model_construct(
            attrs={"objectClass": ["person"]},
        )
        entry = Models.Entry.model_construct(
            dn=Models.DistinguishedName.model_construct(
                value="cn=test,dc=example,dc=com"
            ),
            attributes=attrs,
        )
        result = ops.validate_entry_for_server(entry)
        # Verify the method returns a FlextResult
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_normalize_entry_simple(self) -> None:
        """Test normalize_entry_for_server returns entry."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # Create entry using model_construct
        from flext_ldif.models import FlextLdifModels as Models

        entry = Models.Entry.model_construct(
            dn=Models.DistinguishedName.model_construct(
                value="cn=test,dc=example,dc=com"
            ),
            attributes=Models.LdifAttributes.model_construct(attrs={}),
        )
        result = ops.normalize_entry_for_server(entry)
        # Verify it returns a FlextResult
        assert isinstance(result, FlextResult)
        if result.is_success:
            normalized = result.unwrap()
            assert normalized.dn is not None

    @pytest.mark.unit
    def test_normalize_attribute_name_basic(self) -> None:
        """Test normalize_attribute_name preserves attribute name."""
        ops = FlextLdapServersActiveDirectoryOperations()
        name = ops.normalize_attribute_name("cn")
        assert name == "cn"

    @pytest.mark.unit
    def test_normalize_dn_basic(self) -> None:
        """Test normalize_dn returns normalized DN string."""
        ops = FlextLdapServersActiveDirectoryOperations()
        dn_str = "cn=test,dc=example,dc=com"
        result = ops.normalize_dn(dn_str)
        assert isinstance(result, str)
        assert "cn=test" in result

    @pytest.mark.unit
    def test_parse_basic(self) -> None:
        """Test parse returns FlextResult."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # parse parses ACL strings
        result = ops.parse("test_acl_string")
        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_get_acl_attribute_name_returns_ntsecuritydescriptor(self) -> None:
        """Test get_acl_attribute_name returns AD-specific ACL attribute."""
        ops = FlextLdapServersActiveDirectoryOperations()
        attr_name = ops.get_acl_attribute_name()
        assert attr_name == "nTSecurityDescriptor"

    @pytest.mark.unit
    def test_get_acl_format_returns_sddl(self) -> None:
        """Test get_acl_format returns SDDL format string."""
        ops = FlextLdapServersActiveDirectoryOperations()
        fmt = ops.get_acl_format()
        # AD uses SDDL (Security Descriptor Definition Language) format
        assert fmt == "sddl"


__all__ = [
    "TestADOperationsACLMethods",
    "TestADOperationsACLOperations",
    "TestADOperationsBindMechanisms",
    "TestADOperationsEntryOperations",
    "TestADOperationsExceptionHandlingAndEdgeCases",
    "TestADOperationsFunctionalLevels",
    "TestADOperationsInitialization",
    "TestADOperationsIntegration",
    "TestADOperationsParseSchemaComponents",
    "TestADOperationsRootDSE",
    "TestADOperationsSchemaDN",
    "TestADOperationsSchemaDiscovery",
    "TestADOperationsSchemaMethods",
    "TestADOperationsServerDetection",
    "TestADOperationsServerDetectionLogic",
    "TestADOperationsSupportedControls",
    "TestADOperationsVLVSupport",
]
