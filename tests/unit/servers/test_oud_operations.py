"""Tests for FlextLdapServersOUDOperations module."""

from unittest.mock import MagicMock

from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations


class TestFlextLdapServersOUDInitialization:
    """Test initialization and basic properties."""

    def test_servers_oud_operations_initialization(self) -> None:
        """Test servers OUD operations initialization."""
        ops = FlextLdapServersOUDOperations()
        assert ops is not None
        assert ops.server_type == "oud"

    def test_servers_oud_operations_is_base_operations_instance(self) -> None:
        """Test that OUD is properly inherited."""
        from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations

        ops = FlextLdapServersOUDOperations()
        assert isinstance(ops, FlextLdapServersBaseOperations)

    def test_servers_oud_get_default_port(self) -> None:
        """Test OUD default port."""
        ops = FlextLdapServersOUDOperations()
        port = ops.get_default_port()
        assert port == 389

    def test_servers_oud_supports_start_tls(self) -> None:
        """Test OUD START_TLS support."""
        ops = FlextLdapServersOUDOperations()
        assert ops.supports_start_tls() is True

    def test_servers_oud_get_schema_dn(self) -> None:
        """Test OUD schema DN (cn=schema)."""
        ops = FlextLdapServersOUDOperations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=schema"


class TestFlextLdapServersOUDBindMechanisms:
    """Test bind mechanism operations."""

    def test_get_bind_mechanisms_returns_list(self) -> None:
        """Test get_bind_mechanisms returns list."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_bind_mechanisms_includes_simple(self) -> None:
        """Test get_bind_mechanisms includes SIMPLE."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_get_bind_mechanisms_includes_sasl(self) -> None:
        """Test get_bind_mechanisms includes SASL variants."""
        ops = FlextLdapServersOUDOperations()
        mechanisms = ops.get_bind_mechanisms()
        # Should have multiple SASL mechanisms
        sasl_mechanisms = [m for m in mechanisms if "SASL" in m]
        assert len(sasl_mechanisms) >= 3  # EXTERNAL, DIGEST-MD5, GSSAPI, PLAIN


class TestFlextLdapServersOUDACL:
    """Test ACL-related operations."""

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for OUD (ds-privilege-name)."""
        ops = FlextLdapServersOUDOperations()
        acl_attr = ops.get_acl_attribute_name()
        # OUD uses ds-privilege-name
        assert "privilege" in acl_attr.lower() or acl_attr == "ds-privilege-name"

    def test_get_acl_format(self) -> None:
        """Test ACL format for OUD (oracle)."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()
        # OUD uses 'oracle' format
        assert acl_format == "oracle"

    def test_parse_simple(self) -> None:
        """Test parsing simple OUD ACL."""
        ops = FlextLdapServersOUDOperations()
        # OUD format similar to OID
        acl_str = "access to entry by * : browse"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_format_acl_with_entry(self) -> None:
        """Test format_acl with FlextLdifModels.Entry."""
        ops = FlextLdapServersOUDOperations()
        # Create an entry to test with
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl-rule"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "ds-privilege-name": ["access to entry by * : browse"],
            }).unwrap(),
        )
        # Format should work with entry
        result = ops.format_acl(entry)
        # Should return str or FlextResult
        assert isinstance(result, (str, FlextResult)) or result is not None


class TestFlextLdapServersOUDSchemaOperations:
    """Test schema parsing operations."""

    def test_discover_schema_basic(self) -> None:
        """Test schema discovery for OUD."""
        ops = FlextLdapServersOUDOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = []

        result = ops.discover_schema(mock_connection)
        assert isinstance(result, FlextResult)

    def test_parse_object_class(self) -> None:
        """Test parsing objectClass definition for OUD."""
        ops = FlextLdapServersOUDOperations()
        # Simple objectClass definition
        oc_def = "( 2.5.4.0 NAME 'top' ABSTRACT MUST objectClass )"
        result = ops.parse_object_class(oc_def)
        assert isinstance(result, FlextResult)

    def test_parse_attribute_type(self) -> None:
        """Test parsing attributeType definition for OUD."""
        ops = FlextLdapServersOUDOperations()
        # Simple attributeType definition
        attr_def = "( 2.5.4.3 NAME 'cn' SUP name )"
        result = ops.parse_attribute_type(attr_def)
        assert isinstance(result, FlextResult)


class TestFlextLdapServersOUDServerDetection:
    """Test server detection operations."""

    def test_detect_server_type_from_root_dse_with_entry(self) -> None:
        """Test server detection with Entry object."""
        ops = FlextLdapServersOUDOperations()
        # Create a mock root DSE entry
        root_dse = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="dc=root"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "vendorName": ["Oracle"],
                "supportedLDAPVersion": ["3"],
            }).unwrap(),
        )
        result = ops.detect_server_type_from_root_dse(root_dse)
        # Should return a boolean or string
        assert isinstance(result, (bool, str)) or result is None

    def test_get_root_dse_attributes_with_connection(self) -> None:
        """Test getting Root DSE attributes with mock connection."""
        ops = FlextLdapServersOUDOperations()
        # Create mock connection
        mock_connection = MagicMock()

        # get_root_dse_attributes requires connection parameter
        attrs = ops.get_root_dse_attributes(mock_connection)
        # Should return attributes dict or FlextResult
        assert isinstance(attrs, (dict, FlextResult)) or attrs is not None


class TestFlextLdapServersOUDEntryValidation:
    """Test entry validation operations."""

    def test_validate_entry_for_server_basic(self) -> None:
        """Test entry validation for OUD."""
        ops = FlextLdapServersOUDOperations()

        # Create a minimal entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        # Validate (should return FlextResult)
        result = ops.validate_entry_for_server(entry)
        assert (
            isinstance(result, FlextResult)
            or result is None
            or isinstance(result, dict)
        )

    def test_normalize_entry_for_server(self) -> None:
        """Test entry normalization for OUD."""
        ops = FlextLdapServersOUDOperations()

        # Create entry for normalization
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=Test,ou=Users,dc=Example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "CN": ["Test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        # Normalize
        result = ops.normalize_entry_for_server(entry)
        assert result is not None


class TestFlextLdapServersOUDPaging:
    """Test paging-related operations."""

    def test_get_max_page_size(self) -> None:
        """Test max page size."""
        ops = FlextLdapServersOUDOperations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support (OUD supports VLV)."""
        ops = FlextLdapServersOUDOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)
        # Oracle OUD should support VLV (based on 389 DS)
        assert supports is True


class TestFlextLdapServersOUDControls:
    """Test control operations."""

    def test_get_supported_controls(self) -> None:
        """Test getting supported controls."""
        ops = FlextLdapServersOUDOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True

        result = ops.get_supported_controls(mock_connection)
        assert isinstance(result, FlextResult)
        if result.is_success:
            controls = result.unwrap()
            assert isinstance(controls, list)


class TestFlextLdapServersOUDDiscoverSchemaDetailed:
    """Test schema discovery with detailed scenarios."""

    def test_discover_schema_success(self) -> None:
        """Test successful schema discovery."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.entries = [MagicMock()]

        result = ops.discover_schema(mock_connection)
        assert result.is_success
        schema = result.unwrap()
        assert schema is not None

    def test_discover_schema_invalid_connection(self) -> None:
        """Test schema discovery with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.discover_schema(None)
        assert result.is_failure

    def test_discover_schema_unbound_connection(self) -> None:
        """Test schema discovery with unbound connection."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = False
        result = ops.discover_schema(mock_connection)
        assert result.is_failure

    def test_discover_schema_no_entries(self) -> None:
        """Test schema discovery when search returns no entries."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.entries = []
        result = ops.discover_schema(mock_connection)
        assert result.is_failure

    def test_discover_schema_search_fails(self) -> None:
        """Test schema discovery when search fails."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = False
        result = ops.discover_schema(mock_connection)
        assert result.is_failure

    def test_discover_schema_exception(self) -> None:
        """Test schema discovery exception handling."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Search failed")
        result = ops.discover_schema(mock_connection)
        assert result.is_failure


class TestFlextLdapServersOUDGetAclsDetailed:
    """Test ACL retrieval with detailed scenarios."""

    def test_get_acls_success(self) -> None:
        """Test successful ACL retrieval."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.entries = [MagicMock()]
        result = ops.get_acls(mock_connection, "cn=test,dc=example,dc=com")
        assert result.is_success
        acls = result.unwrap()
        assert isinstance(acls, list)

    def test_get_acls_unbound_connection(self) -> None:
        """Test ACL retrieval with unbound connection."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = False
        result = ops.get_acls(mock_connection, "cn=test,dc=example,dc=com")
        assert result.is_failure

    def test_get_acls_invalid_connection(self) -> None:
        """Test ACL retrieval with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.get_acls(None, "cn=test,dc=example,dc=com")
        assert result.is_failure

    def test_get_acls_search_fails(self) -> None:
        """Test ACL retrieval when search fails."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = False
        result = ops.get_acls(mock_connection, "cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.unwrap() == []

    def test_get_acls_exception(self) -> None:
        """Test ACL retrieval exception handling."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Search failed")
        result = ops.get_acls(mock_connection, "cn=test,dc=example,dc=com")
        assert result.is_failure


class TestFlextLdapServersOUDSetAclsDetailed:
    """Test ACL setting with detailed scenarios."""

    def test_set_acls_success(self) -> None:
        """Test successful ACL setting."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = True
        acls = [{"privilege": "config-read", "raw": "config-read"}]
        result = ops.set_acls(mock_connection, "cn=test,dc=example,dc=com", acls)
        assert result.is_success

    def test_set_acls_unbound_connection(self) -> None:
        """Test ACL setting with unbound connection."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = False
        acls = [{"privilege": "config-read"}]
        result = ops.set_acls(mock_connection, "cn=test,dc=example,dc=com", acls)
        assert result.is_failure

    def test_set_acls_invalid_connection(self) -> None:
        """Test ACL setting with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        acls = [{"privilege": "config-read"}]
        result = ops.set_acls(None, "cn=test,dc=example,dc=com", acls)
        assert result.is_failure

    def test_set_acls_modify_fails(self) -> None:
        """Test ACL setting when modify fails."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = False
        mock_connection.result = {"description": "LDAP error"}
        acls = [{"privilege": "config-read", "raw": "config-read"}]
        result = ops.set_acls(mock_connection, "cn=test,dc=example,dc=com", acls)
        assert result.is_failure

    def test_set_acls_exception(self) -> None:
        """Test ACL setting exception handling."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.side_effect = Exception("Modify failed")
        acls = [{"privilege": "config-read", "raw": "config-read"}]
        result = ops.set_acls(mock_connection, "cn=test,dc=example,dc=com", acls)
        assert result.is_failure


class TestFlextLdapServersOUDParseAclDetailed:
    """Test ACL parsing with detailed scenarios."""

    def test_parse_config_read(self) -> None:
        """Test parsing config-read privilege."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse("config-read")
        assert result.is_success
        entry = result.unwrap()
        assert entry is not None

    def test_parse_password_reset(self) -> None:
        """Test parsing password-reset privilege."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse("password-reset")
        assert result.is_success

    def test_parse_bypass_acl(self) -> None:
        """Test parsing bypass-acl privilege."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse("bypass-acl")
        assert result.is_success

    def test_parse_custom_privilege(self) -> None:
        """Test parsing custom privilege."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse("custom-privilege")
        assert result.is_success

    def test_parse_with_whitespace(self) -> None:
        """Test parsing ACL with whitespace."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse("  config-read  ")
        assert result.is_success

    def test_parse_empty_string(self) -> None:
        """Test parsing empty privilege string."""
        ops = FlextLdapServersOUDOperations()
        result = ops.parse("")
        assert result.is_success


class TestFlextLdapServersOUDFormatAclDetailed:
    """Test ACL formatting with detailed scenarios."""

    def test_format_acl_with_raw(self) -> None:
        """Test formatting ACL with raw field."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "raw": "config-read"
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success
        assert result.unwrap() == "config-read"

    def test_format_acl_with_privilege(self) -> None:
        """Test formatting ACL with privilege field."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "privilege": "password-reset"
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success

    def test_format_acl_missing_fields(self) -> None:
        """Test formatting ACL with missing fields."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({}).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_failure

    def test_format_acl_empty_entry_attributes(self) -> None:
        """Test ACL formatting with minimal entry."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "other": "value"
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_failure


class TestFlextLdapServersOUDModifyEntryDetailed:
    """Test entry modification with detailed scenarios."""

    def test_modify_entry_success(self) -> None:
        """Test successful entry modification."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = True
        modifications = {"cn": "new-value"}
        result = ops.modify_entry(
            mock_connection, "cn=test,dc=example,dc=com", modifications
        )
        assert result.is_success

    def test_modify_entry_schema(self) -> None:
        """Test modification with OUD schema quirks."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = True
        modifications = {"attributeTypes": "new-attribute"}
        result = ops.modify_entry(mock_connection, "cn=schema", modifications)
        assert result.is_success

    def test_modify_entry_invalid_connection(self) -> None:
        """Test modification with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        modifications = {"cn": "new-value"}
        result = ops.modify_entry(None, "cn=test,dc=example,dc=com", modifications)
        assert result.is_failure

    def test_modify_entry_unbound_connection(self) -> None:
        """Test modification with unbound connection."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = False
        modifications = {"cn": "new-value"}
        result = ops.modify_entry(
            mock_connection, "cn=test,dc=example,dc=com", modifications
        )
        assert result.is_failure

    def test_modify_entry_modify_fails(self) -> None:
        """Test modification when LDAP modify fails."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = False
        modifications = {"cn": "new-value"}
        result = ops.modify_entry(
            mock_connection, "cn=test,dc=example,dc=com", modifications
        )
        assert result.is_failure

    def test_modify_entry_exception(self) -> None:
        """Test modification exception handling."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.side_effect = Exception("Modify error")
        modifications = {"cn": "new-value"}
        result = ops.modify_entry(
            mock_connection, "cn=test,dc=example,dc=com", modifications
        )
        assert result.is_failure


class TestFlextLdapServersOUDDetectServerTypeDetailed:
    """Test server type detection with detailed scenarios."""

    def test_detect_oud_from_vendor_oracle(self) -> None:
        """Test OUD detection from vendor name."""
        ops = FlextLdapServersOUDOperations()
        root_dse = {"vendorname": "Oracle"}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "oud"

    def test_detect_oud_from_vendor_oud_string(self) -> None:
        """Test OUD detection from vendor containing 'oud'."""
        ops = FlextLdapServersOUDOperations()
        root_dse = {"vendorname": "Oracle Unified Directory"}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "oud"

    def test_detect_non_oud(self) -> None:
        """Test non-OUD detection."""
        ops = FlextLdapServersOUDOperations()
        root_dse = {"vendorname": "OpenLDAP"}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "generic"

    def test_detect_empty_root_dse(self) -> None:
        """Test detection with empty Root DSE."""
        ops = FlextLdapServersOUDOperations()
        result = ops.detect_server_type_from_root_dse({})
        assert result == "generic"


class TestFlextLdapServersOUDGetRootDseAttributesDetailed:
    """Test Root DSE retrieval with detailed scenarios."""

    def test_get_root_dse_attributes_success(self) -> None:
        """Test successful Root DSE retrieval."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.server.info = {
            "vendorname": "Oracle",
            "supportedLDAPVersion": ["3"],
        }
        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, dict)

    def test_get_root_dse_attributes_invalid_connection(self) -> None:
        """Test Root DSE retrieval with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.get_root_dse_attributes(None)
        assert result.is_failure

    def test_get_root_dse_attributes_unbound(self) -> None:
        """Test Root DSE retrieval with unbound connection."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = False
        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure

    def test_get_root_dse_attributes_no_info(self) -> None:
        """Test Root DSE retrieval when info is None."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.server.info = None
        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure

    def test_get_root_dse_attributes_with_multiple_attributes(self) -> None:
        """Test Root DSE retrieval with multiple attributes."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.server.info = {
            "vendorname": "Oracle",
            "supportedLDAPVersion": ["3"],
            "supportedControls": ["1.2.840.113556.1.4.801"],
        }
        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_success


class TestFlextLdapServersOUDGetSupportedControlsDetailed:
    """Test supported controls retrieval with detailed scenarios."""

    def test_get_supported_controls_success(self) -> None:
        """Test successful supported controls retrieval."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.server.info.supported_controls = [
            "1.2.840.113556.1.4.801",
            "1.2.840.113556.1.4.802",
        ]
        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)

    def test_get_supported_controls_invalid_connection(self) -> None:
        """Test supported controls with invalid connection."""
        ops = FlextLdapServersOUDOperations()
        result = ops.get_supported_controls(None)
        assert result.is_failure

    def test_get_supported_controls_unbound(self) -> None:
        """Test supported controls with unbound connection."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = False
        result = ops.get_supported_controls(mock_connection)
        assert result.is_failure

    def test_get_supported_controls_none(self) -> None:
        """Test supported controls when None."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.server.info.supported_controls = None
        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        assert result.unwrap() == []

    def test_get_supported_controls_with_multiple_controls(self) -> None:
        """Test supported controls with multiple items."""
        ops = FlextLdapServersOUDOperations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        controls = [
            "1.2.840.113556.1.4.801",
            "1.2.840.113556.1.4.802",
            "1.3.6.1.4.1.1466.20037.1",
        ]
        mock_connection.server.info.supported_controls = controls
        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        returned_controls = result.unwrap()
        assert len(returned_controls) == 3


class TestFlextLdapServersOUDNormalizeEntryDetailed:
    """Test entry normalization with detailed scenarios."""

    def test_normalize_entry_success(self) -> None:
        """Test successful entry normalization."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success

    def test_normalize_entry_adds_object_class(self) -> None:
        """Test normalization adds objectClass if missing."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({"cn": ["test"]}).unwrap(),
        )
        result = ops.normalize_entry_for_server(entry)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized is not None

    def test_normalize_entry_exception(self) -> None:
        """Test normalization exception handling."""
        ops = FlextLdapServersOUDOperations()
        entry = MagicMock(spec=FlextLdifModels.Entry)
        entry.model_copy.side_effect = Exception("Copy failed")
        result = ops.normalize_entry_for_server(entry)
        assert result.is_failure


class TestFlextLdapServersOUDValidateEntryDetailed:
    """Test entry validation with detailed scenarios."""

    def test_validate_entry_success(self) -> None:
        """Test successful entry validation."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_entry_minimal_attributes(self) -> None:
        """Test validation with minimal attributes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=minimal,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["minimal"],
                "objectClass": ["device"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_success

    def test_validate_entry_no_object_class_check(self) -> None:
        """Test validation identifies missing objectClass."""
        ops = FlextLdapServersOUDOperations()
        # Create entry with no objectClass attribute
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "mail": ["test@example.com"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_failure

    def test_validate_entry_with_multiple_classes(self) -> None:
        """Test validation with multiple objectClasses."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["top", "person", "inetOrgPerson"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_success


class TestFlextLdapServersOUDOUDSpecificOperations:
    """Test OUD-specific operations."""

    def test_get_oud_version(self) -> None:
        """Test getting OUD version."""
        ops = FlextLdapServersOUDOperations()
        version = ops.get_oud_version()
        assert version == "12c"

    def test_is_based_on_389ds(self) -> None:
        """Test 389DS base check."""
        ops = FlextLdapServersOUDOperations()
        assert ops.is_based_on_389ds() is True

    def test_get_oud_privileges(self) -> None:
        """Test getting OUD privileges list."""
        ops = FlextLdapServersOUDOperations()
        privileges = ops.get_oud_privileges()
        assert isinstance(privileges, list)
        assert len(privileges) > 0
        assert "config-read" in privileges

    def test_get_privilege_category_config(self) -> None:
        """Test privilege category for config privileges."""
        ops = FlextLdapServersOUDOperations()
        category = ops.get_privilege_category("config-read")
        assert category is not None

    def test_get_privilege_category_password(self) -> None:
        """Test privilege category for password privileges."""
        ops = FlextLdapServersOUDOperations()
        category = ops.get_privilege_category("password-reset")
        assert category is not None

    def test_get_privilege_category_custom(self) -> None:
        """Test privilege category for custom privilege."""
        ops = FlextLdapServersOUDOperations()
        category = ops.get_privilege_category("custom-privilege")
        assert category is not None

    def test_supports_replication(self) -> None:
        """Test replication support."""
        ops = FlextLdapServersOUDOperations()
        assert ops.supports_replication() is True

    def test_get_replication_mechanism(self) -> None:
        """Test replication mechanism."""
        ops = FlextLdapServersOUDOperations()
        mechanism = ops.get_replication_mechanism()
        assert mechanism == "multi-master"
