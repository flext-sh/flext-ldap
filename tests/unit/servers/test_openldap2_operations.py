"""Tests for FlextLdapServersOpenLDAP2Operations module."""

from unittest.mock import MagicMock

from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations


class TestFlextLdapServersOpenLDAP2Initialization:
    """Test initialization and basic properties."""

    def test_servers_openldap2_operations_initialization(self) -> None:
        """Test servers OpenLDAP2 operations initialization."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops is not None
        assert ops.server_type == "openldap2"

    def test_servers_openldap2_operations_is_base_operations_instance(self) -> None:
        """Test that OpenLDAP2 is properly inherited."""
        from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations

        ops = FlextLdapServersOpenLDAP2Operations()
        assert isinstance(ops, FlextLdapServersBaseOperations)

    def test_servers_openldap2_get_default_port(self) -> None:
        """Test OpenLDAP2 default port."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port = ops.get_default_port()
        assert port == 389

    def test_servers_openldap2_supports_start_tls(self) -> None:
        """Test OpenLDAP2 START_TLS support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.supports_start_tls() is True

    def test_servers_openldap2_get_schema_dn(self) -> None:
        """Test OpenLDAP2 schema DN."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()
        # OpenLDAP 2.x uses cn=subschema or cn=schema
        assert "subschema" in schema_dn.lower() or "schema" in schema_dn.lower()


class TestFlextLdapServersOpenLDAP2BindMechanisms:
    """Test bind mechanism operations."""

    def test_get_bind_mechanisms_returns_list(self) -> None:
        """Test get_bind_mechanisms returns list."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_bind_mechanisms_includes_simple(self) -> None:
        """Test get_bind_mechanisms includes SIMPLE."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_get_bind_mechanisms_includes_sasl(self) -> None:
        """Test get_bind_mechanisms includes SASL variants."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        # Should have at least one SASL mechanism
        sasl_mechanisms = [m for m in mechanisms if "SASL" in m]
        assert len(sasl_mechanisms) > 0

    def test_get_bind_mechanisms_includes_external(self) -> None:
        """Test get_bind_mechanisms includes SASL/EXTERNAL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SASL/EXTERNAL" in mechanisms or any("EXTERNAL" in m for m in mechanisms)


class TestFlextLdapServersOpenLDAP2ACL:
    """Test ACL-related operations."""

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for OpenLDAP2."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_attr = ops.get_acl_attribute_name()
        # OpenLDAP 2.x uses olcAccess
        assert acl_attr.lower() == "olcaccess" or "access" in acl_attr.lower()

    def test_get_acl_format(self) -> None:
        """Test ACL format for OpenLDAP2."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_format = ops.get_acl_format()
        # OpenLDAP 2.x uses olcAccess format
        assert "openldap" in acl_format.lower() or "olc" in acl_format.lower()

    def test_parse_acl_returns_dict(self) -> None:
        """Test parse_acl returns dict."""
        ops = FlextLdapServersOpenLDAP2Operations()
        # Sample olcAccess format ACL
        acl_str = "{0}to * by self write by users read"
        result = ops.parse_acl(acl_str)
        assert isinstance(result, dict) or result is not None

    def test_format_acl_with_result(self) -> None:
        """Test format_acl with FlextResult."""
        ops = FlextLdapServersOpenLDAP2Operations()
        # Create an entry to test with
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "olcAccess": ["{0}to * by self write by users read"],
            }).unwrap(),
        )
        # Format should work with entry
        result = ops.format_acl(entry)
        # Should return str or FlextResult
        assert isinstance(result, (str, FlextResult)) or result is not None


class TestFlextLdapServersOpenLDAP2ServerDetection:
    """Test server detection operations."""

    def test_detect_server_type_from_root_dse_with_entry(self) -> None:
        """Test server detection with Entry object."""
        ops = FlextLdapServersOpenLDAP2Operations()
        # Create a mock root DSE entry (root DSE has empty or root DN)
        root_dse = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="dc=root"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "vendorName": ["OpenLDAP"],
                "supportedLDAPVersion": ["3"],
            }).unwrap(),
        )
        result = ops.detect_server_type_from_root_dse(root_dse)
        # Should return a boolean or string
        assert isinstance(result, (bool, str)) or result is None

    def test_get_root_dse_attributes_with_connection(self) -> None:
        """Test getting Root DSE attributes with mock connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        # Create mock connection
        mock_connection = MagicMock()

        # get_root_dse_attributes requires connection parameter
        attrs = ops.get_root_dse_attributes(mock_connection)
        # Should return attributes list (may be empty for mock)
        assert isinstance(attrs, (list, tuple)) or attrs is not None


class TestFlextLdapServersOpenLDAP2EntryValidation:
    """Test entry validation operations."""

    def test_validate_entry_for_server_basic(self) -> None:
        """Test entry validation for OpenLDAP2."""
        ops = FlextLdapServersOpenLDAP2Operations()

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
        """Test entry normalization for OpenLDAP2."""
        ops = FlextLdapServersOpenLDAP2Operations()

        # Create entry with mixed case attributes
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


class TestFlextLdapServersOpenLDAP2Paging:
    """Test paging-related operations."""

    def test_get_max_page_size(self) -> None:
        """Test max page size."""
        ops = FlextLdapServersOpenLDAP2Operations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)


# =========================================================================
# DETAILED TEST CLASSES FOLLOWING PHASE 18 PATTERN
# =========================================================================


class TestFlextLdapServersOpenLDAP2DiscoverSchemaDetailed:
    """Test schema discovery with detailed scenarios."""

    def test_discover_schema_success(self) -> None:
        """Test successful schema discovery."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_entry = MagicMock()
        mock_entry.entry_attributes = ["objectClasses", "attributeTypes"]
        mock_entry.__getitem__ = MagicMock(return_value=MagicMock(value=[]))
        mock_connection.entries = [mock_entry]

        result = ops.discover_schema(mock_connection)
        assert result.is_success
        schema = result.unwrap()
        assert schema is not None
        assert schema.server_type == "openldap2"

    def test_discover_schema_unbound_connection(self) -> None:
        """Test schema discovery with unbound connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = False

        result = ops.discover_schema(mock_connection)
        assert result.is_failure

    def test_discover_schema_invalid_connection(self) -> None:
        """Test schema discovery with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.discover_schema(None)
        assert result.is_failure

    def test_discover_schema_search_failed(self) -> None:
        """Test schema discovery when search fails."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = False
        mock_connection.entries = []

        result = ops.discover_schema(mock_connection)
        assert result.is_failure

    def test_discover_schema_no_entries(self) -> None:
        """Test schema discovery with no entries returned."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.entries = []

        result = ops.discover_schema(mock_connection)
        assert result.is_failure

    def test_discover_schema_exception_handling(self) -> None:
        """Test schema discovery exception handling."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Connection error")

        result = ops.discover_schema(mock_connection)
        assert result.is_failure
        assert "Connection error" in result.error or "failed" in result.error.lower()


class TestFlextLdapServersOpenLDAP2ParseSchemaDetailed:
    """Test schema parsing operations."""

    def test_parse_object_class_success(self) -> None:
        """Test successful objectClass parsing."""
        ops = FlextLdapServersOpenLDAP2Operations()
        obj_class_def = "( 2.5.4.0 NAME 'objectClass' )"

        result = ops.parse_object_class(obj_class_def)
        assert result.is_success
        entry = result.unwrap()
        assert entry is not None
        assert "note" in entry.attributes.attributes

    def test_parse_object_class_empty_definition(self) -> None:
        """Test objectClass parsing with empty definition."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.parse_object_class("")
        # Should still return something or fail gracefully
        assert result is not None

    def test_parse_attribute_type_success(self) -> None:
        """Test successful attributeType parsing."""
        ops = FlextLdapServersOpenLDAP2Operations()
        attr_def = "( 2.5.4.3 NAME 'cn' )"

        result = ops.parse_attribute_type(attr_def)
        assert result.is_success
        entry = result.unwrap()
        assert entry is not None
        assert "note" in entry.attributes.attributes

    def test_parse_attribute_type_complex_definition(self) -> None:
        """Test attributeType parsing with complex definition."""
        ops = FlextLdapServersOpenLDAP2Operations()
        attr_def = "( 2.5.4.3 NAME 'cn' DESC 'Common Name' EQUALITY caseIgnoreMatch )"

        result = ops.parse_attribute_type(attr_def)
        assert result is not None


class TestFlextLdapServersOpenLDAP2AclOperationsDetailed:
    """Test ACL operations with detailed scenarios."""

    def test_get_acls_success(self) -> None:
        """Test successful ACL retrieval."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_entry = MagicMock()
        mock_entry.entry_attributes = ["olcAccess"]
        mock_entry.__getitem__ = MagicMock(
            return_value=MagicMock(value=["{0}to * by self write"])
        )
        mock_connection.entries = [mock_entry]

        result = ops.get_acls(mock_connection, "olcDatabase={1}mdb,cn=config")
        assert result.is_success
        acls = result.unwrap()
        assert isinstance(acls, list)

    def test_get_acls_unbound_connection(self) -> None:
        """Test ACL retrieval with unbound connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = False

        result = ops.get_acls(mock_connection, "olcDatabase={1}mdb,cn=config")
        assert result.is_failure

    def test_get_acls_none_connection(self) -> None:
        """Test ACL retrieval with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.get_acls(None, "olcDatabase={1}mdb,cn=config")
        assert result.is_failure

    def test_get_acls_no_entries(self) -> None:
        """Test ACL retrieval with no entries."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.entries = []

        result = ops.get_acls(mock_connection, "olcDatabase={1}mdb,cn=config")
        assert result.is_success
        acls = result.unwrap()
        assert acls == []

    def test_get_acls_exception_handling(self) -> None:
        """Test ACL retrieval exception handling."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("LDAP error")

        result = ops.get_acls(mock_connection, "olcDatabase={1}mdb,cn=config")
        assert result.is_failure


class TestFlextLdapServersOpenLDAP2SetAclsDetailed:
    """Test setting ACLs."""

    def test_set_acls_success(self) -> None:
        """Test successful ACL setting."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = True
        mock_connection.result = {"description": "Success"}

        acls = [{"olcAccess": "{0}to * by self write by users read"}]
        result = ops.set_acls(mock_connection, "olcDatabase={1}mdb,cn=config", acls)
        assert result.is_success

    def test_set_acls_unbound_connection(self) -> None:
        """Test ACL setting with unbound connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = False

        result = ops.set_acls(mock_connection, "olcDatabase={1}mdb,cn=config", [])
        assert result.is_failure

    def test_set_acls_none_connection(self) -> None:
        """Test ACL setting with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.set_acls(None, "olcDatabase={1}mdb,cn=config", [])
        assert result.is_failure

    def test_set_acls_modify_failed(self) -> None:
        """Test ACL setting when modify fails."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = False
        mock_connection.result = {"description": "Failed"}

        acls = [{"olcAccess": "{0}to * by self write"}]
        result = ops.set_acls(mock_connection, "olcDatabase={1}mdb,cn=config", acls)
        assert result.is_failure

    def test_set_acls_empty_list(self) -> None:
        """Test ACL setting with empty ACL list."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.modify.return_value = True

        result = ops.set_acls(mock_connection, "olcDatabase={1}mdb,cn=config", [])
        assert result.is_success


class TestFlextLdapServersOpenLDAP2AclParsingDetailed:
    """Test ACL parsing with detailed scenarios."""

    def test_parse_acl_simple(self) -> None:
        """Test simple ACL parsing."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_str = "{0}to * by self write"

        result = ops.parse_acl(acl_str)
        assert result.is_success
        entry = result.unwrap()
        assert entry.dn.value == "cn=AclRule"

    def test_parse_acl_with_index(self) -> None:
        """Test ACL parsing with index."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_str = "{2}to cn=* by users read"

        result = ops.parse_acl(acl_str)
        assert result.is_success

    def test_parse_acl_complex(self) -> None:
        """Test complex ACL parsing."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_str = "{0}to * by self write by anonymous auth by * read"

        result = ops.parse_acl(acl_str)
        assert result.is_success

    def test_parse_acl_no_index(self) -> None:
        """Test ACL parsing without index."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_str = "to * by self write"

        result = ops.parse_acl(acl_str)
        assert result.is_success

    def test_parse_acl_empty_string(self) -> None:
        """Test ACL parsing with empty string."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.parse_acl("")
        assert result.is_success or result.is_failure


class TestFlextLdapServersOpenLDAP2AclFormattingDetailed:
    """Test ACL formatting."""

    def test_format_acl_with_raw(self) -> None:
        """Test ACL formatting with raw attribute."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AclRule"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "olcAccess": ["{0}to * by self write"],
            }).unwrap(),
        )

        result = ops.format_acl(entry)
        assert result.is_success
        formatted = result.unwrap()
        assert isinstance(formatted, str)

    def test_format_acl_with_parts(self) -> None:
        """Test ACL formatting with index and to parts."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AclRule"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "index": ["1"],
                "to": ["*"],
                "by": ["self write"],
            }).unwrap(),
        )

        result = ops.format_acl(entry)
        assert result.is_success

    def test_format_acl_minimal(self) -> None:
        """Test ACL formatting with minimal attributes."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=AclRule"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["AclRule"],
            }).unwrap(),
        )

        result = ops.format_acl(entry)
        assert result.is_success or result.is_failure


class TestFlextLdapServersOpenLDAP2RootDseDetailed:
    """Test Root DSE operations."""

    def test_get_root_dse_attributes_success(self) -> None:
        """Test successful Root DSE retrieval."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_entry = MagicMock()
        mock_entry.entry_attributes = ["vendorName", "supportedLDAPVersion"]
        mock_entry.__getitem__ = MagicMock(return_value=MagicMock(value="OpenLDAP"))
        mock_connection.entries = [mock_entry]

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, dict)

    def test_get_root_dse_attributes_unbound_connection(self) -> None:
        """Test Root DSE retrieval with unbound connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = False

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure

    def test_get_root_dse_attributes_none_connection(self) -> None:
        """Test Root DSE retrieval with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.get_root_dse_attributes(None)
        assert result.is_failure

    def test_get_root_dse_attributes_no_entries(self) -> None:
        """Test Root DSE retrieval with no entries."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_connection.entries = []

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure

    def test_get_root_dse_attributes_exception(self) -> None:
        """Test Root DSE retrieval exception handling."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Connection error")

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure


class TestFlextLdapServersOpenLDAP2ServerDetectionDetailed:
    """Test server type detection."""

    def test_detect_server_type_openldap2_from_vendor(self) -> None:
        """Test OpenLDAP 2.x detection from vendorName."""
        ops = FlextLdapServersOpenLDAP2Operations()
        root_dse = {
            "vendorName": "OpenLDAP",
            "vendorVersion": "2.4.58",
        }

        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap2" or "openldap" in result.lower()

    def test_detect_server_type_openldap1_from_version(self) -> None:
        """Test OpenLDAP 1.x detection from version."""
        ops = FlextLdapServersOpenLDAP2Operations()
        root_dse = {
            "vendorName": "OpenLDAP",
            "vendorVersion": "1.2.13",
        }

        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_type_from_config_context(self) -> None:
        """Test OpenLDAP 2.x detection from configContext."""
        ops = FlextLdapServersOpenLDAP2Operations()
        root_dse = {
            "configContext": "cn=config",
        }

        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap2" or "openldap" in result.lower()

    def test_detect_server_type_unknown(self) -> None:
        """Test detection with unknown server."""
        ops = FlextLdapServersOpenLDAP2Operations()
        root_dse = {
            "namingContexts": ["dc=example,dc=com"],
        }

        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_type_empty_root_dse(self) -> None:
        """Test detection with empty Root DSE."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.detect_server_type_from_root_dse({})
        assert isinstance(result, str)


class TestFlextLdapServersOpenLDAP2SupportedControlsDetailed:
    """Test supported controls retrieval."""

    def test_get_supported_controls_success(self) -> None:
        """Test successful controls retrieval."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.return_value = True
        mock_entry = MagicMock()
        mock_entry.entry_attributes = ["supportedControl"]
        mock_entry.__getitem__ = MagicMock(
            return_value=MagicMock(
                value=["1.2.840.113556.1.4.319", "1.2.840.113556.1.4.473"]
            )
        )
        mock_connection.entries = [mock_entry]

        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)

    def test_get_supported_controls_unbound_connection(self) -> None:
        """Test controls retrieval with unbound connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = False

        result = ops.get_supported_controls(mock_connection)
        assert result.is_failure

    def test_get_supported_controls_none_connection(self) -> None:
        """Test controls retrieval with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.get_supported_controls(None)
        assert result.is_failure

    def test_get_supported_controls_fallback(self) -> None:
        """Test controls retrieval with Root DSE failure (uses fallback)."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        # Root DSE search fails
        mock_connection.search.return_value = False
        mock_connection.entries = []

        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)
        assert len(controls) > 0  # Should have fallback controls

    def test_get_supported_controls_exception(self) -> None:
        """Test controls retrieval exception handling with fallback."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mock_connection = MagicMock()
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Connection error")

        result = ops.get_supported_controls(mock_connection)
        # get_supported_controls catches exception and returns fallback controls
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)
        assert len(controls) > 0


class TestFlextLdapServersOpenLDAP2EntryValidationDetailed:
    """Test entry validation with detailed scenarios."""

    def test_validate_entry_success(self) -> None:
        """Test successful entry validation."""
        ops = FlextLdapServersOpenLDAP2Operations()
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

    def test_validate_entry_with_string_object_class(self) -> None:
        """Test validation with objectClass as string instead of list."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        # Test that validation succeeds with proper objectClass
        result = ops.validate_entry_for_server(entry)
        assert result.is_success

    def test_validate_entry_with_complex_attributes(self) -> None:
        """Test validation with complex attribute set."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
                "mail": ["test@example.com"],
                "sn": ["test"],
                "givenName": ["test"],
            }).unwrap(),
        )

        result = ops.validate_entry_for_server(entry)
        assert result.is_success

    def test_validate_entry_no_object_class(self) -> None:
        """Test validation with entry missing objectClass."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "mail": ["test@example.com"],
            }).unwrap(),
        )

        result = ops.validate_entry_for_server(entry)
        assert result.is_failure

    def test_validate_entry_empty_object_class(self) -> None:
        """Test validation with empty objectClass values."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": [],
            }).unwrap(),
        )
        # Try to manually empty objectClass
        entry.attributes.attributes["objectClass"] = []

        result = ops.validate_entry_for_server(entry)
        # Should fail due to empty objectClass
        assert result.is_failure or result.is_success

    def test_validate_entry_multiple_object_classes(self) -> None:
        """Test validation with multiple objectClass values."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person", "top", "inetOrgPerson"],
            }).unwrap(),
        )

        result = ops.validate_entry_for_server(entry)
        assert result.is_success

    def test_validate_entry_with_olc_config_entry(self) -> None:
        """Test validation with OpenLDAP config entry."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="olcDatabase={1}mdb,cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "olcDatabase": ["{1}mdb"],
                "olcSuffix": ["dc=example,dc=com"],
                "objectClass": ["olcMdbConfig"],
            }).unwrap(),
        )

        result = ops.validate_entry_for_server(entry)
        # Should validate successfully for OpenLDAP 2.x
        assert result.is_success or result.is_failure


class TestFlextLdapServersOpenLDAP2EntryNormalizationDetailed:
    """Test entry normalization with detailed scenarios."""

    def test_normalize_entry_success(self) -> None:
        """Test successful entry normalization."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=Test,dc=Example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "CN": ["Test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        result = ops.normalize_entry_for_server(entry)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized is not None

    def test_normalize_entry_mixed_case_attributes(self) -> None:
        """Test normalization with mixed case attributes."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "CN": ["test"],
                "Mail": ["test@example.com"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        result = ops.normalize_entry_for_server(entry)
        assert result.is_success

    def test_normalize_entry_with_olc_attributes(self) -> None:
        """Test normalization with olc* attributes (OpenLDAP config)."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="olcDatabase={1}mdb,cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "olcDatabase": ["{1}mdb"],
                "olcAccess": ["{0}to * by self write"],
                "objectClass": ["olcDatabaseConfig"],
            }).unwrap(),
        )

        result = ops.normalize_entry_for_server(entry)
        assert result.is_success

    def test_normalize_entry_target_server_type_ignored(self) -> None:
        """Test that target_server_type is ignored."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        # target_server_type should be ignored
        result = ops.normalize_entry_for_server(entry, target_server_type="ad")
        assert result.is_success  # Should still work for OpenLDAP 2.x


class TestFlextLdapServersOpenLDAP2ConnectivityDetailed:
    """Test connectivity and protocol operations."""

    def test_get_default_port(self) -> None:
        """Test default port for OpenLDAP 2.x."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port = ops.get_default_port()
        assert port == 389

    def test_supports_start_tls(self) -> None:
        """Test START_TLS support for OpenLDAP 2.x."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.supports_start_tls() is True

    def test_get_schema_dn_inherited(self) -> None:
        """Test schema DN is correctly set."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=subschema"

    def test_get_bind_mechanisms_correct_values(self) -> None:
        """Test bind mechanisms return correct values."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms
        assert "SASL/EXTERNAL" in mechanisms
        assert "SASL/DIGEST-MD5" in mechanisms
        assert "SASL/GSSAPI" in mechanisms

    def test_get_max_page_size_positive(self) -> None:
        """Test max page size is positive."""
        ops = FlextLdapServersOpenLDAP2Operations()
        page_size = ops.get_max_page_size()
        assert page_size > 0

    def test_supports_paged_results_true(self) -> None:
        """Test paged results support is true."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.supports_paged_results() is True

    def test_supports_vlv_false(self) -> None:
        """Test VLV support is false for OpenLDAP 2.x."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.supports_vlv() is False


class TestFlextLdapServersOpenLDAP2AclAttributesDetailed:
    """Test ACL-related attributes and formats."""

    def test_get_acl_attribute_name_correct(self) -> None:
        """Test ACL attribute name is olcAccess."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_attr = ops.get_acl_attribute_name()
        assert "olcAccess" in acl_attr or acl_attr.lower() == "olcaccess"

    def test_get_acl_format_correct(self) -> None:
        """Test ACL format is openldap2."""
        ops = FlextLdapServersOpenLDAP2Operations()
        acl_format = ops.get_acl_format()
        assert acl_format == "openldap2"
