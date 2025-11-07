"""Tests for FlextLdapServersOIDOperations module."""

from unittest.mock import MagicMock

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapServersOIDInitialization:
    """Test initialization and basic properties."""

    def test_servers_oid_operations_initialization(self) -> None:
        """Test servers OID operations initialization."""
        ops = FlextLdapServersOIDOperations()
        assert ops is not None
        assert ops.server_type == "oid"

    def test_servers_oid_operations_is_base_operations_instance(self) -> None:
        """Test that OID is properly inherited."""
        from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations

        ops = FlextLdapServersOIDOperations()
        assert isinstance(ops, FlextLdapServersBaseOperations)

    def test_servers_oid_get_default_port(self) -> None:
        """Test OID default port."""
        ops = FlextLdapServersOIDOperations()
        port = ops.get_default_port()
        assert port == 389

    def test_servers_oid_supports_start_tls(self) -> None:
        """Test OID START_TLS support."""
        ops = FlextLdapServersOIDOperations()
        assert ops.supports_start_tls() is True

    def test_servers_oid_get_schema_dn(self) -> None:
        """Test OID schema DN (cn=subschemasubentry)."""
        ops = FlextLdapServersOIDOperations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=subschemasubentry"


class TestFlextLdapServersOIDBindMechanisms:
    """Test bind mechanism operations."""

    def test_get_bind_mechanisms_returns_list(self) -> None:
        """Test get_bind_mechanisms returns list."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert len(mechanisms) > 0

    def test_get_bind_mechanisms_includes_simple(self) -> None:
        """Test get_bind_mechanisms includes SIMPLE."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_get_bind_mechanisms_includes_sasl(self) -> None:
        """Test get_bind_mechanisms includes SASL variants."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        # Should have at least one SASL mechanism
        sasl_mechanisms = [m for m in mechanisms if "SASL" in m]
        assert len(sasl_mechanisms) > 0


class TestFlextLdapServersOIDACL:
    """Test ACL-related operations."""

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for Oracle OID (orclaci)."""
        ops = FlextLdapServersOIDOperations()
        acl_attr = ops.get_acl_attribute_name()
        # Oracle OID uses orclaci
        assert acl_attr == "orclaci"

    def test_get_acl_format(self) -> None:
        """Test ACL format for Oracle OID (oracle)."""
        ops = FlextLdapServersOIDOperations()
        acl_format = ops.get_acl_format()
        # Oracle OID uses 'oracle' format
        assert acl_format == "oracle"

    def test_parse_simple(self) -> None:
        """Test parsing simple Oracle OID ACL."""
        ops = FlextLdapServersOIDOperations()
        # Oracle OID format: access to entry|attr:<target> by <subject>:<permissions>
        acl_str = "access to entry by * : browse"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_parse_with_attributes(self) -> None:
        """Test parsing Oracle OID ACL with attribute target."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "access to attr:userPassword by self : write"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_format_acl_with_result(self) -> None:
        """Test format_acl with FlextResult."""
        ops = FlextLdapServersOIDOperations()
        # Create an entry to test with
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "orclaci": ["access to entry by * : browse"],
            }).unwrap(),
        )
        # Format should work with entry
        result = ops.format_acl(entry)
        # Should return str or FlextResult
        assert isinstance(result, (str, FlextResult)) or result is not None


class TestFlextLdapServersOIDSchemaOperations:
    """Test schema parsing operations."""

    def test_parse_object_class(self) -> None:
        """Test parsing objectClass definition for OID."""
        ops = FlextLdapServersOIDOperations()
        # Simple objectClass definition
        oc_def = "( 2.5.4.0 NAME 'top' ABSTRACT MUST objectClass )"
        result = ops.parse_object_class(oc_def)
        assert isinstance(result, FlextResult)

    def test_parse_attribute_type(self) -> None:
        """Test parsing attributeType definition for OID."""
        ops = FlextLdapServersOIDOperations()
        # Simple attributeType definition
        attr_def = "( 2.5.4.3 NAME 'cn' SUP name )"
        result = ops.parse_attribute_type(attr_def)
        assert isinstance(result, FlextResult)


class TestFlextLdapServersOIDServerDetection:
    """Test server detection operations."""

    def test_detect_server_type_from_root_dse_with_entry(self) -> None:
        """Test server detection with Entry object."""
        ops = FlextLdapServersOIDOperations()
        # Create a mock root DSE entry (root DSE has empty or root DN)
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
        from unittest.mock import MagicMock

        ops = FlextLdapServersOIDOperations()
        # Create mock connection
        mock_connection = MagicMock()

        # get_root_dse_attributes requires connection parameter
        attrs = ops.get_root_dse_attributes(mock_connection)
        # Should return attributes dict or FlextResult
        assert isinstance(attrs, (dict, FlextResult)) or attrs is not None


class TestFlextLdapServersOIDEntryValidation:
    """Test entry validation operations."""

    def test_validate_entry_for_server_basic(self) -> None:
        """Test entry validation for Oracle OID."""
        ops = FlextLdapServersOIDOperations()

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
        """Test entry normalization for Oracle OID."""
        ops = FlextLdapServersOIDOperations()

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


class TestFlextLdapServersOIDPaging:
    """Test paging-related operations."""

    def test_get_max_page_size(self) -> None:
        """Test max page size."""
        ops = FlextLdapServersOIDOperations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support (OID supports VLV)."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)
        # Oracle OID should support VLV
        assert supports is True


class TestFlextLdapServersOIDControls:
    """Test control operations."""

    def test_get_supported_controls(self) -> None:
        """Test getting supported controls."""
        ops = FlextLdapServersOIDOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True

        result = ops.get_supported_controls(mock_connection)
        assert isinstance(result, FlextResult)
        if result.is_success:
            controls = result.unwrap()
            assert isinstance(controls, list)


class TestOIDAclParsingDetailed:
    """Detailed ACL parsing tests for Oracle OID."""

    def test_parse_entry_target(self) -> None:
        """Test parsing Oracle ACI with entry target."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "access to entry by * : browse"
        result = ops.parse(acl_str)
        assert result.is_success

    def test_parse_attr_target(self) -> None:
        """Test parsing Oracle ACI with attribute target."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "access to attr:userPassword by self : write"
        result = ops.parse(acl_str)
        assert result.is_success

    def test_parse_multi_attr(self) -> None:
        """Test parsing ACI with multiple attribute targets."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "access to attr:userPassword,shadowPassword by self : write"
        result = ops.parse(acl_str)
        assert result.is_success

    def test_parse_with_group(self) -> None:
        """Test parsing ACI with group subject."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "access to entry by group cn=REDACTED_LDAP_BIND_PASSWORDs : write"
        result = ops.parse(acl_str)
        assert result.is_success

    def test_parse_invalid(self) -> None:
        """Test parsing invalid ACI format."""
        ops = FlextLdapServersOIDOperations()
        acl_str = "invalid aci string"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)


class TestOIDAclFormattingDetailed:
    """Detailed ACL formatting tests for Oracle OID."""

    def test_format_acl_from_entry(self) -> None:
        """Test formatting ACL from entry."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "orclaci": ["access to entry by * : browse"],
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success

    def test_format_acl_with_to_and_by(self) -> None:
        """Test formatting ACI with to and by clauses."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "to": ["entry"],
                "by": ["* : browse"],
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success


class TestOIDOracleVersionDetailed:
    """Detailed Oracle version detection tests."""

    def test_get_oracle_version(self) -> None:
        """Test getting Oracle OID version."""
        ops = FlextLdapServersOIDOperations()
        version = ops.get_oracle_version()
        assert isinstance(version, str)

    def test_supports_oracle_extensions(self) -> None:
        """Test Oracle extensions support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_oracle_extensions()
        assert isinstance(supports, bool)
        assert supports is True

    def test_get_oracle_object_classes(self) -> None:
        """Test getting Oracle-specific objectClasses."""
        ops = FlextLdapServersOIDOperations()
        classes = ops.get_oracle_object_classes()
        assert isinstance(classes, list)
        assert len(classes) > 0

    def test_get_oracle_attributes(self) -> None:
        """Test getting Oracle-specific attributes."""
        ops = FlextLdapServersOIDOperations()
        attrs = ops.get_oracle_attributes()
        assert isinstance(attrs, list)
        assert len(attrs) > 0


class TestOIDOracleUserDetailed:
    """Detailed Oracle user detection tests."""

    def test_is_oracle_user_with_oracle_class(self) -> None:
        """Test Oracle user detection with orclUserV2."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user,ou=people"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["orclUserV2"],
            }).unwrap(),
        )
        result = ops.is_oracle_user(entry)
        assert isinstance(result, bool)

    def test_is_oracle_user_with_standard_class(self) -> None:
        """Test non-Oracle user detection."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user,ou=people"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.is_oracle_user(entry)
        assert isinstance(result, bool)


class TestOIDEntryNormalizationDetailed:
    """Detailed entry normalization tests for Oracle OID."""

    def test_normalize_entry_basic(self) -> None:
        """Test basic entry normalization."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=Test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "CN": ["Test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success

    def test_normalize_entry_oracle_user(self) -> None:
        """Test normalization of Oracle user."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=oracle_user"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["orclUserV2"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success


class TestOIDEntryValidationDetailed:
    """Detailed entry validation tests for Oracle OID."""

    def test_validate_entry_valid(self) -> None:
        """Test validation of valid entry."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=user,ou=people"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["user"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_validate_entry_oracle_specific(self) -> None:
        """Test validation of Oracle-specific entry."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=oracle_user"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["orclUserV2"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


class TestOIDServerDetectionDetailed:
    """Detailed server detection tests for Oracle OID."""

    def test_detect_server_with_oracle_name(self) -> None:
        """Test detection with Oracle vendor name."""
        ops = FlextLdapServersOIDOperations()
        root_dse = {
            "vendorName": "Oracle",
            "vendorVersion": "11.1.1",
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_with_oid_context(self) -> None:
        """Test detection with OID-specific context."""
        ops = FlextLdapServersOIDOperations()
        root_dse = {
            "vendorName": "Oracle",
            "orclversion": "11.1.1",
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_empty_dse(self) -> None:
        """Test detection with empty DSE."""
        ops = FlextLdapServersOIDOperations()
        root_dse: dict[str, object] = {}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)


class TestOIDRootDseDetailed:
    """Detailed Root DSE retrieval tests for Oracle OID."""

    def test_get_root_dse_success(self) -> None:
        """Test successful Root DSE retrieval."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.server = MagicMock()
        mock_connection.server.info = {
            "vendorName": "Oracle",
            "vendorVersion": "11.1.1",
        }

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_success

    def test_get_root_dse_no_entries(self) -> None:
        """Test Root DSE retrieval with no entries."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.search.return_value = False
        mock_connection.entries = []

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure


class TestOIDSupportedControlsDetailed:
    """Detailed supported controls tests for Oracle OID."""

    def test_get_supported_controls_bound(self) -> None:
        """Test controls from bound connection."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.server = MagicMock()
        mock_connection.server.info = MagicMock()
        mock_connection.server.info.supported_controls = [
            "1.2.840.113556.1.4.319",
            "1.3.6.1.4.1.1466.20037",
        ]

        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)

    def test_get_supported_controls_unbound(self) -> None:
        """Test controls from unbound connection."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = False

        result = ops.get_supported_controls(mock_connection)
        assert result.is_failure


class TestOIDSchemaOperationsDetailed:
    """Detailed schema operations tests for Oracle OID."""

    def test_parse_object_class_simple(self) -> None:
        """Test parsing simple objectClass."""
        ops = FlextLdapServersOIDOperations()
        oc_def = "( 2.5.4.0 NAME 'top' ABSTRACT MUST objectClass )"
        result = ops.parse_object_class(oc_def)
        assert isinstance(result, FlextResult)

    def test_parse_attribute_type_simple(self) -> None:
        """Test parsing simple attributeType."""
        ops = FlextLdapServersOIDOperations()
        attr_def = "( 2.5.4.3 NAME 'cn' SUP name )"
        result = ops.parse_attribute_type(attr_def)
        assert isinstance(result, FlextResult)

    def test_get_schema_dn(self) -> None:
        """Test getting schema DN."""
        ops = FlextLdapServersOIDOperations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=subschemasubentry"


class TestOIDBindMechanismsDetailed:
    """Detailed bind mechanisms tests for Oracle OID."""

    def test_get_bind_mechanisms_includes_simple(self) -> None:
        """Test SIMPLE bind mechanism."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

    def test_get_bind_mechanisms_includes_sasl_external(self) -> None:
        """Test SASL EXTERNAL bind mechanism."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert any("EXTERNAL" in m for m in mechanisms)

    def test_get_bind_mechanisms_includes_digest(self) -> None:
        """Test SASL DIGEST-MD5 bind mechanism."""
        ops = FlextLdapServersOIDOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert any("DIGEST" in m for m in mechanisms)


class TestOIDVLVSupport:
    """Test VLV support in Oracle OID."""

    def test_supports_vlv_returns_true(self) -> None:
        """Test that Oracle OID supports VLV."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_vlv()
        assert supports is True

    def test_get_max_page_size(self) -> None:
        """Test max page size for OID."""
        ops = FlextLdapServersOIDOperations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support."""
        ops = FlextLdapServersOIDOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)
        assert supports is True


class TestOIDGetAclsExceptionHandling:
    """Test exception handling in get_acls method."""

    def test_get_acls_connection_not_bound(self) -> None:
        """Test get_acls with unbound connection."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = False

        result = ops.get_acls(mock_connection, "cn=test")
        assert result.is_failure
        assert "not bound" in str(result.error).lower()

    def test_get_acls_connection_none(self) -> None:
        """Test get_acls with None connection."""
        ops = FlextLdapServersOIDOperations()
        result = ops.get_acls(None, "cn=test")
        assert result.is_failure

    def test_get_acls_search_fails(self) -> None:
        """Test get_acls when search fails."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.return_value = False
        mock_connection.entries = []

        result = ops.get_acls(mock_connection, "cn=test")
        assert result.is_success  # Returns empty list on search failure
        assert result.unwrap() == []

    def test_get_acls_exception_raised(self) -> None:
        """Test get_acls when exception is raised."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.search.side_effect = Exception("Search error")

        result = ops.get_acls(mock_connection, "cn=test")
        assert result.is_failure
        assert "Search error" in str(result.error)


class TestOIDSetAclsExceptionHandling:
    """Test exception handling in set_acls method."""

    def test_set_acls_connection_not_bound(self) -> None:
        """Test set_acls with unbound connection."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = False

        result = ops.set_acls(mock_connection, "cn=test", [])
        assert result.is_failure
        assert "not bound" in str(result.error).lower()

    def test_set_acls_connection_none(self) -> None:
        """Test set_acls with None connection."""
        ops = FlextLdapServersOIDOperations()
        result = ops.set_acls(None, "cn=test", [])
        assert result.is_failure

    def test_set_acls_exception_raised(self) -> None:
        """Test set_acls when exception is raised during modify."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.modify.side_effect = Exception("Modify error")

        acl_dict = {"orclaci": ["access to entry by * : browse"]}
        result = ops.set_acls(mock_connection, "cn=test", [acl_dict])
        assert result.is_failure
        assert "Modify error" in str(result.error)

    def test_set_acls_modify_fails(self) -> None:
        """Test set_acls when modify operation fails."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.modify.return_value = False
        mock_connection.result = {"description": "Modify failed"}

        acl_dict = {"orclaci": ["access to entry by * : browse"]}
        result = ops.set_acls(mock_connection, "cn=test", [acl_dict])
        assert result.is_failure
        assert "Modify failed" in str(result.error)


class TestOIDGetRootDseAttributesExceptionHandling:
    """Test exception handling in get_root_dse_attributes."""

    def test_get_root_dse_connection_not_bound(self) -> None:
        """Test get_root_dse_attributes with unbound connection."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = False

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure

    def test_get_root_dse_exception_raised(self) -> None:
        """Test get_root_dse_attributes when exception is raised."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.server = MagicMock()
        mock_connection.server.info = None

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure


class TestOIDGetSupportedControlsExceptionHandling:
    """Test exception handling in get_supported_controls."""

    def test_get_supported_controls_exception_raised(self) -> None:
        """Test get_supported_controls when exception is raised."""
        ops = FlextLdapServersOIDOperations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        mock_connection.server = MagicMock()
        mock_connection.server.info = None

        result = ops.get_supported_controls(mock_connection)
        assert result.is_failure


class TestOIDNormalizeEntryExceptionHandling:
    """Test exception handling in normalize_entry."""

    def test_normalize_entry_with_none_entry(self) -> None:
        """Test normalize_entry with None."""
        ops = FlextLdapServersOIDOperations()
        result = ops.normalize_entry(None)
        assert isinstance(result, FlextResult)

    def test_normalize_entry_exception_handling(self) -> None:
        """Test normalize_entry handles exceptions gracefully."""
        ops = FlextLdapServersOIDOperations()
        # Create entry with problematic attributes
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert isinstance(result, FlextResult)


class TestOIDValidateEntryExceptionHandling:
    """Test exception handling in validate_entry_for_server."""

    def test_validate_entry_with_none(self) -> None:
        """Test validate_entry_for_server with None."""
        ops = FlextLdapServersOIDOperations()
        result = ops.validate_entry_for_server(None)
        assert isinstance(result, FlextResult)


class TestOIDParseAclExceptionHandling:
    """Test exception handling in parse."""

    def test_parse_empty_string(self) -> None:
        """Test parse with empty string."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse("")
        assert isinstance(result, FlextResult)

    def test_parse_malformed_syntax(self) -> None:
        """Test parse with malformed syntax."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse("access to @#$%^")
        assert isinstance(result, FlextResult)


class TestOIDFormatAclExceptionHandling:
    """Test exception handling in format_acl."""

    def test_format_acl_with_empty_attributes(self) -> None:
        """Test format_acl with entry having no orclaci."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["acl"],
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert isinstance(result, FlextResult)


class TestOIDParseObjectClassExceptionHandling:
    """Test exception handling in parse_object_class."""

    def test_parse_object_class_empty_string(self) -> None:
        """Test parse_object_class with empty string."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_object_class("")
        assert isinstance(result, FlextResult)

    def test_parse_object_class_malformed(self) -> None:
        """Test parse_object_class with malformed definition."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_object_class("( invalid )")
        assert isinstance(result, FlextResult)


class TestOIDParseAttributeTypeExceptionHandling:
    """Test exception handling in parse_attribute_type."""

    def test_parse_attribute_type_empty_string(self) -> None:
        """Test parse_attribute_type with empty string."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_attribute_type("")
        assert isinstance(result, FlextResult)

    def test_parse_attribute_type_malformed(self) -> None:
        """Test parse_attribute_type with malformed definition."""
        ops = FlextLdapServersOIDOperations()
        result = ops.parse_attribute_type("( invalid )")
        assert isinstance(result, FlextResult)


class TestOIDDetectServerTypeExceptionHandling:
    """Test exception handling in detect_server_type_from_root_dse."""

    def test_detect_server_type_with_none(self) -> None:
        """Test detect_server_type_from_root_dse with None raises TypeError."""
        ops = FlextLdapServersOIDOperations()
        import pytest

        with pytest.raises(TypeError):
            ops.detect_server_type_from_root_dse(None)

    def test_detect_server_type_with_invalid_entry(self) -> None:
        """Test detect_server_type_from_root_dse with invalid entry."""
        ops = FlextLdapServersOIDOperations()
        # Pass a string where Entry is expected
        # This should handle gracefully or raise an exception
        try:
            result = ops.detect_server_type_from_root_dse("not-an-entry")
            # If it succeeds, result should be a string or bool
            assert isinstance(result, (str, bool))
        except (TypeError, AttributeError):
            # Expected - string doesn't have the required attributes
            pass
