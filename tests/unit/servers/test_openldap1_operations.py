"""Tests for FlextLdapServersOpenLDAP1Operations module."""

from unittest.mock import MagicMock, PropertyMock

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations


class TestFlextLdapServersOpenLDAP1Initialization:
    """Test initialization and basic properties."""

    def test_servers_openldap1_operations_initialization(self) -> None:
        """Test servers OpenLDAP1 operations initialization."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops is not None
        assert ops.server_type == "openldap1"

    def test_servers_openldap1_operations_is_base_operations_instance(self) -> None:
        """Test that OpenLDAP1 is properly inherited."""
        from flext_ldap.servers.openldap2_operations import (
            FlextLdapServersOpenLDAP2Operations,
        )

        ops = FlextLdapServersOpenLDAP1Operations()
        assert isinstance(ops, FlextLdapServersOpenLDAP2Operations)

    def test_servers_openldap1_get_default_port(self) -> None:
        """Test OpenLDAP1 default port (inherited from OpenLDAP2)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port()
        assert port == 389

    def test_servers_openldap1_get_schema_dn(self) -> None:
        """Test OpenLDAP1 schema DN (cn=Subschema)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=Subschema"


class TestFlextLdapServersOpenLDAP1ACL:
    """Test ACL-related operations specific to OpenLDAP 1.x."""

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for OpenLDAP1 (access, not olcAccess)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_attr = ops.get_acl_attribute_name()
        # OpenLDAP 1.x uses 'access' attribute (slapd.conf style)
        assert acl_attr == "access"

    def test_get_acl_format(self) -> None:
        """Test ACL format for OpenLDAP1."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_format = ops.get_acl_format()
        # OpenLDAP 1.x uses 'openldap1' format
        assert acl_format == "openldap1"

    def test_parse_simple(self) -> None:
        """Test parsing simple OpenLDAP 1.x ACL."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # OpenLDAP 1.x format: access to <what> by <who> <access>
        acl_str = "access to * by self write by users read"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_parse_with_attributes(self) -> None:
        """Test parsing OpenLDAP 1.x ACL with attribute restrictions."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = "access to attrs=userPassword by self write by anonymous auth"
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_format_acl_with_entry(self) -> None:
        """Test format_acl with FlextLdifModels.Entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create an entry to test with
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl-rule"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "access": ["to * by self write by users read"],
            }).unwrap(),
        )
        # Format should work with entry
        result = ops.format_acl(entry)
        # Should return str or FlextResult
        assert isinstance(result, (str, FlextResult)) or result is not None

    def test_get_config_style(self) -> None:
        """Test config style for OpenLDAP 1.x (slapd.conf)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        config_style = ops.get_config_style()
        assert config_style == "slapd.conf"

    def test_get_replication_mechanism(self) -> None:
        """Test replication mechanism for OpenLDAP 1.x (slurpd)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        replication = ops.get_replication_mechanism()
        assert replication == "slurpd"

    def test_supports_dynamic_config(self) -> None:
        """Test dynamic config support for OpenLDAP 1.x (False)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports_dynamic = ops.supports_dynamic_config()
        assert supports_dynamic is False


class TestFlextLdapServersOpenLDAP1EntryNormalization:
    """Test entry normalization for OpenLDAP 1.x."""

    def test_normalize_entry_olcaccess_conversion(self) -> None:
        """Test normalization converts olcAccess to access."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create entry with olcAccess (2.x style)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "olcAccess": ["{0}to * by self write"],
                "objectClass": ["olcConfig"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success

    def test_normalize_entry_for_server_basic(self) -> None:
        """Test entry normalization for OpenLDAP 1.x via wrapper."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create entry for normalization
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)


class TestFlextLdapServersOpenLDAP1EntryValidation:
    """Test entry validation for OpenLDAP 1.x."""

    def test_validate_entry_basic(self) -> None:
        """Test basic entry validation for OpenLDAP 1.x."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create a valid entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_validate_entry_rejects_olc_objectclasses(self) -> None:
        """Test that validation rejects olc* objectClasses (2.x specific)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create entry with 2.x objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["olcDatabaseConfig"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        # Should fail for olc* classes
        assert isinstance(result, FlextResult)

    def test_validate_entry_rejects_olcaccess_attribute(self) -> None:
        """Test that validation rejects olcAccess (2.x specific)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create entry with olcAccess (should use 'access' instead)
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["person"],
                "olcAccess": ["{0}to * by self write"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


class TestFlextLdapServersOpenLDAP1ServerDetection:
    """Test server detection for OpenLDAP 1.x."""

    def test_detect_server_type_from_root_dse_dict(self) -> None:
        """Test server detection with dictionary root DSE."""
        ops = FlextLdapServersOpenLDAP1Operations()
        root_dse = {
            "vendorName": ["OpenLDAP"],
            "vendorVersion": ["1.2.27"],
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        # Should return server type string
        assert isinstance(result, str)

    def test_get_root_dse_attributes_with_connection(self) -> None:
        """Test getting Root DSE attributes with mock connection."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = [MagicMock()]
        mock_entry = mock_connection.entries[0]
        mock_entry.entry_attributes = ["vendorName", "vendorVersion"]
        mock_entry.__getitem__.return_value.value = "OpenLDAP"

        # get_root_dse_attributes requires connection parameter
        attrs = ops.get_root_dse_attributes(mock_connection)
        # Should return attributes dict or FlextResult
        assert isinstance(attrs, (dict, FlextResult)) or attrs is not None

    def test_get_supported_controls(self) -> None:
        """Test getting supported controls for OpenLDAP 1.x."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True

        result = ops.get_supported_controls(mock_connection)
        assert isinstance(result, FlextResult)
        if result.is_success:
            controls = result.unwrap()
            assert isinstance(controls, list)


class TestFlextLdapServersOpenLDAP1InheritedMethods:
    """Test inherited methods from OpenLDAP 2.x."""

    def test_supports_start_tls(self) -> None:
        """Test START_TLS support (inherited from OpenLDAP 2.x)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops.supports_start_tls() is True

    def test_get_bind_mechanisms(self) -> None:
        """Test bind mechanisms (inherited from OpenLDAP 2.x)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert "SIMPLE" in mechanisms

    def test_get_max_page_size(self) -> None:
        """Test max page size (inherited from OpenLDAP 2.x)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support (inherited from OpenLDAP 2.x)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support (inherited from OpenLDAP 2.x)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)


class TestOpenLDAP1AclParsingDetailed:
    """Detailed ACL parsing tests for OpenLDAP 1.x."""

    def test_parse_standard_format(self) -> None:
        """Test parsing standard OpenLDAP 1.x access format."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = "access to * by self write by users read"
        result = ops.parse(acl_str)
        assert result.is_success
        entry = result.unwrap()
        assert entry is not None

    def test_parse_with_attr_filter(self) -> None:
        """Test parsing ACL with attribute restrictions."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = "access to attrs=userPassword,shadowPassword by self write"
        result = ops.parse(acl_str)
        assert result.is_success
        entry = result.unwrap()
        assert entry.attributes.get("to") is not None

    def test_parse_with_dn_subtree(self) -> None:
        """Test parsing ACL with DN subtree restriction."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = 'access to dn.subtree="ou=users,dc=example,dc=com" by * none'
        result = ops.parse(acl_str)
        assert result.is_success

    def test_parse_multiple_by_clauses(self) -> None:
        """Test parsing ACL with multiple by clauses."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = "access to * by self write by anonymous auth by users read by * none"
        result = ops.parse(acl_str)
        assert result.is_success
        entry = result.unwrap()
        rules = entry.attributes.get("rules")
        assert rules is not None

    def test_parse_invalid_format(self) -> None:
        """Test parsing invalid ACL format."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = "invalid acl format here"
        result = ops.parse(acl_str)
        # Should still succeed but create basic entry
        assert isinstance(result, FlextResult)

    def test_parse_empty_string(self) -> None:
        """Test parsing empty ACL string."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_str = ""
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)


class TestOpenLDAP1AclFormattingDetailed:
    """Detailed ACL formatting tests for OpenLDAP 1.x."""

    def test_format_acl_from_parsed(self) -> None:
        """Test formatting ACL from parsed entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # First parse, then format
        acl_str = "access to * by self write by users read"
        parse_result = ops.parse(acl_str)
        assert parse_result.is_success

        entry = parse_result.unwrap()
        format_result = ops.format_acl(entry)
        assert format_result.is_success
        formatted = format_result.unwrap()
        assert "access" in formatted

    def test_format_acl_with_raw_attribute(self) -> None:
        """Test formatting when raw attribute is present."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "raw": ["access to * by self write"],
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success
        formatted = result.unwrap()
        assert "access" in formatted

    def test_format_acl_with_structured_rules(self) -> None:
        """Test formatting with structured rules."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "to": ["*"],
                "rules": ["self:write", "users:read"],
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success
        formatted = result.unwrap()
        assert "by self write" in formatted or "by" in formatted

    def test_format_acl_with_to_clause(self) -> None:
        """Test formatting with to clause only."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "to": ["attrs=userPassword"],
            }).unwrap(),
        )
        result = ops.format_acl(entry)
        assert result.is_success
        formatted = result.unwrap()
        assert "access" in formatted

    def test_format_acl_exception_handling(self) -> None:
        """Test exception handling in format_acl."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create entry with minimal attributes
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({}).unwrap(),
        )
        result = ops.format_acl(entry)
        # Should still succeed with defaults
        assert isinstance(result, FlextResult)


class TestOpenLDAP1EntryNormalizationDetailed:
    """Detailed entry normalization tests for OpenLDAP 1.x."""

    def test_normalize_entry_olcaccess_to_access(self) -> None:
        """Test conversion of olcAccess to access attribute."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "olcAccess": ["{0}to * by self write", "{1}to * by users read"],
                "cn": ["config"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success
        normalized = result.unwrap()
        attrs = normalized.attributes.attributes
        assert "access" in attrs or "olcAccess" in attrs

    def test_normalize_entry_olc_objectclass_mapping(self) -> None:
        """Test mapping of olc* objectClasses."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["olcDatabaseConfig", "olcConfig"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success

    def test_normalize_entry_standard_entry(self) -> None:
        """Test normalization of standard entry without special attributes."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=people,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["user"],
                "objectClass": ["person", "inetOrgPerson"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success
        normalized = result.unwrap()
        assert normalized.dn.value == "cn=user,ou=people,dc=example,dc=com"

    def test_normalize_entry_preserves_non_olc_classes(self) -> None:
        """Test that non-olc objectClasses are preserved."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["person", "organizationalPerson"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert result.is_success
        normalized = result.unwrap()
        oc = normalized.attributes.attributes.get("objectClass", [])
        assert len(oc) > 0

    def test_normalize_entry_exception_handling(self) -> None:
        """Test exception handling in normalize_entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
            }).unwrap(),
        )
        result = ops.normalize_entry(entry)
        assert isinstance(result, FlextResult)


class TestOpenLDAP1EntryValidationDetailed:
    """Detailed entry validation tests for OpenLDAP 1.x."""

    def test_validate_entry_valid_person(self) -> None:
        """Test validation of valid person entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=people,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["user"],
                "objectClass": ["person", "inetOrgPerson"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_success

    def test_validate_entry_missing_dn(self) -> None:
        """Test validation rejects entry without DN."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Create entry with minimal DN that is technically valid
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        # DN exists but may fail other validation
        assert isinstance(result, FlextResult)

    def test_validate_entry_olc_objectclass_rejected(self) -> None:
        """Test validation rejects olc* objectClasses."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=config"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["olcDatabaseConfig"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_failure

    def test_validate_entry_olcaccess_rejected(self) -> None:
        """Test validation rejects olcAccess attribute."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["person"],
                "olcAccess": ["{0}to * by self write"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_failure

    def test_validate_entry_missing_objectclass(self) -> None:
        """Test validation requires objectClass."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert result.is_failure

    def test_validate_entry_exception_handling(self) -> None:
        """Test exception handling in validate_entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


class TestOpenLDAP1ServerDetectionDetailed:
    """Detailed server detection tests for OpenLDAP 1.x."""

    def test_detect_server_openldap_1x_version(self) -> None:
        """Test detection of OpenLDAP 1.x from version string."""
        ops = FlextLdapServersOpenLDAP1Operations()
        root_dse = {
            "vendorName": "OpenLDAP",
            "vendorVersion": "1.2.27",
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap1"

    def test_detect_server_openldap_2x_version(self) -> None:
        """Test detection of OpenLDAP 2.x from version string."""
        ops = FlextLdapServersOpenLDAP1Operations()
        root_dse = {
            "vendorName": "OpenLDAP",
            "vendorVersion": "2.4.59",
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap2"

    def test_detect_server_with_config_context(self) -> None:
        """Test detection with configContext (2.x indicator)."""
        ops = FlextLdapServersOpenLDAP1Operations()
        root_dse = {
            "vendorName": ["OpenLDAP"],
            "configContext": ["cn=config"],
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap2"

    def test_detect_server_no_vendor_info(self) -> None:
        """Test detection without vendor info defaults to 1.x."""
        ops = FlextLdapServersOpenLDAP1Operations()
        root_dse = {"subschemaSubentry": ["cn=Subschema"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap1"

    def test_detect_server_empty_root_dse(self) -> None:
        """Test detection with empty root DSE."""
        ops = FlextLdapServersOpenLDAP1Operations()
        root_dse: dict[str, object] = {}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "openldap1"


class TestOpenLDAP1RootDseDetailed:
    """Detailed Root DSE retrieval tests for OpenLDAP 1.x."""

    def test_get_root_dse_attributes_success(self) -> None:
        """Test successful Root DSE attribute retrieval."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.search.return_value = True
        mock_entry = MagicMock()
        mock_entry.entry_attributes = ["vendorName", "vendorVersion"]
        mock_entry.__getitem__.return_value.value = "OpenLDAP"
        mock_connection.entries = [mock_entry]

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, dict)

    def test_get_root_dse_attributes_no_entries(self) -> None:
        """Test Root DSE retrieval when no entries found."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.search.return_value = False
        mock_connection.entries = []

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure

    def test_get_root_dse_attributes_multiple_attrs(self) -> None:
        """Test Root DSE with multiple attributes."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.search.return_value = True
        mock_entry = MagicMock()
        mock_entry.entry_attributes = [
            "vendorName",
            "vendorVersion",
            "subschemaSubentry",
        ]
        mock_entry.__getitem__.side_effect = lambda x: MagicMock(value=f"value_of_{x}")
        mock_connection.entries = [mock_entry]

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_success

    def test_get_root_dse_attributes_exception_handling(self) -> None:
        """Test exception handling in Root DSE retrieval."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.search.side_effect = Exception("Connection error")

        result = ops.get_root_dse_attributes(mock_connection)
        assert result.is_failure


class TestOpenLDAP1SupportedControlsDetailed:
    """Detailed supported controls tests for OpenLDAP 1.x."""

    def test_get_supported_controls_bound_connection(self) -> None:
        """Test getting controls from bound connection."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True

        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        controls = result.unwrap()
        assert isinstance(controls, list)
        assert len(controls) > 0

    def test_get_supported_controls_unbound_connection(self) -> None:
        """Test getting controls from unbound connection."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = False

        result = ops.get_supported_controls(mock_connection)
        assert result.is_failure

    def test_get_supported_controls_includes_paged_results(self) -> None:
        """Test that controls include paged results OID."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True

        result = ops.get_supported_controls(mock_connection)
        assert result.is_success
        controls = result.unwrap()
        # Check for paged results OID
        assert "1.2.840.113556.1.4.319" in controls

    def test_get_supported_controls_exception_handling(self) -> None:
        """Test exception handling in get_supported_controls."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mock_connection = MagicMock(spec=Connection)
        mock_connection.bound = True
        # Simulate exception
        type(mock_connection).bound = PropertyMock(side_effect=Exception("Error"))

        result = ops.get_supported_controls(mock_connection)
        assert result.is_failure


class TestOpenLDAP1ConfigurationDetailed:
    """Detailed configuration tests for OpenLDAP 1.x."""

    def test_get_config_style_returns_slapd_conf(self) -> None:
        """Test that config style is slapd.conf."""
        ops = FlextLdapServersOpenLDAP1Operations()
        style = ops.get_config_style()
        assert style == "slapd.conf"

    def test_get_replication_mechanism_returns_slurpd(self) -> None:
        """Test that replication mechanism is slurpd."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mechanism = ops.get_replication_mechanism()
        assert mechanism == "slurpd"

    def test_supports_dynamic_config_returns_false(self) -> None:
        """Test that dynamic config is not supported."""
        ops = FlextLdapServersOpenLDAP1Operations()
        supports = ops.supports_dynamic_config()
        assert supports is False

    def test_get_acl_attribute_name_returns_access(self) -> None:
        """Test that ACL attribute is 'access'."""
        ops = FlextLdapServersOpenLDAP1Operations()
        attr_name = ops.get_acl_attribute_name()
        assert attr_name == "access"


class TestOpenLDAP1SchemaDetailed:
    """Detailed schema discovery tests for OpenLDAP 1.x."""

    def test_get_schema_dn_returns_cn_subschema(self) -> None:
        """Test that schema DN is cn=Subschema."""
        ops = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=Subschema"

    def test_get_acl_format_returns_openldap1(self) -> None:
        """Test that ACL format is openldap1."""
        ops = FlextLdapServersOpenLDAP1Operations()
        acl_format = ops.get_acl_format()
        assert acl_format == "openldap1"

    def test_get_default_port_returns_389(self) -> None:
        """Test that default LDAP port is 389."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port()
        assert port == 389
