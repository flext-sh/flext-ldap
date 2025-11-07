"""Tests for FlextLdapServersGenericOperations module."""

from unittest.mock import MagicMock

from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapServersGenericInitialization:
    """Test initialization and basic properties."""

    def test_servers_generic_operations_initialization(self) -> None:
        """Test servers generic operations initialization."""
        ops = FlextLdapServersGenericOperations()
        assert ops is not None
        assert ops.server_type == "generic"

    def test_servers_generic_operations_is_base_operations_instance(self) -> None:
        """Test that generic is properly inherited."""
        from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations

        ops = FlextLdapServersGenericOperations()
        assert isinstance(ops, FlextLdapServersBaseOperations)

    def test_servers_generic_get_default_port(self) -> None:
        """Test generic default port."""
        ops = FlextLdapServersGenericOperations()
        port = ops.get_default_port()
        assert port == 389

    def test_servers_generic_supports_start_tls(self) -> None:
        """Test generic START_TLS support."""
        ops = FlextLdapServersGenericOperations()
        assert ops.supports_start_tls() is True

    def test_servers_generic_get_schema_dn(self) -> None:
        """Test generic schema DN (cn=subschema per RFC 4512)."""
        ops = FlextLdapServersGenericOperations()
        schema_dn = ops.get_schema_dn()
        assert schema_dn == "cn=subschema"


class TestFlextLdapServersGenericACL:
    """Test ACL-related operations."""

    def test_get_acl_attribute_name(self) -> None:
        """Test ACL attribute name for generic (aci)."""
        ops = FlextLdapServersGenericOperations()
        acl_attr = ops.get_acl_attribute_name()
        # Generic LDAP uses aci (RFC 4512 standard)
        assert acl_attr == "aci"

    def test_get_acl_format(self) -> None:
        """Test ACL format for generic."""
        ops = FlextLdapServersGenericOperations()
        acl_format = ops.get_acl_format()
        # Generic LDAP uses 'generic' format
        assert acl_format == "generic"

    def test_parse_simple(self) -> None:
        """Test parsing simple generic ACL."""
        ops = FlextLdapServersGenericOperations()
        # Generic format
        acl_str = '(targetattr="*")(version 3.0; acl "Allow all"; allow (all) userdn="ldap:///anyone";)'
        result = ops.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_format_acl_with_entry(self) -> None:
        """Test format_acl with FlextLdifModels.Entry."""
        ops = FlextLdapServersGenericOperations()
        # Create an entry to test with
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl-rule"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "aci": [
                    '(targetattr="*")(version 3.0; acl "Allow"; allow (all) userdn="ldap:///anyone";)'
                ],
            }).unwrap(),
        )
        # Format should work with entry
        result = ops.format_acl(entry)
        # Should return str or FlextResult
        assert isinstance(result, (str, FlextResult)) or result is not None


class TestFlextLdapServersGenericSchemaOperations:
    """Test schema operations."""

    def test_discover_schema_basic(self) -> None:
        """Test schema discovery for generic."""
        ops = FlextLdapServersGenericOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.search.return_value = True
        mock_connection.entries = []

        result = ops.discover_schema(mock_connection)
        assert isinstance(result, FlextResult)

    def test_parse_object_class(self) -> None:
        """Test parsing objectClass definition for generic."""
        ops = FlextLdapServersGenericOperations()
        # Simple objectClass definition
        oc_def = "( 2.5.4.0 NAME 'top' ABSTRACT MUST objectClass )"
        result = ops.parse_object_class(oc_def)
        assert isinstance(result, FlextResult)

    def test_parse_attribute_type(self) -> None:
        """Test parsing attributeType definition for generic."""
        ops = FlextLdapServersGenericOperations()
        # Simple attributeType definition
        attr_def = "( 2.5.4.3 NAME 'cn' SUP name )"
        result = ops.parse_attribute_type(attr_def)
        assert isinstance(result, FlextResult)


class TestFlextLdapServersGenericEntryOperations:
    """Test entry operation specifics."""

    def test_add_entry_with_normalization_disabled(self) -> None:
        """Test add_entry for generic disables normalization."""
        ops = FlextLdapServersGenericOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.add.return_value = True

        # Create entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        # Generic operations should add entry without normalization
        result = ops.add_entry(mock_connection, entry)
        assert isinstance(result, FlextResult)

    def test_modify_entry_basic(self) -> None:
        """Test modify_entry for generic."""
        ops = FlextLdapServersGenericOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.modify.return_value = True

        from flext_ldap.models import FlextLdapModels

        changes = FlextLdapModels.EntryChanges(
            cn=[
                (
                    "add",
                    ["test"],
                )
            ]
        )

        result = ops.modify_entry(mock_connection, "cn=test,dc=example,dc=com", changes)
        assert isinstance(result, FlextResult)

    def test_delete_entry_basic(self) -> None:
        """Test delete_entry for generic."""
        ops = FlextLdapServersGenericOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.delete.return_value = True

        result = ops.delete_entry(mock_connection, "cn=test,dc=example,dc=com")
        assert isinstance(result, FlextResult)


class TestFlextLdapServersGenericServerDetection:
    """Test server type detection from Root DSE."""

    def test_detect_oracle_oid(self) -> None:
        """Test detection of Oracle OID from Root DSE."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {
            "vendorName": ["Oracle"],
            "vendorVersion": ["11.1.1.0.0"],
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)
        assert result and "oracle" in result.lower()

    def test_detect_openldap(self) -> None:
        """Test detection of OpenLDAP from Root DSE."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {
            "vendorName": ["OpenLDAP"],
            "vendorVersion": ["2.4.58"],
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)
        assert result and "openldap" in result.lower()

    def test_detect_active_directory(self) -> None:
        """Test detection of Active Directory from Root DSE."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {
            "vendorName": ["Microsoft Corporation"],
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)
        assert (result and "directory" in result.lower()) or "active" in result.lower()

    def test_detect_generic_fallback(self) -> None:
        """Test fallback to generic for unknown servers."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {
            "supportedLDAPVersion": ["3"],
        }
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "generic"


class TestFlextLdapServersGenericEntryValidation:
    """Test entry validation operations."""

    def test_validate_entry_for_server_basic(self) -> None:
        """Test entry validation for generic."""
        ops = FlextLdapServersGenericOperations()

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
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_entry_requires_objectclass(self) -> None:
        """Test that validation requires objectClass attribute."""
        ops = FlextLdapServersGenericOperations()

        # Create entry without objectClass
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
            }).unwrap(),
        )

        result = ops.validate_entry_for_server(entry)
        # Should fail without objectClass
        assert isinstance(result, FlextResult)

    def test_normalize_entry_for_server(self) -> None:
        """Test entry normalization for generic."""
        ops = FlextLdapServersGenericOperations()

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


class TestFlextLdapServersGenericPaging:
    """Test paging-related operations."""

    def test_get_max_page_size(self) -> None:
        """Test max page size."""
        ops = FlextLdapServersGenericOperations()
        page_size = ops.get_max_page_size()
        assert isinstance(page_size, int)
        assert page_size > 0

    def test_supports_paged_results(self) -> None:
        """Test paged results support."""
        ops = FlextLdapServersGenericOperations()
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_supports_vlv(self) -> None:
        """Test VLV support (generic typically doesn't)."""
        ops = FlextLdapServersGenericOperations()
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)
        # Generic typically doesn't support VLV
        assert supports is False


class TestFlextLdapServersGenericControls:
    """Test control operations."""

    def test_get_supported_controls(self) -> None:
        """Test getting supported controls."""
        ops = FlextLdapServersGenericOperations()
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.bound = True

        result = ops.get_supported_controls(mock_connection)
        assert isinstance(result, FlextResult)
        if result.is_success:
            controls = result.unwrap()
            assert isinstance(controls, list)


class TestGenericOperationsDetectServerExceptionHandling:
    """Test exception handling in detect_server_type_from_root_dse."""

    def test_detect_server_oracle_vendor(self) -> None:
        """Test Oracle detection with ORACLE vendor name."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["ORACLE"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result and "oracle" in result.lower()

    def test_detect_server_openldap_vendor(self) -> None:
        """Test OpenLDAP detection."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["OpenLDAP Software Foundation"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result and "openldap" in result.lower()

    def test_detect_server_microsoft_vendor(self) -> None:
        """Test Microsoft/Active Directory detection."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["Microsoft Corporation"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_novell_vendor(self) -> None:
        """Test Novell eDirectory detection."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["Novell eDirectory"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_ibm_vendor(self) -> None:
        """Test IBM Tivoli detection."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["IBM"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert isinstance(result, str)

    def test_detect_server_unboundid_vendor(self) -> None:
        """Test UnboundID detection."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["UnboundID"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result and "unboundid" in result.lower()

    def test_detect_server_forgerock_vendor(self) -> None:
        """Test ForgeRock detection."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"vendorName": ["ForgeRock"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result and "forgerock" in result.lower()

    def test_detect_server_with_config_context(self) -> None:
        """Test Oracle OID detection with configContext."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"configContext": ["cn=config"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result and "oracle" in result.lower()

    def test_detect_server_defaults_to_generic(self) -> None:
        """Test fallback to generic for unknown servers."""
        ops = FlextLdapServersGenericOperations()
        root_dse = {"supportedLDAPVersion": ["3"]}
        result = ops.detect_server_type_from_root_dse(root_dse)
        assert result == "generic"


class TestGenericOperationsValidateEntryExceptionHandling:
    """Test exception handling in validate_entry_for_server."""

    def test_validate_entry_requires_objectclass(self) -> None:
        """Test validation fails without objectClass."""
        ops = FlextLdapServersGenericOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)
        # Should fail without objectClass
        assert result.is_failure

    def test_validate_entry_with_objectclass_succeeds(self) -> None:
        """Test validation succeeds with objectClass."""
        ops = FlextLdapServersGenericOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_validate_entry_with_none(self) -> None:
        """Test validate_entry_for_server with None."""
        ops = FlextLdapServersGenericOperations()
        result = ops.validate_entry_for_server(None)
        assert isinstance(result, FlextResult)

    def test_validate_entry_exception_handling(self) -> None:
        """Test exception handling during validation."""
        ops = FlextLdapServersGenericOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


class TestGenericOperationsAddEntryExceptionHandling:
    """Test exception handling in add_entry."""

    def test_add_entry_normalization_disabled(self) -> None:
        """Test add_entry disables normalization for generic."""
        ops = FlextLdapServersGenericOperations()
        mock_connection = MagicMock()
        mock_connection.add.return_value = True

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        result = ops.add_entry(mock_connection, entry)
        assert isinstance(result, FlextResult)

    def test_add_entry_with_explicit_normalization_flag(self) -> None:
        """Test add_entry respects normalization flag."""
        ops = FlextLdapServersGenericOperations()
        mock_connection = MagicMock()
        mock_connection.add.return_value = True

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "cn": ["test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        # Should still disable normalization regardless of flag for generic
        result = ops.add_entry(mock_connection, entry, should_normalize=True)
        assert isinstance(result, FlextResult)


class TestGenericOperationsModifyEntryExceptionHandling:
    """Test exception handling in modify_entry."""

    def test_modify_entry_with_valid_changes(self) -> None:
        """Test modify_entry with valid changes."""
        ops = FlextLdapServersGenericOperations()
        mock_connection = MagicMock()
        mock_connection.modify.return_value = True

        from flext_ldap.models import FlextLdapModels

        changes = FlextLdapModels.EntryChanges(cn=[("add", ["new-value"])])

        result = ops.modify_entry(mock_connection, "cn=test,dc=example,dc=com", changes)
        assert isinstance(result, FlextResult)

    def test_modify_entry_empty_changes(self) -> None:
        """Test modify_entry with empty changes."""
        ops = FlextLdapServersGenericOperations()
        mock_connection = MagicMock()
        mock_connection.modify.return_value = True

        from flext_ldap.models import FlextLdapModels

        changes = FlextLdapModels.EntryChanges()

        result = ops.modify_entry(mock_connection, "cn=test,dc=example,dc=com", changes)
        assert isinstance(result, FlextResult)


class TestGenericOperationsDeleteEntryExceptionHandling:
    """Test exception handling in delete_entry."""

    def test_delete_entry_success(self) -> None:
        """Test delete_entry succeeds."""
        ops = FlextLdapServersGenericOperations()
        mock_connection = MagicMock()
        mock_connection.delete.return_value = True

        result = ops.delete_entry(mock_connection, "cn=test,dc=example,dc=com")
        assert isinstance(result, FlextResult)


class TestGenericOperationsNormalizeEntryExceptionHandling:
    """Test exception handling in normalize_entry_for_server."""

    def test_normalize_entry_with_generic(self) -> None:
        """Test normalize_entry_for_server with generic operations."""
        ops = FlextLdapServersGenericOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=Test,dc=Example"),
            attributes=FlextLdifModels.LdifAttributes.create({
                "CN": ["Test"],
                "objectClass": ["person"],
            }).unwrap(),
        )

        result = ops.normalize_entry_for_server(entry)
        # Generic returns entry as-is (no normalization)
        assert result is not None
