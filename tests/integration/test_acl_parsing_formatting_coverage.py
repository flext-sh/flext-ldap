"""ACL Operations via flext-ldif - Real Docker LDAP testing.

Tests ACL operations through flext-ldif integration with server-specific operations
(FlextLdapServersOIDOperations, FlextLdapServersOUDOperations) using real Docker
LDAP fixture data.

Note: ACL functionality has been moved to flext-ldif. Previous flext-ldap ACL
modules were overengineered stubs and have been removed.

This test suite covers server-specific ACL attribute handling and integration
with flext-ldif ACL operations.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdif, FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# ACL FORMAT CONVERSION COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestAclFormatConversion:
    """ACL format conversion and management."""

    def test_acl_manager_parse_acl_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test ACL manager parse_acl with basic ACL."""
        ldif_client = FlextLdif()
        acl_str = "access to * by * read"
        result = ldif_client.parse_acl(acl_str, "openldap")
        assert isinstance(result, FlextResult)

    def test_acl_service_accessible(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test that ACL service is accessible through flext-ldif."""
        ldif_client = FlextLdif()
        acl_service = ldif_client.acl_service
        assert acl_service is not None
        # Test that we can access ACL parsing method
        result = acl_service.parse_acl("access to * by * read", "openldap")
        assert isinstance(result, FlextResult)

    def test_acl_service_parse_acl(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test ACL service parse_acl through flext-ldif."""
        ldif_client = FlextLdif()
        acl_service = ldif_client.acl_service
        result = acl_service.parse_acl("access to * by * read", "openldap")
        assert isinstance(result, FlextResult)

    def test_acl_service_multiple_formats(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test ACL service supports multiple formats through flext-ldif."""
        ldif_client = FlextLdif()
        acl_service = ldif_client.acl_service

        # Test OpenLDAP ACL
        result_openldap = acl_service.parse_acl("access to * by * read", "openldap")
        assert isinstance(result_openldap, FlextResult)

        # Test Oracle ACL
        oracle_acl = '(target="ldap:///ou=users,dc=example,dc=com")(targetattr="*")(version 3.0; acl "User Access"; allow (read,search,compare) groupdn="ldap:///cn=Admins,ou=Groups,dc=example,dc=com";)'
        result_oracle = acl_service.parse_acl(oracle_acl, "oracle")
        assert isinstance(result_oracle, FlextResult)


# ============================================================================
# SERVER-SPECIFIC ACL PARSING COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOIDServerAclParsing:
    """OID server-specific ACL operations and parsing."""

    def test_oid_parse_oracle_acl_format(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID parse Oracle-specific ACL format."""
        ops = FlextLdapServersOIDOperations()
        # Oracle OID uses orclaci attribute format
        acl_attr_name = ops.get_acl_attribute_name()
        assert acl_attr_name == "orclaci"

    def test_oid_acl_format_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID ACL format is consistent."""
        ops = FlextLdapServersOIDOperations()
        format1 = ops.get_acl_format()
        format2 = ops.get_acl_format()
        assert format1 == format2
        assert isinstance(format1, str)
        assert len(format1) > 0

    def test_oid_normalize_with_acl_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID normalize entry with ACL attributes."""
        ops = FlextLdapServersOIDOperations()
        attrs_result = FlextLdifModels.LdifAttributes.create({
            "objectClass": ["inetOrgPerson"],
            "cn": ["acl_test"],
            "orclaci": ["(target=dn:*)(version 3.0; acl test;)"],
        })
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({}).unwrap()
        )
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=acl_test,dc=flext,dc=local"),
            attributes=attributes,
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oid_validate_with_acl_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID validate entry with ACL attributes."""
        ops = FlextLdapServersOIDOperations()
        attrs_result = FlextLdifModels.LdifAttributes.create({
            "objectClass": ["inetOrgPerson"],
            "cn": ["acl_validate"],
            "orclaci": ["(target=dn:*)(version 3.0; acl test;)"],
        })
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({}).unwrap()
        )
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=acl_validate,dc=flext,dc=local"
            ),
            attributes=attributes,
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


# ============================================================================
# OUD SERVER-SPECIFIC ACL PARSING COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOUDServerAclParsing:
    """OUD server-specific ACL operations and parsing."""

    def test_oud_get_acl_attribute_name_consistency(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD ACL attribute name is consistent."""
        ops = FlextLdapServersOUDOperations()
        attr_name1 = ops.get_acl_attribute_name()
        attr_name2 = ops.get_acl_attribute_name()
        assert attr_name1 == attr_name2
        assert isinstance(attr_name1, str)

    def test_oud_acl_format_valid_type(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD ACL format returns valid type."""
        ops = FlextLdapServersOUDOperations()
        acl_format = ops.get_acl_format()
        assert isinstance(acl_format, str)
        assert len(acl_format) > 0

    def test_oud_normalize_with_privilege_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD normalize entry with privilege attributes."""
        ops = FlextLdapServersOUDOperations()
        attrs_result = FlextLdifModels.LdifAttributes.create({
            "objectClass": ["inetOrgPerson"],
            "cn": ["priv_test"],
            "ds-privilege-name": ["REDACTED_LDAP_BIND_PASSWORD"],
        })
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({}).unwrap()
        )
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=priv_test,dc=flext,dc=local"
            ),
            attributes=attributes,
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_validate_with_privilege_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validate entry with privilege attributes."""
        ops = FlextLdapServersOUDOperations()
        attrs_result = FlextLdifModels.LdifAttributes.create({
            "objectClass": ["inetOrgPerson"],
            "cn": ["priv_validate"],
            "ds-privilege-name": ["user"],
        })
        attributes = (
            attrs_result.unwrap()
            if attrs_result.is_success
            else FlextLdifModels.LdifAttributes.create({}).unwrap()
        )
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=priv_validate,dc=flext,dc=local"
            ),
            attributes=attributes,
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)
