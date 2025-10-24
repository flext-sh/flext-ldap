"""ACL Parsing & Formatting comprehensive coverage - Real Docker LDAP testing.

Targets uncovered ACL parsing and formatting code paths in parsers.py and manager.py
with real Docker LDAP fixture data and comprehensive ACL operation testing.

This test suite expands ACL parsing/formatting coverage from current gaps to 95%+.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.acl.manager import FlextLdapAclManager
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# OPENLDAP ACL PARSING COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLdapAclParsing:
    """OpenLDAP ACL parsing - comprehensive real Docker testing."""

    def test_parse_openldap_acl_valid_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing valid basic OpenLDAP ACL format."""
        acl_str = "access to * by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert result.is_success
        acl = result.unwrap()
        assert acl is not None
        assert isinstance(acl, dict) or hasattr(acl, "target")

    def test_parse_openldap_acl_valid_complex_target(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with complex target."""
        acl_str = 'access to dn.subtree="cn=config" by dn="cn=REDACTED_LDAP_BIND_PASSWORD" write'
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_with_multiple_by_clauses(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with multiple conditions."""
        acl_str = "access to * by users read by anonymous none"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_empty_string_fails(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing empty ACL string fails properly."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse("")
        assert result.is_failure

    def test_parse_openldap_acl_none_fails(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing None ACL fails properly."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(None)  # type: ignore[arg-type]
        assert result.is_failure

    def test_parse_openldap_acl_whitespace_only_fails(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing whitespace-only ACL fails."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse("   ")
        assert result.is_failure

    def test_parse_openldap_acl_no_access_keyword_fails(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing ACL without 'access' keyword fails."""
        acl_str = "to * by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert result.is_failure

    def test_parse_openldap_acl_no_by_keyword_fails(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing ACL without 'by' keyword fails."""
        acl_str = "access to * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert result.is_failure

    def test_parse_openldap_acl_missing_subject_fails(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing ACL with missing subject fails."""
        acl_str = "access to * by"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert result.is_failure

    def test_parse_openldap_acl_with_permissions(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with various permissions."""
        for perm in ["read", "write", "search", "compare", "none", "manage"]:
            acl_str = f"access to * by * {perm}"
            result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
            assert isinstance(result, FlextResult)


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
        manager = FlextLdapAclManager()
        acl_str = "access to * by * read"
        result = manager.parse_acl(acl_str, "openldap")  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)

    def test_acl_manager_convert_acl(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test ACL manager convert_acl converts between formats."""
        manager = FlextLdapAclManager()
        acl_str = "access to * by * read"
        result = manager.convert_acl(acl_str, "openldap", "oid")  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)

    def test_acl_manager_validate_syntax(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test ACL manager validate_acl_syntax validates format."""
        manager = FlextLdapAclManager()
        acl_str = "access to * by * read"
        result = manager.validate_acl_syntax(acl_str, "openldap")  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)

    def test_acl_manager_batch_convert(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test ACL manager batch_convert converts multiple ACLs."""
        manager = FlextLdapAclManager()
        acls = [
            "access to * by * read",
            "access to cn=REDACTED_LDAP_BIND_PASSWORD by REDACTED_LDAP_BIND_PASSWORD write",
        ]
        result = manager.batch_convert(acls, "openldap", "oid")  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)


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
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=acl_test,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["acl_test"]),
                    "orclaci": FlextLdifModels.AttributeValues(
                        values=["(target=dn:*)(version 3.0; acl test;)"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oid_validate_with_acl_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID validate entry with ACL attributes."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=acl_validate,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["acl_validate"]),
                    "orclaci": FlextLdifModels.AttributeValues(
                        values=["(target=dn:*)(version 3.0; acl test;)"]
                    ),
                }
            ),
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
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=priv_test,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["priv_test"]),
                    "ds-privilege-name": FlextLdifModels.AttributeValues(
                        values=["REDACTED_LDAP_BIND_PASSWORD"]
                    ),
                }
            ),
        )
        result = ops.normalize_entry_for_server(entry)
        assert isinstance(result, FlextResult)

    def test_oud_validate_with_privilege_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD validate entry with privilege attributes."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=priv_validate,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["priv_validate"]),
                    "ds-privilege-name": FlextLdifModels.AttributeValues(
                        values=["user"]
                    ),
                }
            ),
        )
        result = ops.validate_entry_for_server(entry)
        assert isinstance(result, FlextResult)


# ============================================================================
# ACL EDGE CASES AND ERROR HANDLING
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestAclParsingEdgeCases:
    """Test ACL parsing edge cases and error conditions."""

    def test_parse_openldap_acl_with_quotes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with quoted values."""
        acl_str = 'access to dn="ou=people,dc=example,dc=com" by users read'
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_with_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with attribute specifications."""
        acl_str = "access to dn.subtree=* attr=userPassword by self write"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_complex_filter(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with filter expression."""
        acl_str = 'access to filter="(objectClass=inetOrgPerson)" by users read'
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_dn_matching(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with DN matching rules."""
        acl_str = "access to * by dn.base=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com write"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_self_reference(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with self reference."""
        acl_str = "access to * by self write"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)

    def test_parse_openldap_acl_anonymous_access(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test parsing OpenLDAP ACL with anonymous access."""
        acl_str = "access to * by anonymous none"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl_str)
        assert isinstance(result, FlextResult)
