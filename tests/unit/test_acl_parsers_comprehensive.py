"""Comprehensive tests for FlextLdapAclParsers class."""

import pytest
from flext_core import FlextResult
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.models import FlextLdapModels


class TestFlextLdapAclParsersOpenLdapAclParser:
    """Tests for FlextLdapAclParsers.OpenLdapAclParser class."""

    def test_parse_valid_openldap_acl(self) -> None:
        """Test parsing valid OpenLDAP ACL."""
        acl = "access to dn.base=\"cn=test\" by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, FlextLdapModels.UnifiedAcl)

    def test_parse_empty_acl_string(self) -> None:
        """Test parsing empty ACL string."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse("")
        assert result.is_failure
        assert result.error is not None
        assert "ACL string cannot be empty" in result.error

    def test_parse_whitespace_only_acl(self) -> None:
        """Test parsing whitespace-only ACL string."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse("   ")
        assert result.is_failure
        assert result.error is not None
        assert "ACL string cannot be empty" in result.error

    def test_parse_invalid_format_missing_access(self) -> None:
        """Test parsing ACL with missing 'access' keyword."""
        acl = "to dn.base=\"cn=test\" by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid OpenLDAP ACL format" in result.error

    def test_parse_invalid_format_missing_to(self) -> None:
        """Test parsing ACL with missing 'to' keyword."""
        acl = "access dn.base=\"cn=test\" by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid OpenLDAP ACL format" in result.error

    def test_parse_invalid_format_missing_by(self) -> None:
        """Test parsing ACL with missing 'by' keyword."""
        acl = "access to dn.base=\"cn=test\" * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid OpenLDAP ACL format" in result.error

    def test_parse_invalid_format_too_short(self) -> None:
        """Test parsing ACL with too few parts."""
        acl = "access to by"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid OpenLDAP ACL format" in result.error

    def test_parse_invalid_format_empty_subject_permissions(self) -> None:
        """Test parsing ACL with empty subject/permissions after 'by'."""
        acl = "access to dn.base=\"cn=test\" by"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid OpenLDAP ACL format" in result.error

    def test_parse_attrs_target(self) -> None:
        """Test parsing ACL with attrs= target."""
        acl = "access to attrs=mail,cn by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "attributes"
        assert "mail" in result.data.target.attributes
        assert "cn" in result.data.target.attributes

    def test_parse_dn_exact_target(self) -> None:
        """Test parsing ACL with dn.exact= target."""
        acl = "access to dn.exact=\"cn=test,dc=example,dc=com\" by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "entry"
        assert result.data.target.dn_pattern == "cn=test,dc=example,dc=com"

    def test_parse_default_target(self) -> None:
        """Test parsing ACL with default target."""
        acl = "access to * by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "entry"
        assert result.data.target.dn_pattern == "*"

    def test_parse_subject_self(self) -> None:
        """Test parsing ACL with 'self' subject."""
        acl = "access to dn.base=\"cn=test\" by self read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "self"

    def test_parse_subject_users(self) -> None:
        """Test parsing ACL with 'users' subject."""
        acl = "access to dn.base=\"cn=test\" by users read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "authenticated"

    def test_parse_subject_anonymous(self) -> None:
        """Test parsing ACL with 'anonymous' subject."""
        acl = "access to dn.base=\"cn=test\" by anonymous read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "anonymous"

    def test_parse_subject_wildcard(self) -> None:
        """Test parsing ACL with '*' subject."""
        acl = "access to dn.base=\"cn=test\" by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "anyone"

    def test_parse_subject_default(self) -> None:
        """Test parsing ACL with default subject type."""
        acl = "access to dn.base=\"cn=test\" by cn=REDACTED_LDAP_BIND_PASSWORD read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "user"

    def test_parse_permissions_single(self) -> None:
        """Test parsing ACL with single permission."""
        acl = "access to dn.base=\"cn=test\" by * read"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions

    def test_parse_permissions_multiple(self) -> None:
        """Test parsing ACL with multiple permissions."""
        acl = "access to dn.base=\"cn=test\" by * read,write,search"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions
        assert "search" in result.data.permissions.permissions

    def test_parse_permissions_default(self) -> None:
        """Test parsing ACL with no permissions (defaults to read)."""
        acl = "access to dn.base=\"cn=test\" by *"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions

    def test_parse_permissions_mapped(self) -> None:
        """Test parsing ACL with mapped permissions."""
        acl = "access to dn.base=\"cn=test\" by * add,delete,compare,auth"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "add" in result.data.permissions.permissions
        assert "delete" in result.data.permissions.permissions
        assert "compare" in result.data.permissions.permissions
        assert "auth" in result.data.permissions.permissions

    def test_parse_permissions_unknown_filtered(self) -> None:
        """Test parsing ACL with unknown permissions (should be filtered out)."""
        acl = "access to dn.base=\"cn=test\" by * read,unknown,write"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions
        assert "unknown" not in result.data.permissions.permissions

    def test_parse_exception_handling(self) -> None:
        """Test parsing ACL with exception handling."""
        # This should cause an exception due to invalid input
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(None)
        assert result.is_failure
        assert result.error is not None
        assert "Failed to parse OpenLDAP ACL:" in result.error


class TestFlextLdapAclParsersOracleAclParser:
    """Tests for FlextLdapAclParsers.OracleAclParser class."""

    def test_parse_valid_oracle_acl(self) -> None:
        """Test parsing valid Oracle ACL."""
        acl = "access to entry by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, FlextLdapModels.UnifiedAcl)

    def test_parse_empty_acl_string(self) -> None:
        """Test parsing empty ACL string."""
        result = FlextLdapAclParsers.OracleAclParser.parse("")
        assert result.is_failure
        assert result.error is not None
        assert "ACL string cannot be empty" in result.error

    def test_parse_whitespace_only_acl(self) -> None:
        """Test parsing whitespace-only ACL string."""
        result = FlextLdapAclParsers.OracleAclParser.parse("   ")
        assert result.is_failure
        assert result.error is not None
        assert "ACL string cannot be empty" in result.error

    def test_parse_invalid_format_too_short(self) -> None:
        """Test parsing ACL with too few parts."""
        acl = "access to by"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid Oracle ACL format" in result.error

    def test_parse_invalid_format_missing_access(self) -> None:
        """Test parsing ACL with missing 'access' keyword."""
        acl = "to entry by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required keywords in Oracle ACL" in result.error

    def test_parse_invalid_format_missing_to(self) -> None:
        """Test parsing ACL with missing 'to' keyword."""
        acl = "access entry by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required keywords in Oracle ACL" in result.error

    def test_parse_invalid_format_missing_by(self) -> None:
        """Test parsing ACL with missing 'by' keyword."""
        acl = "access to entry users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required keywords in Oracle ACL" in result.error

    def test_parse_entry_target(self) -> None:
        """Test parsing ACL with 'entry' target."""
        acl = "access to entry by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "entry"

    def test_parse_attrs_target(self) -> None:
        """Test parsing ACL with 'attrs=' target."""
        acl = "access to attrs=mail,cn by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "attributes"
        assert "mail" in result.data.target.attributes
        assert "cn" in result.data.target.attributes

    def test_parse_attr_target(self) -> None:
        """Test parsing ACL with 'attr=' target."""
        acl = "access to attr=(userPassword) by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "attributes"
        assert "userPassword" in result.data.target.attributes

    def test_parse_attr_target_no_parentheses(self) -> None:
        """Test parsing ACL with 'attr=' target without parentheses."""
        acl = "access to attr=userPassword by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "attributes"
        assert "userPassword" in result.data.target.attributes

    def test_parse_default_target(self) -> None:
        """Test parsing ACL with default target."""
        acl = "access to other by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "entry"

    def test_parse_subject_group(self) -> None:
        """Test parsing ACL with group subject."""
        acl = "access to entry by group=REDACTED_LDAP_BIND_PASSWORDs (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "group"

    def test_parse_subject_user(self) -> None:
        """Test parsing ACL with user subject."""
        acl = "access to entry by user=REDACTED_LDAP_BIND_PASSWORD (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "user"

    def test_parse_subject_self(self) -> None:
        """Test parsing ACL with 'self' subject."""
        acl = "access to entry by self (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "self"

    def test_parse_subject_anonymous(self) -> None:
        """Test parsing ACL with 'anonymous' subject."""
        acl = "access to entry by anonymous (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "anonymous"

    def test_parse_subject_default(self) -> None:
        """Test parsing ACL with default subject type."""
        acl = "access to entry by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "user"

    def test_parse_permissions_multiple(self) -> None:
        """Test parsing ACL with multiple permissions."""
        acl = "access to entry by users (read,write,add,delete)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions
        assert "add" in result.data.permissions.permissions
        assert "delete" in result.data.permissions.permissions

    def test_parse_permissions_with_parentheses(self) -> None:
        """Test parsing ACL with permissions in parentheses."""
        acl = "access to entry by users (read,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions

    def test_parse_permissions_oracle_specific(self) -> None:
        """Test parsing ACL with Oracle-specific permissions."""
        acl = "access to entry by users (selfwrite,selfadd,selfdelete)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "selfwrite" in result.data.permissions.permissions
        assert "selfadd" in result.data.permissions.permissions
        assert "selfdelete" in result.data.permissions.permissions

    def test_parse_permissions_unknown_filtered(self) -> None:
        """Test parsing ACL with unknown permissions (should be filtered out)."""
        acl = "access to entry by users (read,unknown,write)"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions
        assert "unknown" not in result.data.permissions.permissions

    def test_parse_permissions_default(self) -> None:
        """Test parsing ACL with no permissions (defaults to read)."""
        acl = "access to entry by users"
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions

    def test_parse_exception_handling(self) -> None:
        """Test parsing ACL with exception handling."""
        # This should cause an exception due to invalid input
        result = FlextLdapAclParsers.OracleAclParser.parse(None)
        assert result.is_failure
        assert result.error is not None
        assert "Failed to parse Oracle ACL:" in result.error


class TestFlextLdapAclParsersAciParser:
    """Tests for FlextLdapAclParsers.AciParser class."""

    def test_parse_valid_aci(self) -> None:
        """Test parsing valid ACI."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert isinstance(result.data, FlextLdapModels.UnifiedAcl)

    def test_parse_empty_aci_string(self) -> None:
        """Test parsing empty ACI string."""
        result = FlextLdapAclParsers.AciParser.parse("")
        assert result.is_failure
        assert result.error is not None
        assert "ACI string cannot be empty" in result.error

    def test_parse_whitespace_only_aci(self) -> None:
        """Test parsing whitespace-only ACI string."""
        result = FlextLdapAclParsers.AciParser.parse("   ")
        assert result.is_failure
        assert result.error is not None
        assert "ACI string cannot be empty" in result.error

    def test_parse_missing_target(self) -> None:
        """Test parsing ACI with missing target."""
        aci = '(version 3.0; acl "test_acl"; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACI format: missing target" in result.error

    def test_parse_missing_acl_name(self) -> None:
        """Test parsing ACI with missing ACL name."""
        aci = '(target="cn=test")(version 3.0; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACI format: missing ACL name" in result.error

    def test_parse_missing_grant_type(self) -> None:
        """Test parsing ACI with missing grant type."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACI format: missing grant type" in result.error

    def test_parse_missing_permissions(self) -> None:
        """Test parsing ACI with missing permissions."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACI format: missing permissions" in result.error

    def test_parse_missing_subject(self) -> None:
        """Test parsing ACI with missing subject."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write);)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACI format: missing subject" in result.error

    def test_parse_allow_grant_type(self) -> None:
        """Test parsing ACI with 'allow' grant type."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.permissions.grant_type == "allow"
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions

    def test_parse_deny_grant_type(self) -> None:
        """Test parsing ACI with 'deny' grant type."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; deny (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.permissions.grant_type == "deny"
        assert "read" in result.data.permissions.denied_permissions
        assert "write" in result.data.permissions.denied_permissions

    def test_parse_userdn_subject(self) -> None:
        """Test parsing ACI with 'userdn' subject."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "user"
        assert result.data.subject.identifier == "ldap:///all"

    def test_parse_groupdn_subject(self) -> None:
        """Test parsing ACI with 'groupdn' subject."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write) groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "group"
        assert result.data.subject.identifier == "ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com"

    def test_parse_anyone_subject(self) -> None:
        """Test parsing ACI with 'anyone' in subject."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write) userdn="ldap:///anyone";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.subject.subject_type == "anyone"

    def test_parse_target_entry(self) -> None:
        """Test parsing ACI with entry target."""
        aci = '(target="cn=test,dc=example,dc=com")(version 3.0; acl "test_acl"; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.target.target_type == "entry"
        assert result.data.target.dn_pattern == "cn=test,dc=example,dc=com"

    def test_parse_acl_name(self) -> None:
        """Test parsing ACI with ACL name."""
        aci = '(target="cn=test")(version 3.0; acl "my_test_acl"; allow (read,write) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert result.data.name == "my_test_acl"

    def test_parse_permissions_multiple(self) -> None:
        """Test parsing ACI with multiple permissions."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read,write,add,delete,search) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions
        assert "add" in result.data.permissions.permissions
        assert "delete" in result.data.permissions.permissions
        assert "search" in result.data.permissions.permissions

    def test_parse_permissions_with_spaces(self) -> None:
        """Test parsing ACI with permissions containing spaces."""
        aci = '(target="cn=test")(version 3.0; acl "test_acl"; allow (read, write, add, delete) userdn="ldap:///all";)'
        result = FlextLdapAclParsers.AciParser.parse(aci)
        assert result.is_success
        assert result.data is not None
        assert "read" in result.data.permissions.permissions
        assert "write" in result.data.permissions.permissions
        assert "add" in result.data.permissions.permissions
        assert "delete" in result.data.permissions.permissions

    def test_parse_exception_handling(self) -> None:
        """Test parsing ACI with exception handling."""
        # This should cause an exception due to invalid input
        result = FlextLdapAclParsers.AciParser.parse(None)
        assert result.is_failure
        assert result.error is not None
        assert "Failed to parse ACI:" in result.error
