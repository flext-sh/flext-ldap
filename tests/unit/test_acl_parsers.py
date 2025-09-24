"""Unit tests for ACL parsers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.acl import FlextLdapAclConstants, FlextLdapAclParsers


class TestOpenLdapAclParser:
    """Test cases for OpenLDAP ACL parser."""

    def test_parse_simple_acl(self) -> None:
        """Test parsing simple OpenLDAP ACL."""
        acl = "access to attrs=userPassword by self write"
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)

        assert result.is_success
        unified = result.unwrap()
        assert "userPassword" in unified.target.attributes
        assert unified.subject.subject_type == FlextLdapAclConstants.SubjectType.SELF
        assert FlextLdapAclConstants.Permission.WRITE in unified.permissions.permissions

    def test_parse_acl_with_dn(self) -> None:
        """Test parsing ACL with DN specification."""
        acl = 'access to dn.exact="ou=users,dc=example,dc=com" by users read'
        result = FlextLdapAclParsers.OpenLdapAclParser.parse(acl)

        assert result.is_success
        unified = result.unwrap()
        assert unified.target.dn_pattern == "ou=users,dc=example,dc=com"
        assert (
            unified.subject.subject_type
            == FlextLdapAclConstants.SubjectType.AUTHENTICATED
        )

    def test_parse_empty_acl_fails(self) -> None:
        """Test that parsing empty ACL fails."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse("")

        assert result.is_failure
        assert "cannot be empty" in result.error

    def test_parse_invalid_format_fails(self) -> None:
        """Test that parsing invalid format fails."""
        result = FlextLdapAclParsers.OpenLdapAclParser.parse("invalid acl format")

        assert result.is_failure
        assert "Invalid OpenLDAP ACL format" in result.error


class TestOracleAclParser:
    """Test cases for Oracle ACL parser."""

    def test_parse_simple_oracle_acl(self) -> None:
        """Test parsing simple Oracle ACL."""
        acl = 'access to attr=(userPassword) by group="cn=admins" (read,write)'
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)

        assert result.is_success
        unified = result.unwrap()
        assert "userPassword" in unified.target.attributes
        assert unified.subject.subject_type == FlextLdapAclConstants.SubjectType.GROUP
        assert "read" in unified.permissions.permissions
        assert "write" in unified.permissions.permissions

    def test_parse_oracle_entry_acl(self) -> None:
        """Test parsing Oracle entry-level ACL."""
        acl = 'access to entry by user="cn=admin" (read,write,delete)'
        result = FlextLdapAclParsers.OracleAclParser.parse(acl)

        assert result.is_success
        unified = result.unwrap()
        assert unified.target.target_type == FlextLdapAclConstants.TargetType.ENTRY
        assert unified.subject.subject_type == FlextLdapAclConstants.SubjectType.USER

    def test_parse_empty_oracle_acl_fails(self) -> None:
        """Test that parsing empty Oracle ACL fails."""
        result = FlextLdapAclParsers.OracleAclParser.parse("")

        assert result.is_failure
        assert "cannot be empty" in result.error


class TestAciParser:
    """Test cases for ACI format parser."""

    def test_parse_simple_aci(self) -> None:
        """Test parsing simple ACI."""
        aci = (
            '(target="ldap:///ou=users,dc=example,dc=com")'
            '(version 3.0; acl "User Read Access"; allow (read) userdn="ldap:///anyone";)'
        )
        result = FlextLdapAclParsers.AciParser.parse(aci)

        assert result.is_success
        unified = result.unwrap()
        assert unified.name == "User Read Access"
        assert unified.target.dn_pattern == "ldap:///ou=users,dc=example,dc=com"
        assert "read" in unified.permissions.permissions
        assert unified.permissions.grant_type == "allow"

    def test_parse_aci_with_deny(self) -> None:
        """Test parsing ACI with deny permission."""
        aci = (
            '(target="ldap:///dc=example,dc=com")'
            '(version 3.0; acl "Deny Delete"; deny (delete) userdn="ldap:///anyone";)'
        )
        result = FlextLdapAclParsers.AciParser.parse(aci)

        assert result.is_success
        unified = result.unwrap()
        assert unified.permissions.grant_type == "deny"
        assert "delete" in unified.permissions.denied_permissions

    def test_parse_aci_with_group(self) -> None:
        """Test parsing ACI with group subject."""
        aci = (
            '(target="ldap:///ou=data,dc=example,dc=com")'
            '(version 3.0; acl "Group Access"; allow (read,write) groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=com";)'
        )
        result = FlextLdapAclParsers.AciParser.parse(aci)

        assert result.is_success
        unified = result.unwrap()
        assert unified.subject.subject_type == FlextLdapAclConstants.SubjectType.GROUP

    def test_parse_empty_aci_fails(self) -> None:
        """Test that parsing empty ACI fails."""
        result = FlextLdapAclParsers.AciParser.parse("")

        assert result.is_failure
        assert "cannot be empty" in result.error
