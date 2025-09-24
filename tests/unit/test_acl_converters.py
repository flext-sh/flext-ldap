"""Unit tests for ACL converters.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclModels,
)


class TestOpenLdapConverter:
    """Test cases for OpenLDAP converter."""

    def test_convert_from_unified(self) -> None:
        """Test conversion from unified to OpenLDAP format."""
        target_result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.ATTRIBUTES,
            attributes=["userPassword"],
        )
        subject_result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.SELF
        )
        perms_result = FlextLdapAclModels.AclPermissions.create(
            permissions=[FlextLdapAclConstants.Permission.WRITE]
        )

        unified_result = FlextLdapAclModels.UnifiedAcl.create(
            target=target_result.unwrap(),
            subject=subject_result.unwrap(),
            permissions=perms_result.unwrap(),
        )

        result = FlextLdapAclConverters.OpenLdapConverter.from_unified(
            unified_result.unwrap()
        )

        assert result.is_success
        acl_line = result.unwrap()
        assert "access to" in acl_line
        assert "attrs=userPassword" in acl_line
        assert "by self" in acl_line
        assert "write" in acl_line

    def test_convert_with_group_subject(self) -> None:
        """Test conversion with group subject."""
        target_result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.DN,
            dn_pattern="ou=users,dc=example,dc=com",
        )
        subject_result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.GROUP,
            identifier="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
        )
        perms_result = FlextLdapAclModels.AclPermissions.create(
            permissions=[FlextLdapAclConstants.Permission.READ]
        )

        unified_result = FlextLdapAclModels.UnifiedAcl.create(
            target=target_result.unwrap(),
            subject=subject_result.unwrap(),
            permissions=perms_result.unwrap(),
        )

        result = FlextLdapAclConverters.OpenLdapConverter.from_unified(
            unified_result.unwrap()
        )

        assert result.is_success
        acl_line = result.unwrap()
        assert "by group=cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com" in acl_line


class TestOracleConverter:
    """Test cases for Oracle converter."""

    def test_convert_from_unified(self) -> None:
        """Test conversion from unified to Oracle format."""
        target_result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.ATTRIBUTES,
            attributes=["cn", "sn"],
        )
        subject_result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.GROUP,
            identifier="cn=REDACTED_LDAP_BIND_PASSWORDs",
        )
        perms_result = FlextLdapAclModels.AclPermissions.create(
            permissions=["read", "write"]
        )

        unified_result = FlextLdapAclModels.UnifiedAcl.create(
            target=target_result.unwrap(),
            subject=subject_result.unwrap(),
            permissions=perms_result.unwrap(),
        )

        result = FlextLdapAclConverters.OracleConverter.from_unified(
            unified_result.unwrap()
        )

        assert result.is_success
        orclaci = result.unwrap()
        assert "access to" in orclaci
        assert "attr=(cn, sn)" in orclaci
        assert 'by group="cn=REDACTED_LDAP_BIND_PASSWORDs"' in orclaci
        assert "(read, write)" in orclaci


class TestAciConverter:
    """Test cases for ACI converter."""

    def test_convert_from_unified(self) -> None:
        """Test conversion from unified to ACI format."""
        target_result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.DN,
            dn_pattern="ldap:///ou=users,dc=example,dc=com",
        )
        subject_result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.DN,
            identifier="ldap:///anyone",
        )
        perms_result = FlextLdapAclModels.AclPermissions.create(
            permissions=["read"], grant_type="allow"
        )

        unified_result = FlextLdapAclModels.UnifiedAcl.create(
            name="Read Access",
            target=target_result.unwrap(),
            subject=subject_result.unwrap(),
            permissions=perms_result.unwrap(),
        )

        result = FlextLdapAclConverters.AciConverter.from_unified(
            unified_result.unwrap()
        )

        assert result.is_success
        aci = result.unwrap()
        assert '(target="ldap:///ou=users,dc=example,dc=com")' in aci
        assert 'acl "Read Access"' in aci
        assert "allow (read)" in aci
        assert 'userdn="ldap:///anyone"' in aci


class TestUniversalConverter:
    """Test cases for universal converter."""

    def test_openldap_to_oracle_conversion(self) -> None:
        """Test conversion from OpenLDAP to Oracle format."""
        openldap_acl = "access to attrs=userPassword by self write"

        result = FlextLdapAclConverters.UniversalConverter.convert(
            openldap_acl,
            FlextLdapAclConstants.AclFormat.OPENLDAP,
            FlextLdapAclConstants.AclFormat.ORACLE,
        )

        assert result.is_success
        conv_result = result.unwrap()
        assert conv_result.source_format == FlextLdapAclConstants.AclFormat.OPENLDAP
        assert conv_result.target_format == FlextLdapAclConstants.AclFormat.ORACLE
        assert "access to" in conv_result.converted_acl

    def test_oracle_to_aci_conversion(self) -> None:
        """Test conversion from Oracle to ACI format."""
        oracle_acl = 'access to attr=(cn) by group="cn=REDACTED_LDAP_BIND_PASSWORDs" (read)'

        result = FlextLdapAclConverters.UniversalConverter.convert(
            oracle_acl,
            FlextLdapAclConstants.AclFormat.ORACLE,
            FlextLdapAclConstants.AclFormat.ACI,
        )

        assert result.is_success
        conv_result = result.unwrap()
        assert conv_result.source_format == FlextLdapAclConstants.AclFormat.ORACLE
        assert conv_result.target_format == FlextLdapAclConstants.AclFormat.ACI
        assert "(target=" in conv_result.converted_acl
        assert "version 3.0" in conv_result.converted_acl

    def test_empty_acl_conversion_fails(self) -> None:
        """Test that converting empty ACL fails."""
        result = FlextLdapAclConverters.UniversalConverter.convert(
            "",
            FlextLdapAclConstants.AclFormat.OPENLDAP,
            FlextLdapAclConstants.AclFormat.ORACLE,
        )

        assert result.is_failure
        assert "cannot be empty" in result.error

    def test_unsupported_format_fails(self) -> None:
        """Test that unsupported format fails."""
        result = FlextLdapAclConverters.UniversalConverter.convert(
            "test", "invalid_format", FlextLdapAclConstants.AclFormat.OPENLDAP
        )

        assert result.is_failure
        assert "Unsupported" in result.error
