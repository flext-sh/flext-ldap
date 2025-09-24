"""Unit tests for ACL models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.acl import FlextLdapAclConstants, FlextLdapAclModels


class TestAclTarget:
    """Test cases for AclTarget model."""

    def test_create_acl_target_success(self) -> None:
        """Test successful ACL target creation."""
        result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.DN,
            dn_pattern="ou=users,dc=example,dc=com",
            attributes=["uid", "cn"],
            scope="subtree",
        )

        assert result.is_success
        target = result.unwrap()
        assert target.target_type == FlextLdapAclConstants.TargetType.DN
        assert target.dn_pattern == "ou=users,dc=example,dc=com"
        assert target.attributes == ["uid", "cn"]
        assert target.scope == "subtree"

    def test_create_acl_target_with_defaults(self) -> None:
        """Test ACL target creation with default values."""
        result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.ENTRY
        )

        assert result.is_success
        target = result.unwrap()
        assert target.target_type == FlextLdapAclConstants.TargetType.ENTRY
        assert target.dn_pattern == "*"
        assert target.attributes == []
        assert target.scope == "subtree"


class TestAclSubject:
    """Test cases for AclSubject model."""

    def test_create_acl_subject_success(self) -> None:
        """Test successful ACL subject creation."""
        result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.GROUP,
            identifier="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
            authentication_level="strong",
        )

        assert result.is_success
        subject = result.unwrap()
        assert subject.subject_type == FlextLdapAclConstants.SubjectType.GROUP
        assert subject.identifier == "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"
        assert subject.authentication_level == "strong"

    def test_create_self_subject(self) -> None:
        """Test creation of self subject type."""
        result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.SELF
        )

        assert result.is_success
        subject = result.unwrap()
        assert subject.subject_type == FlextLdapAclConstants.SubjectType.SELF
        assert subject.identifier == "*"


class TestAclPermissions:
    """Test cases for AclPermissions model."""

    def test_create_permissions_success(self) -> None:
        """Test successful permissions creation."""
        result = FlextLdapAclModels.AclPermissions.create(
            permissions=[
                FlextLdapAclConstants.Permission.READ,
                FlextLdapAclConstants.Permission.WRITE,
            ],
            grant_type="allow",
        )

        assert result.is_success
        perms = result.unwrap()
        assert FlextLdapAclConstants.Permission.READ in perms.permissions
        assert FlextLdapAclConstants.Permission.WRITE in perms.permissions
        assert perms.grant_type == "allow"

    def test_create_denied_permissions(self) -> None:
        """Test denied permissions creation."""
        result = FlextLdapAclModels.AclPermissions.create(
            denied_permissions=[FlextLdapAclConstants.Permission.DELETE],
            grant_type="deny",
        )

        assert result.is_success
        perms = result.unwrap()
        assert FlextLdapAclConstants.Permission.DELETE in perms.denied_permissions
        assert perms.grant_type == "deny"


class TestUnifiedAcl:
    """Test cases for UnifiedAcl model."""

    def test_create_unified_acl_success(self) -> None:
        """Test successful unified ACL creation."""
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

        assert target_result.is_success
        assert subject_result.is_success
        assert perms_result.is_success

        result = FlextLdapAclModels.UnifiedAcl.create(
            name="Allow self password write",
            target=target_result.unwrap(),
            subject=subject_result.unwrap(),
            permissions=perms_result.unwrap(),
            priority=100,
        )

        assert result.is_success
        acl = result.unwrap()
        assert acl.name == "Allow self password write"
        assert acl.priority == 100
        assert acl.target.attributes == ["userPassword"]
        assert acl.subject.subject_type == FlextLdapAclConstants.SubjectType.SELF

    def test_unified_acl_with_conditions(self) -> None:
        """Test unified ACL with conditions."""
        target_result = FlextLdapAclModels.AclTarget.create(
            target_type=FlextLdapAclConstants.TargetType.DN
        )
        subject_result = FlextLdapAclModels.AclSubject.create(
            subject_type=FlextLdapAclConstants.SubjectType.GROUP
        )
        perms_result = FlextLdapAclModels.AclPermissions.create(
            permissions=[FlextLdapAclConstants.Permission.READ]
        )

        result = FlextLdapAclModels.UnifiedAcl.create(
            target=target_result.unwrap(),
            subject=subject_result.unwrap(),
            permissions=perms_result.unwrap(),
            conditions={"time": "09:00-17:00", "ip": "192.168.1.0/24"},
        )

        assert result.is_success
        acl = result.unwrap()
        assert "time" in acl.conditions
        assert "ip" in acl.conditions


class TestConversionResult:
    """Test cases for ConversionResult model."""

    def test_create_conversion_result_success(self) -> None:
        """Test successful conversion result creation."""
        result = FlextLdapAclModels.ConversionResult.create(
            converted_acl="access to attrs=userPassword by self write",
            source_format=FlextLdapAclConstants.AclFormat.ORACLE,
            target_format=FlextLdapAclConstants.AclFormat.OPENLDAP,
            warnings=["Permission mapping may differ"],
        )

        assert result.is_success
        conv_result = result.unwrap()
        assert conv_result.source_format == FlextLdapAclConstants.AclFormat.ORACLE
        assert conv_result.target_format == FlextLdapAclConstants.AclFormat.OPENLDAP
        assert len(conv_result.warnings) == 1
