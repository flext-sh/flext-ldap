"""Unit tests for ACL manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.acl import FlextLdapAclConstants, FlextLdapAclManager


class TestAclManager:
    """Test cases for ACL manager."""

    def test_parse_openldap_acl(self) -> None:
        """Test parsing OpenLDAP ACL through manager."""
        manager = FlextLdapAclManager()
        acl = "access to attrs=mail by self write"

        result = manager.parse_acl(acl, FlextLdapAclConstants.AclFormat.OPENLDAP)

        assert result.is_success
        unified = result.unwrap()
        assert "mail" in unified.target.attributes

    def test_parse_oracle_acl(self) -> None:
        """Test parsing Oracle ACL through manager."""
        manager = FlextLdapAclManager()
        acl = 'access to entry by group="cn=users" (read)'

        result = manager.parse_acl(acl, FlextLdapAclConstants.AclFormat.ORACLE)

        assert result.is_success
        unified = result.unwrap()
        assert unified.target.target_type == FlextLdapAclConstants.TargetType.ENTRY

    def test_convert_acl(self) -> None:
        """Test ACL conversion through manager."""
        manager = FlextLdapAclManager()
        openldap_acl = "access to attrs=cn by users read"

        result = manager.convert_acl(
            openldap_acl,
            FlextLdapAclConstants.AclFormat.OPENLDAP,
            FlextLdapAclConstants.AclFormat.ORACLE,
        )

        assert result.is_success
        conv_result = result.unwrap()
        assert "access to" in conv_result.converted_acl
        assert conv_result.source_format == FlextLdapAclConstants.AclFormat.OPENLDAP
        assert conv_result.target_format == FlextLdapAclConstants.AclFormat.ORACLE

    def test_batch_convert_acls(self) -> None:
        """Test batch ACL conversion."""
        manager = FlextLdapAclManager()
        acls = [
            "access to attrs=cn by self write",
            "access to attrs=mail by users read",
        ]

        result = manager.batch_convert(
            acls,
            FlextLdapAclConstants.AclFormat.OPENLDAP,
            FlextLdapAclConstants.AclFormat.ACI,
        )

        assert result.is_success
        results = result.unwrap()
        assert len(results) == 2
        for conv_result in results:
            assert conv_result.source_format == FlextLdapAclConstants.AclFormat.OPENLDAP
            assert conv_result.target_format == FlextLdapAclConstants.AclFormat.ACI

    def test_validate_acl_syntax_success(self) -> None:
        """Test successful ACL syntax validation."""
        manager = FlextLdapAclManager()
        acl = "access to attrs=userPassword by self write"

        result = manager.validate_acl_syntax(
            acl, FlextLdapAclConstants.AclFormat.OPENLDAP
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_acl_syntax_failure(self) -> None:
        """Test ACL syntax validation failure."""
        manager = FlextLdapAclManager()
        invalid_acl = "invalid acl syntax"

        result = manager.validate_acl_syntax(
            invalid_acl, FlextLdapAclConstants.AclFormat.OPENLDAP
        )

        assert result.is_failure
        assert "Invalid ACL syntax" in result.error

    def test_parse_empty_acl_fails(self) -> None:
        """Test that parsing empty ACL fails."""
        manager = FlextLdapAclManager()

        result = manager.parse_acl("", FlextLdapAclConstants.AclFormat.OPENLDAP)

        assert result.is_failure
        assert "cannot be empty" in result.error

    def test_parse_unsupported_format_fails(self) -> None:
        """Test that parsing unsupported format fails."""
        manager = FlextLdapAclManager()

        result = manager.parse_acl("test", "unsupported_format")

        assert result.is_failure
        assert "Unsupported" in result.error

    def test_batch_convert_empty_list_fails(self) -> None:
        """Test that batch converting empty list fails."""
        manager = FlextLdapAclManager()

        result = manager.batch_convert(
            [],
            FlextLdapAclConstants.AclFormat.OPENLDAP,
            FlextLdapAclConstants.AclFormat.ORACLE,
        )

        assert result.is_failure
        assert "cannot be empty" in result.error
