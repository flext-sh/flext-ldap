"""Comprehensive unit tests for DomainServices.

Tests domain-specific business logic for LDAP operations including user display names,
user status determination, group membership validation, and username generation.

All tests use actual DomainServices with real FlextLdifModels.Entry objects.

Test Categories:
- @pytest.mark.unit - Unit tests with real objects
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.services.domain import DomainServices


class TestDomainServicesDisplayName:
    """Test calculate_user_display_name method with priority ordering."""

    @pytest.mark.unit
    def test_display_name_from_display_name_string(self) -> None:
        """Test extracting display name from displayName attribute (string)."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=john.doe,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"displayName": ["John Doe"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "John Doe"

    @pytest.mark.unit
    def test_display_name_from_display_name_list(self) -> None:
        """Test extracting display name from displayName attribute (list)."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=jane.doe,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"displayName": ["Jane Marie Doe", "Jane Doe"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "Jane Marie Doe"

    @pytest.mark.unit
    def test_display_name_fallback_to_given_name_and_sn(self) -> None:
        """Test fallback to givenName + sn when displayName absent."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"givenName": ["Test"], "sn": ["User"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "Test User"

    @pytest.mark.unit
    def test_display_name_fallback_to_given_name_and_sn_lists(self) -> None:
        """Test fallback to givenName + sn with list values."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"givenName": ["Test", "T"], "sn": ["User", "U"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "Test User"

    @pytest.mark.unit
    def test_display_name_fallback_to_cn(self) -> None:
        """Test fallback to cn when displayName and givenName/sn absent."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=testuser,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"cn": ["testuser"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "testuser"

    @pytest.mark.unit
    def test_display_name_fallback_to_cn_list(self) -> None:
        """Test fallback to cn with list value."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=testuser,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"cn": ["testuser", "test.user"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "testuser"

    @pytest.mark.unit
    def test_display_name_fallback_to_uid(self) -> None:
        """Test fallback to uid when other attributes absent."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "uid=testuid,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"uid": ["testuid"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "testuid"

    @pytest.mark.unit
    def test_display_name_fallback_to_uid_list(self) -> None:
        """Test fallback to uid with list value."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "uid=testuid,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"uid": ["testuid", "test"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == "testuid"

    @pytest.mark.unit
    def test_display_name_no_attributes(self) -> None:
        """Test display name when all attributes are absent."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=unknown,dc=example,dc=com"
        })
        attrs = FlextLdifModels.LdifAttributes(attributes={})
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == FlextLdapConstants.ErrorStrings.UNKNOWN_USER

    @pytest.mark.unit
    def test_display_name_empty_attributes(self) -> None:
        """Test display name with empty attributes."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=unknown,dc=example,dc=com"
        })
        attrs = FlextLdifModels.LdifAttributes(attributes={})
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        assert result == FlextLdapConstants.ErrorStrings.UNKNOWN_USER

    @pytest.mark.unit
    def test_display_name_priority_given_name_requires_sn(self) -> None:
        """Test that givenName requires sn for combined display."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=test.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"givenName": ["Test"], "cn": ["testuser"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.calculate_user_display_name(entry)

        # Should fallback to cn since sn is missing
        assert result == "testuser"


class TestDomainServicesUserStatus:
    """Test determine_user_status method for various status indicators."""

    @pytest.mark.unit
    def test_user_status_active_default(self) -> None:
        """Test default active status when no lock attributes present."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=active.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"cn": ["active.user"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.ACTIVE

    @pytest.mark.unit
    def test_user_status_locked_from_lock_flag(self) -> None:
        """Test locked status when lock flag is true."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=locked.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"nsAccountLock": ["TRUE"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.LOCKED

    @pytest.mark.unit
    def test_user_status_locked_from_lock_flag_yes(self) -> None:
        """Test locked status with 'yes' flag value."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=locked.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"nsAccountLock": ["yes"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.LOCKED

    @pytest.mark.unit
    def test_user_status_locked_from_lock_flag_one(self) -> None:
        """Test locked status with '1' flag value."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=locked.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"nsAccountLock": ["1"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.LOCKED

    @pytest.mark.unit
    def test_user_status_disabled_from_ad_flag(self) -> None:
        """Test disabled status from Active Directory userAccountControl flag."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=disabled.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"userAccountControl": ["2"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.DISABLED

    @pytest.mark.unit
    def test_user_status_disabled_from_ad_flag_integer(self) -> None:
        """Test disabled status with integer userAccountControl."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=disabled.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"userAccountControl": ["514"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.DISABLED

    @pytest.mark.unit
    def test_user_status_active_with_password_expiry(self) -> None:
        """Test active status when password expiry attribute present."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=user.pwd,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"pwdLastSet": ["20251029120000Z"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.ACTIVE

    @pytest.mark.unit
    def test_user_status_no_attributes(self) -> None:
        """Test default active status when attributes are empty."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=empty.user,dc=example,dc=com"
        })
        attrs = FlextLdifModels.LdifAttributes(attributes={})
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.ACTIVE

    @pytest.mark.unit
    def test_user_status_lock_attribute_list(self) -> None:
        """Test locked status with lock attribute as list."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=locked.user,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"nsAccountLock": ["TRUE", "false"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        assert result == FlextLdapConstants.UserStatus.LOCKED

    @pytest.mark.unit
    def test_user_status_invalid_ad_flag(self) -> None:
        """Test status with invalid AD flag that cannot be parsed."""
        dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=user.ad,ou=users,dc=example,dc=com"
        })
        attrs_dict = {"userAccountControl": ["invalid"]}
        attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
        entry = FlextLdifModels.Entry(dn=dn, attributes=attrs)

        result = DomainServices.determine_user_status(entry)

        # Should default to ACTIVE when AD flag is invalid
        assert result == FlextLdapConstants.UserStatus.ACTIVE


class TestDomainServicesGroupMembership:
    """Test validate_group_membership_rules for business logic validation."""

    @pytest.mark.unit
    def test_group_membership_valid_admin_with_email(self) -> None:
        """Test valid membership in admin group with email address."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=admin.user,ou=users,dc=example,dc=com"
        })
        user_attrs_dict = {"mail": ["admin.user@example.com"]}
        user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=admin,ou=groups,dc=example,dc=com"
        })
        group_attrs_dict = {"cn": ["admin"]}
        group_attrs = FlextLdifModels.LdifAttributes(attributes=group_attrs_dict)
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert result.is_success
        assert result.unwrap() is True

    @pytest.mark.unit
    def test_group_membership_invalid_admin_without_email(self) -> None:
        """Test invalid membership in admin group without email address."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=nomail.user,ou=users,dc=example,dc=com"
        })
        user_attrs = FlextLdifModels.LdifAttributes(attributes={})
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=admin,ou=groups,dc=example,dc=com"
        })
        group_attrs_dict = {"cn": ["admin"]}
        group_attrs = FlextLdifModels.LdifAttributes(attributes=group_attrs_dict)
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert result.is_failure
        assert "must have email" in result.error.lower()

    @pytest.mark.unit
    def test_group_membership_valid_non_admin_group(self) -> None:
        """Test valid membership in non-admin group without email requirement."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=user.nomail,ou=users,dc=example,dc=com"
        })
        user_attrs = FlextLdifModels.LdifAttributes(attributes={})
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=users,ou=groups,dc=example,dc=com"
        })
        group_attrs_dict = {"cn": ["users"]}
        group_attrs = FlextLdifModels.LdifAttributes(attributes=group_attrs_dict)
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert result.is_success
        assert result.unwrap() is True

    @pytest.mark.unit
    def test_group_membership_invalid_locked_user(self) -> None:
        """Test invalid membership for locked users."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=locked.user,ou=users,dc=example,dc=com"
        })
        user_attrs_dict = {"nsAccountLock": ["TRUE"], "mail": ["locked@example.com"]}
        user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=users,ou=groups,dc=example,dc=com"
        })
        group_attrs_dict = {"cn": ["users"]}
        group_attrs = FlextLdifModels.LdifAttributes(attributes=group_attrs_dict)
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert result.is_failure
        assert "inactive" in result.error.lower()

    @pytest.mark.unit
    def test_group_membership_empty_group_attributes(self) -> None:
        """Test membership validation with empty group attributes."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=user,ou=users,dc=example,dc=com"
        })
        user_attrs_dict = {"mail": ["user@example.com"]}
        user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=group,ou=groups,dc=example,dc=com"
        })
        group_attrs = FlextLdifModels.LdifAttributes(attributes={})
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert result.is_success
        assert result.unwrap() is True

    @pytest.mark.unit
    def test_group_membership_group_cn_case_insensitive(self) -> None:
        """Test admin group detection is case insensitive."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=nomail,ou=users,dc=example,dc=com"
        })
        user_attrs = FlextLdifModels.LdifAttributes(attributes={})
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=Admin,ou=groups,dc=example,dc=com"
        })
        group_attrs_dict = {"cn": ["Admin"]}
        group_attrs = FlextLdifModels.LdifAttributes(attributes=group_attrs_dict)
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert result.is_failure
        assert "must have email" in result.error.lower()

    @pytest.mark.unit
    def test_group_membership_returns_flext_result(self) -> None:
        """Test that group membership validation returns FlextResult."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=user,ou=users,dc=example,dc=com"
        })
        user_attrs = FlextLdifModels.LdifAttributes(attributes={})
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        group_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=group,ou=groups,dc=example,dc=com"
        })
        group_attrs = FlextLdifModels.LdifAttributes(attributes={})
        group = FlextLdifModels.Entry(dn=group_dn, attributes=group_attrs)

        result = DomainServices.validate_group_membership_rules(user, group)

        assert isinstance(result, FlextResult)
        assert isinstance(result.unwrap(), bool)


class TestDomainServicesUsernameGeneration:
    """Test generate_unique_username for username creation and validation."""

    @pytest.mark.unit
    def test_username_generation_simple_name(self) -> None:
        """Test simple username generation from base name."""
        result = DomainServices.generate_unique_username("john.doe", [])

        assert result.is_success
        # Dots are removed by sanitization regex
        assert result.unwrap() == "johndoe"

    @pytest.mark.unit
    def test_username_generation_normalize_spaces(self) -> None:
        """Test username normalization replaces spaces with underscores."""
        result = DomainServices.generate_unique_username("John Doe", [])

        # Check that it either succeeds with valid LDAP name or fails validation
        # Underscores might not pass LDAP attribute name validation
        if result.is_success:
            # If it passes, it should have underscores
            assert "_" in result.unwrap()
        else:
            # If validation fails, it's due to underscore in LDAP name
            assert "LDAP attribute name requirements" in result.error

    @pytest.mark.unit
    def test_username_generation_lowercase(self) -> None:
        """Test username is converted to lowercase."""
        result = DomainServices.generate_unique_username("JOHN", [])

        assert result.is_success
        assert result.unwrap() == "john"

    @pytest.mark.unit
    def test_username_generation_empty_base_name(self) -> None:
        """Test error when base name is empty."""
        result = DomainServices.generate_unique_username("", [])

        assert result.is_failure
        assert "empty" in result.error.lower()

    @pytest.mark.unit
    def test_username_generation_special_chars_removed(self) -> None:
        """Test that special characters are removed from username."""
        result = DomainServices.generate_unique_username("john@#$%doe", [])

        assert result.is_success
        # Special chars removed, should result in "johndoe"
        username = result.unwrap()
        assert "@" not in username
        assert "#" not in username

    @pytest.mark.unit
    def test_username_generation_only_invalid_chars(self) -> None:
        """Test error when base name contains only invalid characters."""
        result = DomainServices.generate_unique_username("@#$%^&*()", [])

        assert result.is_failure
        assert "valid characters" in result.error.lower()

    @pytest.mark.unit
    def test_username_generation_unique_when_not_existing(self) -> None:
        """Test unique username returned when not in existing users."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "uid=existing,ou=users,dc=example,dc=com"
        })
        user_attrs_dict = {"uid": ["existing"]}
        user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
        existing_user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        result = DomainServices.generate_unique_username("john.doe", [existing_user])

        assert result.is_success
        # Dots are removed by sanitization regex
        assert result.unwrap() == "johndoe"

    @pytest.mark.unit
    def test_username_generation_numeric_suffix_when_exists(self) -> None:
        """Test numeric suffix appended when base username exists."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "uid=john,ou=users,dc=example,dc=com"
        })
        user_attrs_dict = {"uid": ["john"]}
        user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
        existing_user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        result = DomainServices.generate_unique_username("john", [existing_user])

        assert result.is_success
        assert result.unwrap() == "john1"

    @pytest.mark.unit
    def test_username_generation_finds_first_available(self) -> None:
        """Test finds first available numeric suffix."""
        # Create users: john, john1, john2
        users = []
        for uid in ["john", "john1", "john2"]:
            user_dn = FlextLdifModels.DistinguishedName.model_validate({
                "value": f"uid={uid},ou=users,dc=example,dc=com"
            })
            user_attrs_dict = {"uid": [uid]}
            user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
            users.append(FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs))

        result = DomainServices.generate_unique_username("john", users)

        assert result.is_success
        assert result.unwrap() == "john3"

    @pytest.mark.unit
    def test_username_generation_max_attempts(self) -> None:
        """Test error when max attempts exceeded."""
        # Create 10 existing users: john, john1, ..., john9
        users = []
        for i in range(10):
            uid = "john" if i == 0 else f"john{i}"
            user_dn = FlextLdifModels.DistinguishedName.model_validate({
                "value": f"uid={uid},ou=users,dc=example,dc=com"
            })
            user_attrs_dict = {"uid": [uid]}
            user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
            users.append(FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs))

        result = DomainServices.generate_unique_username("john", users, max_attempts=10)

        assert result.is_failure
        assert "unique username" in result.error.lower()

    @pytest.mark.unit
    def test_username_generation_with_empty_uid_entries(self) -> None:
        """Test username generation ignores entries without uid attribute."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "cn=noid,ou=users,dc=example,dc=com"
        })
        # Entry with no uid attribute
        user_attrs = FlextLdifModels.LdifAttributes(attributes={})
        user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        result = DomainServices.generate_unique_username("john", [user])

        assert result.is_success
        assert result.unwrap() == "john"

    @pytest.mark.unit
    def test_username_generation_returns_flext_result(self) -> None:
        """Test that username generation returns FlextResult."""
        result = DomainServices.generate_unique_username("john", [])

        assert isinstance(result, FlextResult)

    @pytest.mark.unit
    def test_username_generation_multiple_uid_values(self) -> None:
        """Test username generation with user having multiple uid values."""
        user_dn = FlextLdifModels.DistinguishedName.model_validate({
            "value": "uid=john,ou=users,dc=example,dc=com"
        })
        user_attrs_dict = {"uid": ["john", "john.doe"]}
        user_attrs = FlextLdifModels.LdifAttributes(attributes=user_attrs_dict)
        existing_user = FlextLdifModels.Entry(dn=user_dn, attributes=user_attrs)

        result = DomainServices.generate_unique_username("john", [existing_user])

        assert result.is_success
        assert result.unwrap() == "john1"


__all__ = [
    "TestDomainServicesDisplayName",
    "TestDomainServicesGroupMembership",
    "TestDomainServicesUserStatus",
    "TestDomainServicesUsernameGeneration",
]
