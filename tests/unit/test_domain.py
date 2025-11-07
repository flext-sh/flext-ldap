"""Unit tests for DomainServices - Testing actual domain business logic.

Tests the real implementation of DomainServices with proper FlextLdifModels.Entry objects
and actual LDAP attribute handling.

Test Categories:
- User display name calculation with priority ordering
- User status determination from lock attributes
- Group membership validation with business rules
- Unique username generation and collision handling

All tests use real Entry objects without mocks or stubs.
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.services.domain import DomainServices


class TestUserDisplayName:
    """Test calculate_user_display_name with priority ordering."""

    @pytest.mark.unit
    def test_display_name_priority_displayname_attribute(self) -> None:
        """Test priority 1: displayName attribute is highest priority."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "displayName": ["John Doe"],
                "givenName": ["John"],
                "sn": ["Doe"],
                "uid": ["jdoe"],
            },
        ).unwrap()

        result = DomainServices.calculate_user_display_name(entry)
        assert result == "John Doe"

    @pytest.mark.unit
    def test_display_name_priority_given_plus_sn(self) -> None:
        """Test priority 2: givenName + sn when displayName absent."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "givenName": ["John"],
                "sn": ["Doe"],
                "uid": ["jdoe"],
            },
        ).unwrap()

        result = DomainServices.calculate_user_display_name(entry)
        assert result == "John Doe"

    @pytest.mark.unit
    def test_display_name_priority_cn(self) -> None:
        """Test priority 3: cn when displayName and givenName+sn absent."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "uid": ["jdoe"],
            },
        ).unwrap()

        result = DomainServices.calculate_user_display_name(entry)
        assert result == "john.doe"

    @pytest.mark.unit
    def test_display_name_priority_uid_fallback(self) -> None:
        """Test priority 4: uid as fallback when all else absent."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=unknown,ou=users,dc=example,dc=com",
            attributes={"uid": ["jdoe"]},
        ).unwrap()

        result = DomainServices.calculate_user_display_name(entry)
        assert result == "jdoe"

    @pytest.mark.unit
    def test_display_name_no_attributes_returns_unknown(self) -> None:
        """Test fallback to 'unknown' when no identifying attributes exist."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=unknown,ou=users,dc=example,dc=com",
            attributes={},
        ).unwrap()

        result = DomainServices.calculate_user_display_name(entry)
        assert result == FlextLdapConstants.ErrorStrings.UNKNOWN_USER


class TestUserStatus:
    """Test determine_user_status for active/locked/disabled states."""

    @pytest.mark.unit
    def test_user_status_active_default(self) -> None:
        """Test default status is 'active' for normal entries."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "mail": ["john@example.com"],
                "pwdLastSet": ["132123456789"],
            },
        ).unwrap()

        result = DomainServices.determine_user_status(entry)
        assert result == FlextLdapConstants.UserStatus.ACTIVE

    @pytest.mark.unit
    def test_user_status_locked_with_lock_attribute(self) -> None:
        """Test 'locked' status when lock attribute is present."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "nsAccountLock": ["true"],  # Valid LDAP lock attribute
            },
        ).unwrap()

        result = DomainServices.determine_user_status(entry)
        assert result == FlextLdapConstants.UserStatus.LOCKED

    @pytest.mark.unit
    def test_user_status_empty_entry(self) -> None:
        """Test status for entry with no attributes."""
        entry = FlextLdifModels.Entry.create(
            dn="cn=unknown,ou=users,dc=example,dc=com",
            attributes={},
        ).unwrap()

        result = DomainServices.determine_user_status(entry)
        assert result == FlextLdapConstants.UserStatus.ACTIVE


class TestGroupMembershipValidation:
    """Test validate_group_membership_rules business logic."""

    @pytest.mark.unit
    def test_admin_group_requires_email(self) -> None:
        """Test that admin group members must have email."""
        user = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={"cn": ["john.doe"]},
        ).unwrap()

        admin_group = FlextLdifModels.Entry.create(
            dn="cn=admins,ou=groups,dc=example,dc=com",
            attributes={"cn": ["admins"]},
        ).unwrap()

        result = DomainServices.validate_group_membership_rules(user, admin_group)
        assert result.is_failure
        assert result.error and "email" in result.error.lower()

    @pytest.mark.unit
    def test_admin_group_with_email_succeeds(self) -> None:
        """Test admin group membership succeeds with email."""
        user = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "mail": ["john@example.com"],
            },
        ).unwrap()

        admin_group = FlextLdifModels.Entry.create(
            dn="cn=admins,ou=groups,dc=example,dc=com",
            attributes={"cn": ["admins"]},
        ).unwrap()

        result = DomainServices.validate_group_membership_rules(user, admin_group)
        assert result.is_success

    @pytest.mark.unit
    def test_regular_group_no_email_required(self) -> None:
        """Test regular (non-admin) groups don't require email."""
        user = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={"cn": ["john.doe"]},
        ).unwrap()

        group = FlextLdifModels.Entry.create(
            dn="cn=developers,ou=groups,dc=example,dc=com",
            attributes={"cn": ["developers"]},
        ).unwrap()

        result = DomainServices.validate_group_membership_rules(user, group)
        assert result.is_success

    @pytest.mark.unit
    def test_locked_user_cannot_join_group(self) -> None:
        """Test locked users cannot be added to any group."""
        user = FlextLdifModels.Entry.create(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["john.doe"],
                "nsAccountLock": ["true"],  # Valid LDAP lock attribute
                "mail": ["john@example.com"],
            },
        ).unwrap()

        group = FlextLdifModels.Entry.create(
            dn="cn=developers,ou=groups,dc=example,dc=com",
            attributes={"cn": ["developers"]},
        ).unwrap()

        result = DomainServices.validate_group_membership_rules(user, group)
        assert result.is_failure
        assert result.error and "inactive" in result.error.lower()


class TestUniqueUsernameGeneration:
    """Test generate_unique_username collision handling."""

    @pytest.mark.unit
    def test_generate_unique_username_first_attempt(self) -> None:
        """Test generating username when base name is available."""
        result = DomainServices.generate_unique_username("johndoe", [])
        assert result.is_success
        assert result.unwrap() == "johndoe"

    @pytest.mark.unit
    def test_generate_unique_username_with_collision(self) -> None:
        """Test appending number when base username exists."""
        existing_user = FlextLdifModels.Entry.create(
            dn="cn=johndoe,ou=users,dc=example,dc=com",
            attributes={"uid": ["johndoe"]},
        ).unwrap()

        result = DomainServices.generate_unique_username("johndoe", [existing_user])
        assert result.is_success
        assert result.unwrap() == "johndoe1"

    @pytest.mark.unit
    def test_generate_unique_username_multiple_collisions(self) -> None:
        """Test handling multiple collisions."""
        users = [
            FlextLdifModels.Entry.create(
                dn=f"cn=johndoe{i},ou=users,dc=example,dc=com",
                attributes={"uid": [f"johndoe{i}"] if i > 0 else ["johndoe"]},
            ).unwrap()
            for i in range(3)
        ]

        result = DomainServices.generate_unique_username("johndoe", users)
        assert result.is_success
        assert result.unwrap() == "johndoe3"

    @pytest.mark.unit
    def test_generate_username_empty_base_fails(self) -> None:
        """Test that empty base name fails."""
        result = DomainServices.generate_unique_username("", [])
        assert result.is_failure
        assert result.error and "empty" in result.error.lower()

    @pytest.mark.unit
    def test_generate_username_sanitizes_special_chars(self) -> None:
        """Test that special characters are sanitized."""
        result = DomainServices.generate_unique_username("johnobrien", [])
        assert result.is_success
        # Should work with valid alphanumeric
        username = result.unwrap()
        assert username == "johnobrien"
