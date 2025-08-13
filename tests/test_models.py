"""Test FLEXT LDAP Models - Domain models and value objects."""

from __future__ import annotations

from flext_ldap.models import (
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapGroup,
    FlextLdapUser,
)


class TestFlextLdapDistinguishedName:
    """Test DN value object."""

    def test_create_valid_dn(self) -> None:
        """Test creating valid DN."""
        result = FlextLdapDistinguishedName.create("cn=test,dc=example,dc=com")
        assert result.is_success
        assert result.data is not None

    def test_create_invalid_dn(self) -> None:
        """Test creating invalid DN."""
        result = FlextLdapDistinguishedName.create("")
        assert result.is_failure


class TestFlextLdapFilter:
    """Test LDAP filter value object."""

    def test_create_valid_filter(self) -> None:
        """Test creating valid filter."""
        result = FlextLdapFilter.create("(objectClass=person)")
        assert result.is_success
        assert result.data is not None

    def test_create_empty_filter(self) -> None:
        """Test creating empty filter."""
        result = FlextLdapFilter.create("")
        assert result.is_failure


class TestFlextLdapModels:
    """Test LDAP domain models."""

    def test_ldap_entry_creation(self) -> None:
        """Test LDAP entry model creation."""
        entry = FlextLdapEntry(
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
            attributes={"cn": "test"},
        )
        assert entry.dn == "cn=test,dc=example,dc=com"

    def test_ldap_user_creation(self) -> None:
        """Test LDAP user model creation."""
        user = FlextLdapUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            object_classes=["person", "inetOrgPerson"],
            attributes={"uid": "testuser", "cn": "Test User"},
        )
        assert user.dn == "uid=testuser,ou=users,dc=example,dc=com"
        assert "person" in user.object_classes

    def test_ldap_group_creation(self) -> None:
        """Test LDAP group model creation."""
        group = FlextLdapGroup(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            object_classes=["groupOfNames"],
            attributes={"cn": "testgroup"},
        )
        assert group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
