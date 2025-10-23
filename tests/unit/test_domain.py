"""Simplified tests for FlextLdapDomain module."""

from flext_ldap.domain import FlextLdapDomain
from flext_ldap.models import FlextLdapModels


class TestFlextLdapDomainSimple:
    """Simple, working tests for FlextLdapDomain."""

    def test_domain_namespace_exists(self) -> None:
        """Test domain namespace exists."""
        assert FlextLdapDomain is not None
        assert hasattr(FlextLdapDomain, "UserSpecification")
        assert hasattr(FlextLdapDomain, "GroupSpecification")
        assert hasattr(FlextLdapDomain, "SearchSpecification")
        assert hasattr(FlextLdapDomain, "DomainServices")

    def test_user_specification_valid_username(self) -> None:
        """Test valid username."""
        assert FlextLdapDomain.UserSpecification.is_valid_username("john_doe")
        assert FlextLdapDomain.UserSpecification.is_valid_username("user123")

    def test_user_specification_invalid_username(self) -> None:
        """Test invalid username."""
        assert not FlextLdapDomain.UserSpecification.is_valid_username("")
        assert not FlextLdapDomain.UserSpecification.is_valid_username("ab")

    def test_user_specification_password_policy(self) -> None:
        """Test password policy."""
        result = FlextLdapDomain.UserSpecification.meets_password_policy("Password123")
        assert result.is_success

    def test_group_specification_valid_name(self) -> None:
        """Test valid group name."""
        assert FlextLdapDomain.GroupSpecification.is_valid_group_name("REDACTED_LDAP_BIND_PASSWORD_users")
        assert FlextLdapDomain.GroupSpecification.is_valid_group_name("group123")

    def test_group_specification_invalid_name(self) -> None:
        """Test invalid group name."""
        assert not FlextLdapDomain.GroupSpecification.is_valid_group_name("")
        assert not FlextLdapDomain.GroupSpecification.is_valid_group_name(
            "g"
        )  # Too short

    def test_domain_services_display_name(self) -> None:
        """Test calculate display name."""
        user = FlextLdapModels.Entry(
            dn="cn=john,dc=example,dc=com",
            object_classes=["inetOrgPerson"],
            attributes={
                "cn": ["john"],
                "givenName": ["John"],
                "sn": ["Doe"],
            },
        )
        result = FlextLdapDomain.DomainServices.calculate_user_display_name(user)
        assert result == "John Doe"

    def test_domain_services_user_status(self) -> None:
        """Test determine user status."""
        user = FlextLdapModels.Entry(
            dn="cn=john,dc=example,dc=com",
            object_classes=["inetOrgPerson"],
            attributes={"cn": ["john"]},
        )
        result = FlextLdapDomain.DomainServices.determine_user_status(user)
        assert result == "active"

    def test_domain_services_unique_username(self) -> None:
        """Test generate unique username."""
        result = FlextLdapDomain.DomainServices.generate_unique_username("john", [])
        assert result.is_success
        assert result.unwrap() == "john"
