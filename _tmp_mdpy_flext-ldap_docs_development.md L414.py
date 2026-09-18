# from flext-ldap/docs/development.md:414
from __future__ import annotations

import pytest
from flext_ldap import FlextLdapUser


class TestFlextLdapUser:
    """Test domain entity behavior."""

    def test_user_validation_success(self):
        """Test valid user data passes validation."""
        user = FlextLdapUser(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
        )

        assert user.is_valid()
        assert user.get_display_name() == "John Doe"

    def test_user_validation_failure(self):
        """Test invalid user data fails validation."""
        user = FlextLdapUser(
            dn="",  # Invalid empty DN
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
        )

        assert not user.is_valid()

    @pytest.mark.parametrize(
        "uid,expected",
        [
            ("john.doe", True),
            ("", False),
            ("a", False),  # Too short
        ],
    )
    def test_uid_validation(self, uid: str, expected: bool):
        """Test UID validation with parameters."""
        user = FlextLdapUser(
            dn="cn=test,dc=example,dc=com", uid=uid, cn="Test User", sn="User"
        )

        assert user.is_valid() == expected```
### Integration Test Structure

