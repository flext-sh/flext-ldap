"""Tests for LDAP domain specifications."""

from unittest.mock import MagicMock

import pytest

from flext_ldap.domain.specifications import (
    FlextLdapActiveUserSpecification,
    FlextLdapDistinguishedNameSpecification,
    FlextLdapEntrySpecification,
    FlextLdapFilterSpecification,
    FlextLdapGroupSpecification,
    FlextLdapNonEmptyGroupSpecification,
    FlextLdapSpecification,
    FlextLdapUserSpecification,
    FlextLdapValidEntrySpecification,
    FlextLdapValidPasswordSpecification,
)


class TestFlextLdapSpecification:
    """Test base specification interface."""

    def test_is_abstract(self) -> None:
        """Test that base specification is abstract."""
        with pytest.raises(TypeError):
            FlextLdapSpecification()


class TestFlextLdapEntrySpecification:
    """Test LDAP entry specification."""

    def test_is_satisfied_by_valid_entry(self) -> None:
        """Test specification with valid entry."""
        spec = FlextLdapEntrySpecification()

        # Mock entry with DN and attributes
        entry = MagicMock()
        entry.dn = "cn=test,dc=example,dc=org"
        entry.attributes = {"cn": ["test"]}

        assert spec.is_satisfied_by(entry) is True

    def test_is_satisfied_by_no_dn(self) -> None:
        """Test specification with entry without DN."""
        spec = FlextLdapEntrySpecification()

        # Mock entry without DN
        entry = MagicMock()
        entry.dn = ""
        entry.attributes = {"cn": ["test"]}

        assert spec.is_satisfied_by(entry) is False

    def test_is_satisfied_by_no_attributes(self) -> None:
        """Test specification with entry without attributes."""
        spec = FlextLdapEntrySpecification()

        # Mock entry without attributes
        entry = MagicMock()
        entry.dn = "cn=test,dc=example,dc=org"
        entry.attributes = {}

        assert spec.is_satisfied_by(entry) is False

    def test_is_satisfied_by_none_dn(self) -> None:
        """Test specification with None DN."""
        spec = FlextLdapEntrySpecification()

        # Mock entry with None DN
        entry = MagicMock()
        entry.dn = None
        entry.attributes = {"cn": ["test"]}

        assert spec.is_satisfied_by(entry) is False


class TestFlextLdapValidEntrySpecification:
    """Test valid LDAP entry specification."""

    def test_is_satisfied_by_valid_entry(self) -> None:
        """Test specification with valid entry."""
        spec = FlextLdapValidEntrySpecification()

        # Mock valid entry
        entry = MagicMock()
        entry.dn = "cn=test,dc=example,dc=org"
        entry.attributes = {"objectClass": ["person"], "cn": ["test"]}

        assert spec.is_satisfied_by(entry) is True

    def test_is_satisfied_by_no_object_class(self) -> None:
        """Test specification with entry without objectClass."""
        spec = FlextLdapValidEntrySpecification()

        # Mock entry without objectClass
        entry = MagicMock()
        entry.dn = "cn=test,dc=example,dc=org"
        entry.attributes = {"cn": ["test"]}

        assert spec.is_satisfied_by(entry) is False

    def test_is_satisfied_by_empty_object_class(self) -> None:
        """Test specification with empty objectClass."""
        spec = FlextLdapValidEntrySpecification()

        # Mock entry with empty objectClass
        entry = MagicMock()
        entry.dn = "cn=test,dc=example,dc=org"
        entry.attributes = {"objectClass": [], "cn": ["test"]}

        assert spec.is_satisfied_by(entry) is False

    def test_is_satisfied_by_invalid_dn_format(self) -> None:
        """Test specification with invalid DN format."""
        spec = FlextLdapValidEntrySpecification()

        # Mock entry with invalid DN
        entry = MagicMock()
        entry.dn = "invalid_dn"
        entry.attributes = {"objectClass": ["person"], "cn": ["test"]}

        assert spec.is_satisfied_by(entry) is False

    def test_is_satisfied_by_fails_parent_spec(self) -> None:
        """Test specification when parent specification fails."""
        spec = FlextLdapValidEntrySpecification()

        # Mock entry that fails parent specification (no DN)
        entry = MagicMock()
        entry.dn = ""
        entry.attributes = {"objectClass": ["person"], "cn": ["test"]}

        assert spec.is_satisfied_by(entry) is False


class TestFlextLdapUserSpecification:
    """Test LDAP user specification."""

    def test_is_satisfied_by_valid_user(self) -> None:
        """Test specification with valid user."""
        spec = FlextLdapUserSpecification()

        # Mock valid user
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"

        assert spec.is_satisfied_by(user) is True

    def test_is_satisfied_by_no_dn(self) -> None:
        """Test specification with user without DN."""
        spec = FlextLdapUserSpecification()

        # Mock user without DN
        user = MagicMock()
        user.dn = ""
        user.uid = "testuser"

        assert spec.is_satisfied_by(user) is False

    def test_is_satisfied_by_no_uid(self) -> None:
        """Test specification with user without UID."""
        spec = FlextLdapUserSpecification()

        # Mock user without UID
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = ""

        assert spec.is_satisfied_by(user) is False

    def test_is_satisfied_by_none_values(self) -> None:
        """Test specification with None values."""
        spec = FlextLdapUserSpecification()

        # Mock user with None values
        user = MagicMock()
        user.dn = None
        user.uid = None

        assert spec.is_satisfied_by(user) is False


class TestFlextLdapActiveUserSpecification:
    """Test active LDAP user specification."""

    def test_is_satisfied_by_active_user(self) -> None:
        """Test specification with active user."""
        spec = FlextLdapActiveUserSpecification()

        # Mock active user
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {}

        assert spec.is_satisfied_by(user) is True

    def test_is_satisfied_by_disabled_account_control(self) -> None:
        """Test specification with disabled userAccountControl."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with disabled account (bit 2 set)
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"userAccountControl": ["514"]}  # 512 + 2 = disabled

        assert spec.is_satisfied_by(user) is False

    def test_is_satisfied_by_enabled_account_control(self) -> None:
        """Test specification with enabled userAccountControl."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with enabled account (bit 2 not set)
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"userAccountControl": ["512"]}  # Normal account

        assert spec.is_satisfied_by(user) is True

    def test_is_satisfied_by_account_control_string(self) -> None:
        """Test specification with userAccountControl as string."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with userAccountControl as string
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"userAccountControl": "514"}  # Disabled

        assert spec.is_satisfied_by(user) is False

    def test_is_satisfied_by_invalid_account_control(self) -> None:
        """Test specification with invalid userAccountControl."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with invalid userAccountControl
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"userAccountControl": ["invalid"]}

        # Should return True when userAccountControl is invalid (default to active)
        assert spec.is_satisfied_by(user) is True

    def test_is_satisfied_by_account_disabled_true(self) -> None:
        """Test specification with accountDisabled set to true."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with accountDisabled = true
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"accountDisabled": ["true"]}

        assert spec.is_satisfied_by(user) is False

    def test_is_satisfied_by_account_disabled_false(self) -> None:
        """Test specification with accountDisabled set to false."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with accountDisabled = false
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"accountDisabled": ["false"]}

        assert spec.is_satisfied_by(user) is True

    def test_is_satisfied_by_account_disabled_string(self) -> None:
        """Test specification with accountDisabled as string."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user with accountDisabled as string
        user = MagicMock()
        user.dn = "uid=testuser,ou=users,dc=example,dc=org"
        user.uid = "testuser"
        user.attributes = {"accountDisabled": "TRUE"}

        assert spec.is_satisfied_by(user) is False

    def test_is_satisfied_by_fails_parent_spec(self) -> None:
        """Test specification when parent specification fails."""
        spec = FlextLdapActiveUserSpecification()

        # Mock user that fails parent specification
        user = MagicMock()
        user.dn = ""  # Invalid DN
        user.uid = "testuser"
        user.attributes = {}

        assert spec.is_satisfied_by(user) is False


class TestFlextLdapValidPasswordSpecification:
    """Test valid password specification."""

    def test_is_satisfied_by_valid_password_default(self) -> None:
        """Test specification with valid password using defaults."""
        spec = FlextLdapValidPasswordSpecification()

        # Valid password with minimum length and special chars
        password = "Password123!"
        assert spec.is_satisfied_by(password) is True

    def test_is_satisfied_by_too_short(self) -> None:
        """Test specification with password too short."""
        spec = FlextLdapValidPasswordSpecification(min_length=10)

        # Password too short
        password = "Pass123!"
        assert spec.is_satisfied_by(password) is False

    def test_is_satisfied_by_no_special_chars(self) -> None:
        """Test specification with password missing special chars."""
        spec = FlextLdapValidPasswordSpecification(require_special_chars=True)

        # Password without special characters
        password = "Password123"
        assert spec.is_satisfied_by(password) is False

    def test_is_satisfied_by_no_special_chars_not_required(self) -> None:
        """Test specification when special chars not required."""
        spec = FlextLdapValidPasswordSpecification(require_special_chars=False)

        # Password without special characters, but not required
        password = "Password123"
        assert spec.is_satisfied_by(password) is True

    def test_is_satisfied_by_custom_min_length(self) -> None:
        """Test specification with custom minimum length."""
        spec = FlextLdapValidPasswordSpecification(min_length=12)

        # Password meeting custom length requirement
        password = "LongPassword123!"
        assert spec.is_satisfied_by(password) is True

    def test_is_satisfied_by_various_special_chars(self) -> None:
        """Test specification with various special characters."""
        spec = FlextLdapValidPasswordSpecification()

        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        for char in special_chars:
            password = f"Password123{char}"
            assert spec.is_satisfied_by(password) is True

    def test_initialization_defaults(self) -> None:
        """Test specification initialization with defaults."""
        spec = FlextLdapValidPasswordSpecification()
        assert spec.min_length == 8
        assert spec.require_special_chars is True

    def test_initialization_custom(self) -> None:
        """Test specification initialization with custom values."""
        spec = FlextLdapValidPasswordSpecification(
            min_length=10, require_special_chars=False,
        )
        assert spec.min_length == 10
        assert spec.require_special_chars is False


class TestFlextLdapGroupSpecification:
    """Test LDAP group specification."""

    def test_is_satisfied_by_valid_group(self) -> None:
        """Test specification with valid group."""
        spec = FlextLdapGroupSpecification()

        # Mock valid group
        group = MagicMock()
        group.dn = "cn=testgroup,ou=groups,dc=example,dc=org"
        group.cn = "testgroup"

        assert spec.is_satisfied_by(group) is True

    def test_is_satisfied_by_no_dn(self) -> None:
        """Test specification with group without DN."""
        spec = FlextLdapGroupSpecification()

        # Mock group without DN
        group = MagicMock()
        group.dn = ""
        group.cn = "testgroup"

        assert spec.is_satisfied_by(group) is False

    def test_is_satisfied_by_no_cn(self) -> None:
        """Test specification with group without CN."""
        spec = FlextLdapGroupSpecification()

        # Mock group without CN
        group = MagicMock()
        group.dn = "cn=testgroup,ou=groups,dc=example,dc=org"
        group.cn = ""

        assert spec.is_satisfied_by(group) is False

    def test_is_satisfied_by_none_values(self) -> None:
        """Test specification with None values."""
        spec = FlextLdapGroupSpecification()

        # Mock group with None values
        group = MagicMock()
        group.dn = None
        group.cn = None

        assert spec.is_satisfied_by(group) is False


class TestFlextLdapNonEmptyGroupSpecification:
    """Test non-empty LDAP group specification."""

    def test_is_satisfied_by_group_with_members(self) -> None:
        """Test specification with group having members."""
        spec = FlextLdapNonEmptyGroupSpecification()

        # Mock group with members
        group = MagicMock()
        group.dn = "cn=testgroup,ou=groups,dc=example,dc=org"
        group.cn = "testgroup"
        group.members = ["uid=user1,ou=users,dc=example,dc=org"]

        assert spec.is_satisfied_by(group) is True

    def test_is_satisfied_by_empty_group(self) -> None:
        """Test specification with empty group."""
        spec = FlextLdapNonEmptyGroupSpecification()

        # Mock empty group
        group = MagicMock()
        group.dn = "cn=testgroup,ou=groups,dc=example,dc=org"
        group.cn = "testgroup"
        group.members = []

        assert spec.is_satisfied_by(group) is False

    def test_is_satisfied_by_fails_parent_spec(self) -> None:
        """Test specification when parent specification fails."""
        spec = FlextLdapNonEmptyGroupSpecification()

        # Mock group that fails parent specification
        group = MagicMock()
        group.dn = ""  # Invalid DN
        group.cn = "testgroup"
        group.members = ["uid=user1,ou=users,dc=example,dc=org"]

        assert spec.is_satisfied_by(group) is False


class TestFlextLdapDistinguishedNameSpecification:
    """Test distinguished name specification."""

    def test_is_satisfied_by_valid_dn(self) -> None:
        """Test specification with valid DN."""
        spec = FlextLdapDistinguishedNameSpecification()

        valid_dns = [
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",
            "uid=user,ou=users,dc=example,dc=org",
            "cn=group,ou=groups,dc=company,dc=com",
            "o=organization,c=us",
        ]

        for dn in valid_dns:
            assert spec.is_satisfied_by(dn) is True

    def test_is_satisfied_by_empty_dn(self) -> None:
        """Test specification with empty DN."""
        spec = FlextLdapDistinguishedNameSpecification()

        assert spec.is_satisfied_by("") is False

    def test_is_satisfied_by_none_dn(self) -> None:
        """Test specification with None DN."""
        spec = FlextLdapDistinguishedNameSpecification()

        assert spec.is_satisfied_by(None) is False

    def test_is_satisfied_by_non_string_dn(self) -> None:
        """Test specification with non-string DN."""
        spec = FlextLdapDistinguishedNameSpecification()

        assert spec.is_satisfied_by(123) is False

    def test_is_satisfied_by_no_equals(self) -> None:
        """Test specification with DN without equals."""
        spec = FlextLdapDistinguishedNameSpecification()

        assert spec.is_satisfied_by("invalid_dn") is False

    def test_is_satisfied_by_invalid_component(self) -> None:
        """Test specification with invalid DN component."""
        spec = FlextLdapDistinguishedNameSpecification()

        invalid_dns = [
            "cn=REDACTED_LDAP_BIND_PASSWORD,invalid,dc=org",  # Component without =
            "cn=REDACTED_LDAP_BIND_PASSWORD,=value,dc=org",  # Empty attribute name
            "cn=REDACTED_LDAP_BIND_PASSWORD,attr=,dc=org",  # Empty attribute value
            "cn=,dc=example,dc=org",  # Empty CN value
            "=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",  # Empty attribute name
        ]

        for dn in invalid_dns:
            assert spec.is_satisfied_by(dn) is False

    def test_is_satisfied_by_dn_with_spaces(self) -> None:
        """Test specification with DN containing spaces."""
        spec = FlextLdapDistinguishedNameSpecification()

        # DN with spaces around components (should be valid after strip)
        dn = "cn=REDACTED_LDAP_BIND_PASSWORD , ou=users , dc=example , dc=org"
        assert spec.is_satisfied_by(dn) is True


class TestFlextLdapFilterSpecification:
    """Test LDAP filter specification."""

    def test_is_satisfied_by_valid_filter(self) -> None:
        """Test specification with valid filters."""
        spec = FlextLdapFilterSpecification()

        valid_filters = [
            "(cn=REDACTED_LDAP_BIND_PASSWORD)",
            "(objectClass=person)",
            "(&(cn=REDACTED_LDAP_BIND_PASSWORD)(objectClass=person))",
            "(|(cn=REDACTED_LDAP_BIND_PASSWORD)(cn=user))",
            "(!(cn=REDACTED_LDAP_BIND_PASSWORD))",
            "(cn=*)",
        ]

        for filter_str in valid_filters:
            assert spec.is_satisfied_by(filter_str) is True

    def test_is_satisfied_by_empty_filter(self) -> None:
        """Test specification with empty filter."""
        spec = FlextLdapFilterSpecification()

        assert spec.is_satisfied_by("") is False

    def test_is_satisfied_by_none_filter(self) -> None:
        """Test specification with None filter."""
        spec = FlextLdapFilterSpecification()

        assert spec.is_satisfied_by(None) is False

    def test_is_satisfied_by_non_string_filter(self) -> None:
        """Test specification with non-string filter."""
        spec = FlextLdapFilterSpecification()

        assert spec.is_satisfied_by(123) is False

    def test_is_satisfied_by_no_parentheses(self) -> None:
        """Test specification with filter without parentheses."""
        spec = FlextLdapFilterSpecification()

        assert spec.is_satisfied_by("cn=REDACTED_LDAP_BIND_PASSWORD") is False

    def test_is_satisfied_by_missing_opening_parenthesis(self) -> None:
        """Test specification with missing opening parenthesis."""
        spec = FlextLdapFilterSpecification()

        assert spec.is_satisfied_by("cn=REDACTED_LDAP_BIND_PASSWORD)") is False

    def test_is_satisfied_by_missing_closing_parenthesis(self) -> None:
        """Test specification with missing closing parenthesis."""
        spec = FlextLdapFilterSpecification()

        assert spec.is_satisfied_by("(cn=REDACTED_LDAP_BIND_PASSWORD") is False

    def test_is_satisfied_by_unbalanced_parentheses(self) -> None:
        """Test specification with unbalanced parentheses."""
        spec = FlextLdapFilterSpecification()

        unbalanced_filters = [
            "((cn=REDACTED_LDAP_BIND_PASSWORD)",  # Extra opening
            "(cn=REDACTED_LDAP_BIND_PASSWORD))",  # Extra closing
            "((cn=REDACTED_LDAP_BIND_PASSWORD)(",  # Multiple imbalances
        ]

        for filter_str in unbalanced_filters:
            assert spec.is_satisfied_by(filter_str) is False

    def test_is_satisfied_by_complex_balanced_filter(self) -> None:
        """Test specification with complex but balanced filter."""
        spec = FlextLdapFilterSpecification()

        # Complex nested filter with balanced parentheses
        complex_filter = (
            "(&(|(cn=REDACTED_LDAP_BIND_PASSWORD)(cn=user))(objectClass=person)(!(accountDisabled=true)))"
        )
        assert spec.is_satisfied_by(complex_filter) is True
