"""Tests for LDAP models."""

import pytest
from pydantic import ValidationError

from flext_ldap.models import (
    ExtendedLDAPEntry,
    FlextLdapExtendedEntry,
    FlextLdapFilter,
    FlextLdapScope,
    LDAPFilter,
    LDAPScope,
)


class TestFlextLdapScope:
    """Test LDAP scope enumeration."""

    def test_scope_values(self) -> None:
        """Test scope enum values."""
        assert FlextLdapScope.BASE == "BASE"
        assert FlextLdapScope.ONE == "ONE"
        assert FlextLdapScope.SUB == "SUB"

    def test_backward_compatibility_mappings(self) -> None:
        """Test backward compatibility mappings."""
        assert FlextLdapScope.ONELEVEL.value == "ONE"
        assert FlextLdapScope.SUBTREE.value == "SUB"

    def test_scope_membership(self) -> None:
        """Test scope membership."""
        valid_scopes = ["BASE", "ONE", "SUB"]
        for scope in valid_scopes:
            assert scope in FlextLdapScope.__members__.values()

    def test_backward_compatibility_alias(self) -> None:
        """Test backward compatibility alias."""
        assert LDAPScope is FlextLdapScope


class TestFlextLdapExtendedEntry:
    """Test extended LDAP entry model."""

    def test_entry_creation_minimal(self) -> None:
        """Test creating entry with minimal required fields."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.dn == "cn=test,dc=example,dc=org"
        assert entry.attributes == {}

    def test_entry_creation_with_attributes(self) -> None:
        """Test creating entry with attributes."""
        attributes = {
            "cn": ["Test User"],
            "uid": ["testuser"],
            "mail": ["test@example.org", "alt@example.org"],
            "objectClass": ["inetOrgPerson"]
        }
        entry = FlextLdapExtendedEntry(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            attributes=attributes
        )
        assert entry.dn == "uid=testuser,ou=users,dc=example,dc=org"
        assert entry.attributes == attributes

    def test_get_attribute_exists(self) -> None:
        """Test getting existing attribute."""
        attributes = {"cn": ["Test User"], "mail": ["test@example.org"]}
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org", attributes=attributes)

        assert entry.get_attribute("cn") == ["Test User"]
        assert entry.get_attribute("mail") == ["test@example.org"]

    def test_get_attribute_not_exists(self) -> None:
        """Test getting non-existent attribute."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.get_attribute("nonexistent") is None

    def test_set_attribute_new(self) -> None:
        """Test setting new attribute."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        entry.set_attribute("cn", ["Test User"])
        assert entry.get_attribute("cn") == ["Test User"]

    def test_set_attribute_existing(self) -> None:
        """Test setting existing attribute."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"cn": ["Old Name"]}
        )
        entry.set_attribute("cn", ["New Name"])
        assert entry.get_attribute("cn") == ["New Name"]

    def test_set_attribute_multiple_values(self) -> None:
        """Test setting attribute with multiple values."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        mail_values = ["test@example.org", "alt@example.org"]
        entry.set_attribute("mail", mail_values)
        assert entry.get_attribute("mail") == mail_values

    def test_has_attribute_true(self) -> None:
        """Test has_attribute returns True for existing attribute."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"cn": ["Test User"]}
        )
        assert entry.has_attribute("cn") is True

    def test_has_attribute_false(self) -> None:
        """Test has_attribute returns False for non-existent attribute."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.has_attribute("nonexistent") is False

    def test_get_single_attribute_exists(self) -> None:
        """Test getting single value from existing attribute."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"cn": ["Test User"]}
        )
        assert entry.get_single_attribute("cn") == "Test User"

    def test_get_single_attribute_multiple_values(self) -> None:
        """Test getting single value from attribute with multiple values."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"mail": ["first@example.org", "second@example.org"]}
        )
        assert entry.get_single_attribute("mail") == "first@example.org"

    def test_get_single_attribute_not_exists(self) -> None:
        """Test getting single value from non-existent attribute."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.get_single_attribute("nonexistent") is None

    def test_get_cn(self) -> None:
        """Test getting common name."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"cn": ["Test User"]}
        )
        assert entry.get_cn() == "Test User"

    def test_get_cn_not_exists(self) -> None:
        """Test getting common name when it doesn't exist."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.get_cn() is None

    def test_get_uid(self) -> None:
        """Test getting user identifier."""
        entry = FlextLdapExtendedEntry(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            attributes={"uid": ["testuser"]}
        )
        assert entry.get_uid() == "testuser"

    def test_get_uid_not_exists(self) -> None:
        """Test getting user identifier when it doesn't exist."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.get_uid() is None

    def test_get_mail(self) -> None:
        """Test getting email address."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"mail": ["test@example.org"]}
        )
        assert entry.get_mail() == "test@example.org"

    def test_get_mail_not_exists(self) -> None:
        """Test getting email address when it doesn't exist."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.get_mail() is None

    def test_is_person_true(self) -> None:
        """Test is_person returns True for person object class."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"objectClass": ["person", "inetOrgPerson"]}
        )
        assert entry.is_person() is True

    def test_is_person_true_case_insensitive(self) -> None:
        """Test is_person is case insensitive."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"objectClass": ["PERSON", "organizationalPerson"]}
        )
        assert entry.is_person() is True

    def test_is_person_false(self) -> None:
        """Test is_person returns False for non-person object class."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"objectClass": ["group", "organizationalUnit"]}
        )
        assert entry.is_person() is False

    def test_is_person_no_object_class(self) -> None:
        """Test is_person returns False when no objectClass attribute."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.is_person() is False

    def test_is_group_true_group(self) -> None:
        """Test is_group returns True for group object class."""
        entry = FlextLdapExtendedEntry(
            dn="cn=testgroup,ou=groups,dc=example,dc=org",
            attributes={"objectClass": ["group"]}
        )
        assert entry.is_group() is True

    def test_is_group_true_groupofnames(self) -> None:
        """Test is_group returns True for groupOfNames object class."""
        entry = FlextLdapExtendedEntry(
            dn="cn=testgroup,ou=groups,dc=example,dc=org",
            attributes={"objectClass": ["groupOfNames"]}
        )
        assert entry.is_group() is True

    def test_is_group_true_groupofuniquenames(self) -> None:
        """Test is_group returns True for groupOfUniqueNames object class."""
        entry = FlextLdapExtendedEntry(
            dn="cn=testgroup,ou=groups,dc=example,dc=org",
            attributes={"objectClass": ["groupOfUniqueNames"]}
        )
        assert entry.is_group() is True

    def test_is_group_true_case_insensitive(self) -> None:
        """Test is_group is case insensitive."""
        entry = FlextLdapExtendedEntry(
            dn="cn=testgroup,ou=groups,dc=example,dc=org",
            attributes={"objectClass": ["GROUP", "organizationalUnit"]}
        )
        assert entry.is_group() is True

    def test_is_group_false(self) -> None:
        """Test is_group returns False for non-group object class."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"objectClass": ["person", "inetOrgPerson"]}
        )
        assert entry.is_group() is False

    def test_is_group_no_object_class(self) -> None:
        """Test is_group returns False when no objectClass attribute."""
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        assert entry.is_group() is False

    def test_validate_domain_rules_success(self) -> None:
        """Test domain rules validation with valid entry."""
        entry = FlextLdapExtendedEntry(
            dn="cn=test,dc=example,dc=org",
            attributes={"cn": ["Test User"]}
        )
        # Should not raise
        entry.validate_domain_rules()

    def test_validate_domain_rules_empty_dn(self) -> None:
        """Test domain rules validation with empty DN."""
        entry = FlextLdapExtendedEntry(dn="", attributes={})
        with pytest.raises(ValueError, match="LDAP entry must have a distinguished name"):
            entry.validate_domain_rules()

    def test_validate_domain_rules_invalid_attributes_type(self) -> None:
        """Test domain rules validation with invalid attributes type."""
        # We can't easily create an invalid type due to Pydantic validation
        # but we can test the validation logic
        entry = FlextLdapExtendedEntry(dn="cn=test,dc=example,dc=org")
        # Manually set invalid type to test domain validation
        object.__setattr__(entry, "attributes", "invalid")
        with pytest.raises(TypeError, match="LDAP attributes must be a dictionary"):
            entry.validate_domain_rules()

    def test_backward_compatibility_alias(self) -> None:
        """Test backward compatibility alias."""
        assert ExtendedLDAPEntry is FlextLdapExtendedEntry


class TestFlextLdapFilter:
    """Test LDAP filter model."""

    def test_filter_creation(self) -> None:
        """Test creating LDAP filter."""
        filter_obj = FlextLdapFilter(filter_string="(cn=admin)")
        assert filter_obj.filter_string == "(cn=admin)"
        assert str(filter_obj) == "(cn=admin)"

    def test_equals_filter(self) -> None:
        """Test creating equals filter."""
        filter_obj = FlextLdapFilter.equals("cn", "admin")
        assert filter_obj.filter_string == "(cn=admin)"

    def test_contains_filter(self) -> None:
        """Test creating contains filter."""
        filter_obj = FlextLdapFilter.contains("cn", "test")
        assert filter_obj.filter_string == "(cn=*test*)"

    def test_starts_with_filter(self) -> None:
        """Test creating starts-with filter."""
        filter_obj = FlextLdapFilter.starts_with("cn", "admin")
        assert filter_obj.filter_string == "(cn=admin*)"

    def test_ends_with_filter(self) -> None:
        """Test creating ends-with filter."""
        filter_obj = FlextLdapFilter.ends_with("cn", "admin")
        assert filter_obj.filter_string == "(cn=*admin)"

    def test_present_filter(self) -> None:
        """Test creating presence filter."""
        filter_obj = FlextLdapFilter.present("mail")
        assert filter_obj.filter_string == "(mail=*)"

    def test_not_equals_filter(self) -> None:
        """Test creating not-equals filter."""
        filter_obj = FlextLdapFilter.not_equals("cn", "admin")
        assert filter_obj.filter_string == "(!(cn=admin))"

    def test_and_filter_single(self) -> None:
        """Test AND filter with single filter."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        result = FlextLdapFilter.and_filter(filter1)
        assert result.filter_string == "(&(cn=admin))"

    def test_and_filter_multiple(self) -> None:
        """Test AND filter with multiple filters."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        filter2 = FlextLdapFilter(filter_string="(objectClass=person)")
        result = FlextLdapFilter.and_filter(filter1, filter2)
        assert result.filter_string == "(&(cn=admin)(objectClass=person))"

    def test_or_filter_single(self) -> None:
        """Test OR filter with single filter."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        result = FlextLdapFilter.or_filter(filter1)
        assert result.filter_string == "(|(cn=admin))"

    def test_or_filter_multiple(self) -> None:
        """Test OR filter with multiple filters."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        filter2 = FlextLdapFilter(filter_string="(cn=user)")
        result = FlextLdapFilter.or_filter(filter1, filter2)
        assert result.filter_string == "(|(cn=admin)(cn=user))"

    def test_not_filter(self) -> None:
        """Test NOT filter."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        result = FlextLdapFilter.not_filter(filter1)
        assert result.filter_string == "(!(cn=admin))"

    def test_person_filter(self) -> None:
        """Test person filter."""
        filter_obj = FlextLdapFilter.person_filter()
        assert filter_obj.filter_string == "(object_class=person)"

    def test_group_filter(self) -> None:
        """Test group filter."""
        filter_obj = FlextLdapFilter.group_filter()
        expected = "(|(object_class=group)(object_class=groupOfNames)(object_class=groupOfUniqueNames))"
        assert filter_obj.filter_string == expected

    def test_and_operator(self) -> None:
        """Test AND operator (&)."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        filter2 = FlextLdapFilter(filter_string="(objectClass=person)")
        result = filter1 & filter2
        assert result.filter_string == "(&(cn=admin)(objectClass=person))"

    def test_or_operator(self) -> None:
        """Test OR operator (|)."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        filter2 = FlextLdapFilter(filter_string="(cn=user)")
        result = filter1 | filter2
        assert result.filter_string == "(|(cn=admin)(cn=user))"

    def test_not_operator(self) -> None:
        """Test NOT operator (~)."""
        filter1 = FlextLdapFilter(filter_string="(cn=admin)")
        result = ~filter1
        assert result.filter_string == "(!(cn=admin))"

    def test_complex_filter_combination(self) -> None:
        """Test complex filter combinations."""
        person_filter = FlextLdapFilter.equals("objectClass", "person")
        name_filter = FlextLdapFilter.starts_with("cn", "admin")
        mail_filter = FlextLdapFilter.present("mail")

        # ((objectClass=person) AND (cn=admin*)) OR (mail=*)
        complex_filter = (person_filter & name_filter) | mail_filter
        expected = "(|(&(objectClass=person)(cn=admin*))(mail=*))"
        assert complex_filter.filter_string == expected

    def test_validate_domain_rules_success(self) -> None:
        """Test domain rules validation with valid filter."""
        filter_obj = FlextLdapFilter(filter_string="(cn=admin)")
        # Should not raise
        filter_obj.validate_domain_rules()

    def test_validate_domain_rules_empty_filter(self) -> None:
        """Test domain rules validation with empty filter string."""
        filter_obj = FlextLdapFilter(filter_string="")
        with pytest.raises(ValueError, match="LDAP filter must have a filter string"):
            filter_obj.validate_domain_rules()

    def test_validate_domain_rules_missing_parentheses(self) -> None:
        """Test domain rules validation with missing parentheses."""
        filter_obj = FlextLdapFilter(filter_string="cn=admin")
        with pytest.raises(ValueError, match="LDAP filter string must be enclosed in parentheses"):
            filter_obj.validate_domain_rules()

    def test_validate_domain_rules_missing_opening_parenthesis(self) -> None:
        """Test domain rules validation with missing opening parenthesis."""
        filter_obj = FlextLdapFilter(filter_string="cn=admin)")
        with pytest.raises(ValueError, match="LDAP filter string must be enclosed in parentheses"):
            filter_obj.validate_domain_rules()

    def test_validate_domain_rules_missing_closing_parenthesis(self) -> None:
        """Test domain rules validation with missing closing parenthesis."""
        filter_obj = FlextLdapFilter(filter_string="(cn=admin")
        with pytest.raises(ValueError, match="LDAP filter string must be enclosed in parentheses"):
            filter_obj.validate_domain_rules()

    def test_backward_compatibility_alias(self) -> None:
        """Test backward compatibility alias."""
        assert LDAPFilter is FlextLdapFilter


class TestBackwardCompatibility:
    """Test backward compatibility features."""

    def test_all_aliases_exist(self) -> None:
        """Test that all backward compatibility aliases exist."""
        # Import all the aliases to ensure they're available
        from flext_ldap.models import (
            ExtendedLDAPEntry,
            LDAPFilter,
            LDAPScope,
        )

        # Verify they're the same as the new classes
        assert ExtendedLDAPEntry is FlextLdapExtendedEntry
        assert LDAPFilter is FlextLdapFilter
        assert LDAPScope is FlextLdapScope

    def test_module_exports(self) -> None:
        """Test that module exports contain expected items."""
        from flext_ldap import models

        # Check that __all__ contains expected items
        expected_exports = [
            "ExtendedLDAPEntry",
            "FlextLdapExtendedEntry",
            "FlextLdapFilter",
            "FlextLdapScope",
            "LDAPScope",
        ]

        for export in expected_exports:
            assert export in models.__all__
