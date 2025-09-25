"""Comprehensive tests for FlextLdapModels.

This module provides complete test coverage for the FlextLdapModels class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapModels


class TestFlextLdapModels:
    """Comprehensive test suite for FlextLdapModels."""

    def test_models_initialization(self) -> None:
        """Test models initialization."""
        models = FlextLdapModels()
        assert models is not None
        assert hasattr(models, "_container")
        assert hasattr(models, "_logger")

    def test_distinguished_name_creation_success(self) -> None:
        """Test successful DistinguishedName creation."""
        dn_string = "uid=testuser,ou=people,dc=example,dc=com"
        dn = FlextLdapModels.DistinguishedName(value=dn_string)

        assert dn.value == dn_string
        assert dn.rdn == "uid=testuser"

    def test_distinguished_name_creation_failure_empty(self) -> None:
        """Test DistinguishedName creation with empty value."""
        with pytest.raises(ValueError, match="Distinguished Name cannot be empty"):
            FlextLdapModels.DistinguishedName(value="")

    def test_distinguished_name_creation_failure_invalid_format(self) -> None:
        """Test DistinguishedName creation with invalid format."""
        with pytest.raises(ValueError, match="Invalid DN format"):
            FlextLdapModels.DistinguishedName(value="invalid-dn-format")

    def test_distinguished_name_create_method_success(self) -> None:
        """Test DistinguishedName create method success."""
        result = FlextLdapModels.DistinguishedName.create(
            "uid=testuser,ou=people,dc=example,dc=com"
        )

        assert result.is_success
        assert isinstance(result.data, FlextLdapModels.DistinguishedName)
        assert result.data.value == "uid=testuser,ou=people,dc=example,dc=com"

    def test_distinguished_name_create_method_failure(self) -> None:
        """Test DistinguishedName create method failure."""
        result = FlextLdapModels.DistinguishedName.create("invalid-dn")

        assert result.is_failure
        assert "Invalid DN format" in result.error

    def test_filter_creation_success(self) -> None:
        """Test successful Filter creation."""
        filter_expr = "(objectClass=person)"
        filter_obj = FlextLdapModels.Filter(expression=filter_expr)

        assert filter_obj.expression == filter_expr

    def test_filter_creation_failure_empty(self) -> None:
        """Test Filter creation with empty expression."""
        with pytest.raises(ValueError, match="LDAP filter cannot be empty"):
            FlextLdapModels.Filter(expression="")

    def test_filter_creation_failure_invalid_format(self) -> None:
        """Test Filter creation with invalid format."""
        with pytest.raises(
            ValueError, match="LDAP filter must be enclosed in parentheses"
        ):
            FlextLdapModels.Filter(expression="objectClass=person")

    def test_filter_equals_method(self) -> None:
        """Test Filter equals method."""
        filter_obj = FlextLdapModels.Filter.equals("objectClass", "person")

        assert filter_obj.expression == "(objectClass=person)"

    def test_filter_starts_with_method(self) -> None:
        """Test Filter starts_with method."""
        filter_obj = FlextLdapModels.Filter.starts_with("cn", "Test")

        assert filter_obj.expression == "(cn=Test*)"

    def test_filter_ends_with_method(self) -> None:
        """Test Filter ends_with method."""
        filter_obj = FlextLdapModels.Filter.ends_with("mail", "@example.com")

        assert filter_obj.expression == "(mail=*@example.com)"

    def test_filter_contains_method(self) -> None:
        """Test Filter contains method."""
        filter_obj = FlextLdapModels.Filter.contains("description", "test")

        assert filter_obj.expression == "(description=*test*)"

    def test_filter_and_method(self) -> None:
        """Test Filter and method."""
        filter1 = FlextLdapModels.Filter.equals("objectClass", "person")
        filter2 = FlextLdapModels.Filter.equals("cn", "Test User")
        combined = FlextLdapModels.Filter.and_filter([filter1, filter2])

        assert combined.expression == "(&(objectClass=person)(cn=Test User))"

    def test_filter_or_method(self) -> None:
        """Test Filter or method."""
        filter1 = FlextLdapModels.Filter.equals("objectClass", "person")
        filter2 = FlextLdapModels.Filter.equals("objectClass", "group")
        combined = FlextLdapModels.Filter.or_filter([filter1, filter2])

        assert combined.expression == "(|(objectClass=person)(objectClass=group))"

    def test_filter_not_method(self) -> None:
        """Test Filter not method."""
        filter_obj = FlextLdapModels.Filter.equals("objectClass", "person")
        negated = FlextLdapModels.Filter.not_filter(filter_obj)

        assert negated.expression == "(!(objectClass=person))"

    def test_user_creation_success(self, sample_user: FlextLdapModels.User) -> None:
        """Test successful User creation."""
        assert sample_user.uid == "testuser"
        assert sample_user.cn == "Test User"
        assert sample_user.sn == "User"
        assert sample_user.mail == "testuser@example.com"

    def test_user_creation_with_minimal_data(self) -> None:
        """Test User creation with minimal required data."""
        user = FlextLdapModels.User(uid="testuser", cn="Test User", sn="User")

        assert user.uid == "testuser"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.mail is None

    def test_user_business_rules_validation_success(
        self, sample_user: FlextLdapModels.User
    ) -> None:
        """Test User business rules validation success."""
        result = sample_user.validate_business_rules()

        assert result.is_success
        assert result.data is True

    def test_user_business_rules_validation_failure(self) -> None:
        """Test User business rules validation failure."""
        user = FlextLdapModels.User(
            uid="",  # Invalid empty uid
            cn="Test User",
            sn="User",
        )

        result = user.validate_business_rules()

        assert result.is_failure
        assert "uid" in result.error.lower()

    def test_user_to_ldap_attributes(self, sample_user: FlextLdapModels.User) -> None:
        """Test User to LDAP attributes conversion."""
        attributes = sample_user.to_ldap_attributes()

        assert "uid" in attributes
        assert "cn" in attributes
        assert "sn" in attributes
        assert "mail" in attributes
        assert attributes["uid"] == ["testuser"]
        assert attributes["cn"] == ["Test User"]

    def test_user_from_ldap_attributes_success(self) -> None:
        """Test User creation from LDAP attributes success."""
        ldap_attributes = {
            "uid": ["testuser"],
            "cn": ["Test User"],
            "sn": ["User"],
            "mail": ["testuser@example.com"],
        }

        result = FlextLdapModels.User.from_ldap_attributes(ldap_attributes)

        assert result.is_success
        assert result.data.uid == "testuser"
        assert result.data.cn == "Test User"

    def test_user_from_ldap_attributes_failure(self) -> None:
        """Test User creation from LDAP attributes failure."""
        invalid_attributes = {"invalid": ["data"]}

        result = FlextLdapModels.User.from_ldap_attributes(invalid_attributes)

        assert result.is_failure
        assert "Invalid user attributes" in result.error

    def test_group_creation_success(self, sample_group: FlextLdapModels.Group) -> None:
        """Test successful Group creation."""
        assert sample_group.cn == "testgroup"
        assert sample_group.description == "Test Group"
        assert len(sample_group.member) == 1
        assert sample_group.member[0] == "uid=testuser,ou=people,dc=example,dc=com"

    def test_group_creation_with_empty_members(self) -> None:
        """Test Group creation with empty members list."""
        group = FlextLdapModels.Group(
            cn="testgroup", description="Test Group", member=[]
        )

        assert group.cn == "testgroup"
        assert group.description == "Test Group"
        assert len(group.member) == 0

    def test_group_business_rules_validation_success(
        self, sample_group: FlextLdapModels.Group
    ) -> None:
        """Test Group business rules validation success."""
        result = sample_group.validate_business_rules()

        assert result.is_success
        assert result.data is True

    def test_group_business_rules_validation_failure(self) -> None:
        """Test Group business rules validation failure."""
        group = FlextLdapModels.Group(
            cn="",  # Invalid empty cn
            description="Test Group",
            member=["uid=testuser,ou=people,dc=example,dc=com"],
        )

        result = group.validate_business_rules()

        assert result.is_failure
        assert "cn" in result.error.lower()

    def test_group_add_member_success(
        self, sample_group: FlextLdapModels.Group
    ) -> None:
        """Test Group add member success."""
        initial_count = len(sample_group.member)
        sample_group.add_member("uid=newuser,ou=people,dc=example,dc=com")

        assert len(sample_group.member) == initial_count + 1
        assert "uid=newuser,ou=people,dc=example,dc=com" in sample_group.member

    def test_group_add_member_duplicate(
        self, sample_group: FlextLdapModels.Group
    ) -> None:
        """Test Group add member duplicate handling."""
        initial_count = len(sample_group.member)
        sample_group.add_member(
            "uid=testuser,ou=people,dc=example,dc=com"
        )  # Already exists

        assert len(sample_group.member) == initial_count  # No change

    def test_group_remove_member_success(
        self, sample_group: FlextLdapModels.Group
    ) -> None:
        """Test Group remove member success."""
        initial_count = len(sample_group.member)
        sample_group.remove_member("uid=testuser,ou=people,dc=example,dc=com")

        assert len(sample_group.member) == initial_count - 1
        assert "uid=testuser,ou=people,dc=example,dc=com" not in sample_group.member

    def test_group_remove_member_not_found(
        self, sample_group: FlextLdapModels.Group
    ) -> None:
        """Test Group remove member when not found."""
        initial_count = len(sample_group.member)
        sample_group.remove_member("uid=nonexistent,ou=people,dc=example,dc=com")

        assert len(sample_group.member) == initial_count  # No change

    def test_group_to_ldap_attributes(
        self, sample_group: FlextLdapModels.Group
    ) -> None:
        """Test Group to LDAP attributes conversion."""
        attributes = sample_group.to_ldap_attributes()

        assert "cn" in attributes
        assert "description" in attributes
        assert "member" in attributes
        assert attributes["cn"] == ["testgroup"]
        assert attributes["description"] == ["Test Group"]

    def test_group_from_ldap_attributes_success(self) -> None:
        """Test Group creation from LDAP attributes success."""
        ldap_attributes = {
            "cn": ["testgroup"],
            "description": ["Test Group"],
            "member": ["uid=testuser,ou=people,dc=example,dc=com"],
        }

        result = FlextLdapModels.Group.from_ldap_attributes(ldap_attributes)

        assert result.is_success
        assert result.data.cn == "testgroup"
        assert result.data.description == "Test Group"

    def test_group_from_ldap_attributes_failure(self) -> None:
        """Test Group creation from LDAP attributes failure."""
        invalid_attributes = {"invalid": ["data"]}

        result = FlextLdapModels.Group.from_ldap_attributes(invalid_attributes)

        assert result.is_failure
        assert "Invalid group attributes" in result.error

    def test_connection_config_creation_success(
        self, ldap_config: FlextLdapModels.ConnectionConfig
    ) -> None:
        """Test successful ConnectionConfig creation."""
        assert ldap_config.server_uri == "ldap://localhost:389"
        assert ldap_config.bind_dn == "cn=admin,dc=example,dc=com"
        assert ldap_config.password == "admin123"
        assert ldap_config.base_dn == "dc=example,dc=com"

    def test_connection_config_validation_success(
        self, ldap_config: FlextLdapModels.ConnectionConfig
    ) -> None:
        """Test ConnectionConfig validation success."""
        result = ldap_config.validate()

        assert result.is_success
        assert result.data is True

    def test_connection_config_validation_failure(
        self, ldap_config_invalid: FlextLdapModels.ConnectionConfig
    ) -> None:
        """Test ConnectionConfig validation failure."""
        result = ldap_config_invalid.validate()

        assert result.is_failure
        assert "Invalid configuration" in result.error

    def test_search_config_creation_success(self) -> None:
        """Test successful SearchConfig creation."""
        search_config = FlextLdapModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn", "mail"],
        )

        assert search_config.base_dn == "dc=example,dc=com"
        assert search_config.search_filter == "(objectClass=person)"
        assert search_config.attributes == ["cn", "sn", "mail"]

    def test_search_config_validation_success(self) -> None:
        """Test SearchConfig validation success."""
        search_config = FlextLdapModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn", "mail"],
        )

        result = search_config.validate()

        assert result.is_success
        assert result.data is True

    def test_search_config_validation_failure(self) -> None:
        """Test SearchConfig validation failure."""
        search_config = FlextLdapModels.SearchConfig(
            base_dn="",  # Invalid empty base_dn
            search_filter="(objectClass=person)",
            attributes=["cn", "sn", "mail"],
        )

        result = search_config.validate()

        assert result.is_failure
        assert "Invalid search configuration" in result.error

    def test_modify_config_creation_success(self) -> None:
        """Test successful ModifyConfig creation."""
        modify_config = FlextLdapModels.ModifyConfig(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            changes={"cn": [("MODIFY_REPLACE", ["New Name"])]},
        )

        assert modify_config.dn == "uid=testuser,ou=people,dc=example,dc=com"
        assert "cn" in modify_config.changes

    def test_modify_config_validation_success(self) -> None:
        """Test ModifyConfig validation success."""
        modify_config = FlextLdapModels.ModifyConfig(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            changes={"cn": [("MODIFY_REPLACE", ["New Name"])]},
        )

        result = modify_config.validate()

        assert result.is_success
        assert result.data is True

    def test_modify_config_validation_failure(self) -> None:
        """Test ModifyConfig validation failure."""
        modify_config = FlextLdapModels.ModifyConfig(
            dn="",  # Invalid empty dn
            changes={"cn": [("MODIFY_REPLACE", ["New Name"])]},
        )

        result = modify_config.validate()

        assert result.is_failure
        assert "Invalid modify configuration" in result.error

    def test_add_config_creation_success(self) -> None:
        """Test successful AddConfig creation."""
        add_config = FlextLdapModels.AddConfig(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            attributes={"cn": ["Test User"], "sn": ["User"]},
        )

        assert add_config.dn == "uid=testuser,ou=people,dc=example,dc=com"
        assert "cn" in add_config.attributes
        assert "sn" in add_config.attributes

    def test_add_config_validation_success(self) -> None:
        """Test AddConfig validation success."""
        add_config = FlextLdapModels.AddConfig(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            attributes={"cn": ["Test User"], "sn": ["User"]},
        )

        result = add_config.validate()

        assert result.is_success
        assert result.data is True

    def test_add_config_validation_failure(self) -> None:
        """Test AddConfig validation failure."""
        add_config = FlextLdapModels.AddConfig(
            dn="",  # Invalid empty dn
            attributes={"cn": ["Test User"], "sn": ["User"]},
        )

        result = add_config.validate()

        assert result.is_failure
        assert "Invalid add configuration" in result.error

    def test_delete_config_creation_success(self) -> None:
        """Test successful DeleteConfig creation."""
        delete_config = FlextLdapModels.DeleteConfig(
            dn="uid=testuser,ou=people,dc=example,dc=com"
        )

        assert delete_config.dn == "uid=testuser,ou=people,dc=example,dc=com"

    def test_delete_config_validation_success(self) -> None:
        """Test DeleteConfig validation success."""
        delete_config = FlextLdapModels.DeleteConfig(
            dn="uid=testuser,ou=people,dc=example,dc=com"
        )

        result = delete_config.validate()

        assert result.is_success
        assert result.data is True

    def test_delete_config_validation_failure(self) -> None:
        """Test DeleteConfig validation failure."""
        delete_config = FlextLdapModels.DeleteConfig(
            dn=""  # Invalid empty dn
        )

        result = delete_config.validate()

        assert result.is_failure
        assert "Invalid delete configuration" in result.error

    def test_models_integration_user_group_relationship(self) -> None:
        """Test integration between User and Group models."""
        user = FlextLdapModels.User(
            uid="testuser", cn="Test User", sn="User", mail="testuser@example.com"
        )

        group = FlextLdapModels.Group(
            cn="testgroup", description="Test Group", member=[user.dn]
        )

        assert user.dn in group.member
        assert group.member[0] == user.dn

    def test_models_integration_filter_search_config(self) -> None:
        """Test integration between Filter and SearchConfig models."""
        filter_obj = FlextLdapModels.Filter.equals("objectClass", "person")

        search_config = FlextLdapModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter=filter_obj.expression,
            attributes=["cn", "sn", "mail"],
        )

        assert search_config.search_filter == filter_obj.expression
        assert search_config.base_dn == "dc=example,dc=com"

    def test_models_error_handling_consistency(self) -> None:
        """Test consistent error handling across model methods."""
        # Test DN validation consistency
        dn_result = FlextLdapModels.DistinguishedName.create("")
        assert dn_result.is_failure
        assert "empty" in dn_result.error.lower()

        # Test Filter validation consistency
        with pytest.raises(ValueError, match="empty"):
            FlextLdapModels.Filter(expression="")

        # Test User validation consistency
        user = FlextLdapModels.User(uid="", cn="Test", sn="User")
        user_result = user.validate_business_rules()
        assert user_result.is_failure
        assert "uid" in user_result.error.lower()

        # Test Group validation consistency
        group = FlextLdapModels.Group(cn="", description="Test", member=[])
        group_result = group.validate_business_rules()
        assert group_result.is_failure
        assert "cn" in group_result.error.lower()

    def test_models_performance_large_datasets(self) -> None:
        """Test model performance with large datasets."""
        # Test large member list in Group
        large_member_list = [
            f"uid=user{i},ou=people,dc=example,dc=com" for i in range(1000)
        ]

        group = FlextLdapModels.Group(
            cn="largegroup", description="Large Group", member=large_member_list
        )

        assert len(group.member) == 1000
        assert group.member[0] == "uid=user0,ou=people,dc=example,dc=com"
        assert group.member[999] == "uid=user999,ou=people,dc=example,dc=com"

        # Test adding member to large group
        group.add_member("uid=newuser,ou=people,dc=example,dc=com")
        assert len(group.member) == 1001

        # Test removing member from large group
        group.remove_member("uid=user500,ou=people,dc=example,dc=com")
        assert len(group.member) == 1000
        assert "uid=user500,ou=people,dc=example,dc=com" not in group.member
