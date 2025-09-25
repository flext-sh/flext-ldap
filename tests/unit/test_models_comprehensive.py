"""Comprehensive tests for FlextLdapModels following FLEXT standards.

This module provides complete test coverage for the FlextLdapModels class
using flext_tests library, centralized fixtures, and real functionality testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapModels
from flext_tests import FlextTestsFactories


class TestFlextLdapModelsComprehensive:
    """Comprehensive test suite for FlextLdapModels using FLEXT standards."""

    def test_connection_config_creation(self) -> None:
        """Test ConnectionConfig model creation."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
            timeout=30
        )

        assert config.server == "ldap://localhost"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert config.bind_password == "REDACTED_LDAP_BIND_PASSWORD123"
        assert config.timeout == 30

    def test_connection_config_defaults(self) -> None:
        """Test ConnectionConfig with default values."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost"
        )

        assert config.server == "ldap://localhost"
        assert config.port == 389  # Default port
        assert config.use_ssl is True  # Default SSL
        assert config.bind_dn is None
        assert config.bind_password is None
        assert config.timeout == 30  # Default timeout

    def test_search_config_creation(self) -> None:
        """Test SearchConfig model creation."""
        config = FlextLdapModels.SearchConfig(
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "sn", "mail"],



        )

        assert config.base_dn == "dc=example,dc=com"
        assert config.search_filter == "(objectClass=person)"
        assert config.attributes == ["cn", "sn", "mail"]

    def test_search_config_defaults(self) -> None:
        """Test SearchConfig with default values."""
        config = FlextLdapModels.SearchConfig(
            base_dn="dc=example,dc=com"
        )

        assert config.base_dn == "dc=example,dc=com"
        assert config.search_filter == "(objectClass=*)"  # Default filter
        assert config.attributes == ["*"]  # Default attributes

    def test_modify_config_creation(self) -> None:
        """Test ModifyConfig model creation."""
        config = FlextLdapModels.ModifyConfig(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            changes={
                "cn": [("MODIFY_REPLACE", ["New Name"])],
                "mail": [("MODIFY_ADD", ["newemail@example.com"])]
            }
        )

        assert config.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert len(config.changes) == 2
        assert "cn" in config.changes
        assert "mail" in config.changes

    def test_add_config_creation(self) -> None:
        """Test AddConfig model creation."""
        config = FlextLdapModels.AddConfig(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "organizationalPerson"],
                "cn": ["Test User"],
                "sn": ["User"],
                "uid": ["testuser"],
                "mail": ["testuser@example.com"]
            }
        )

        assert config.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert len(config.attributes) == 5
        assert "objectClass" in config.attributes
        assert "cn" in config.attributes
        assert config.attributes["cn"] == ["Test User"]

    def test_delete_config_creation(self) -> None:
        """Test DeleteConfig model creation."""
        config = FlextLdapModels.DeleteConfig(
            dn="cn=testuser,ou=users,dc=example,dc=com"
        )

        assert config.dn == "cn=testuser,ou=users,dc=example,dc=com"

    def test_user_model_creation(self) -> None:
        """Test User model creation."""
        user = FlextLdapModels.LdapUser(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            sn="User",
            uid="testuser",
            mail="testuser@example.com",
            object_classes=["person", "organizationalPerson"]
        )

        assert user.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.uid == "testuser"
        assert user.mail == "testuser@example.com"
        assert user.object_classes == ["person", "organizationalPerson"]

    def test_group_model_creation(self) -> None:
        """Test Group model creation."""
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="Test Group",
            member=["cn=user1,ou=users,dc=example,dc=com"],
            object_classes=["groupOfNames"]
        )

        assert group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert group.cn == "Test Group"
        assert len(group.member) == 1
        assert group.member[0] == "cn=user1,ou=users,dc=example,dc=com"
        assert group.object_classes == ["groupOfNames"]

    def test_search_request_creation(self) -> None:
        """Test SearchRequest model creation."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",

            attributes=["cn", "sn", "mail"],


        )

        assert request.base_dn == "dc=example,dc=com"
        assert request.filter_str == "(objectClass=person)"
        assert request.scope == "subtree"
        assert request.attributes == ["cn", "sn", "mail"]
        assert request.size_limit == 1000
        assert request.time_limit == 30

    def test_search_response_creation(self) -> None:
        """Test SearchResponse model creation."""
        response = FlextLdapModels.SearchResponse(
            entries=[],
            total_count=0,

        )

        assert response.entries == []
        assert response.total_count == 0

    def test_ldap_entry_creation(self) -> None:
        """Test LDAPEntry model creation."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["testuser@example.com"]
            }
        )

        assert entry.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert len(entry.attributes) == 3
        assert entry.attributes["cn"] == ["Test User"]

    def test_models_with_flext_tests_factories(self) -> None:
        """Test models integration with flext_tests factories."""
        # Use flext_tests to create realistic test data
        FlextTestsFactories.create_realistic_test_data()

        # Test that we can create models with realistic data
        user = FlextLdapModels.LdapUser(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            sn="User",
            uid="testuser",
            mail="testuser@example.com"
        )

        assert user is not None
        assert isinstance(user.dn, str)
        assert isinstance(user.cn, str)

    def test_models_validation_with_pydantic(self) -> None:
        """Test that models use Pydantic validation correctly."""
        # Test valid data
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )
        assert config.server == "ldap://localhost"

        # Test invalid data should raise validation error
        with pytest.raises(Exception):  # Pydantic validation error
            FlextLdapModels.ConnectionConfig(
                server="invalid-url",
                port="not-a-number",
                use_ssl="not-a-boolean"
            )

    def test_models_field_validation(self) -> None:
        """Test field validation in models."""
        # Test required fields
        with pytest.raises(Exception):
            FlextLdapModels.ConnectionConfig()  # Missing required server field

        # Test field types
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )
        assert isinstance(config.server, str)
        assert isinstance(config.port, int)
        assert isinstance(config.use_ssl, bool)

    def test_models_default_values(self) -> None:
        """Test default values in models."""
        config = FlextLdapModels.ConnectionConfig(server="ldap://localhost")

        # Check defaults are applied
        assert config.port == 389  # Default LDAP port
        assert config.use_ssl is False  # Default SSL disabled
        assert config.timeout == 30  # Default timeout

    def test_models_equality(self) -> None:
        """Test models equality comparison."""
        config1 = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )

        config2 = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )

        # Should be equal
        assert config1 == config2

        # Different values should not be equal
        config3 = FlextLdapModels.ConnectionConfig(
            server="ldap://otherhost",
            port=389,
            use_ssl=True
        )
        assert config1 != config3

    def test_models_hash_support(self) -> None:
        """Test that models support hashing."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )

        # Should be hashable
        hash_value = hash(config)
        assert isinstance(hash_value, int)

        # Same config should have same hash
        config2 = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )
        assert hash(config) == hash(config2)

    def test_models_string_representation(self) -> None:
        """Test models string representation."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap://localhost",
            port=389,
            use_ssl=True
        )

        str_repr = str(config)
        assert isinstance(str_repr, str)
        assert "ConnectionConfig" in str_repr
        assert "ldap://localhost" in str_repr

    def test_models_comprehensive_coverage(self) -> None:
        """Test comprehensive coverage of all model types."""
        # Test all major model types
        models_to_test = [
            lambda: FlextLdapModels.ConnectionConfig(server="ldap://localhost"),
            lambda: FlextLdapModels.SearchConfig(base_dn="dc=example,dc=com", search_filter="(objectClass=*)", attributes=["*"]),
            lambda: FlextLdapModels.ModifyConfig(dn="cn=test,dc=example,dc=com", changes={}),
            lambda: FlextLdapModels.AddConfig(dn="cn=test,dc=example,dc=com", attributes={}),
            lambda: FlextLdapModels.DeleteConfig(dn="cn=test,dc=example,dc=com"),
            lambda: FlextLdapModels.LdapUser(dn="cn=test,dc=example,dc=com", cn="Test"),
            lambda: FlextLdapModels.Group(dn="cn=test,dc=example,dc=com", cn="Test"),
            lambda: FlextLdapModels.SearchRequest(base_dn="dc=example,dc=com", search_filter="(objectClass=*)", attributes=["*"]),
            lambda: FlextLdapModels.SearchResponse(entries=[], total_count=0),
            lambda: FlextLdapModels.Entry(dn="cn=test,dc=example,dc=com", attributes={})
        ]

        for model_factory in models_to_test:
            model = model_factory()
            assert model is not None
            assert hasattr(model, 'validate')  # Validation method
            assert hasattr(model, 'validate')  # Validation method
