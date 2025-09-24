"""Functional tests for flext-ldap models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapModels


class TestFlextLdapModelsFunctional:
    """Functional tests for FlextLdapModels - real business logic validation."""

    def test_flext_ldap_models_import_and_structure(self) -> None:
        """Test that FlextLdapModels can be imported and has expected structure."""
        # Verify main class exists and is accessible
        assert hasattr(FlextLdapModels, "__name__")
        assert "FlextLdapModels" in str(FlextLdapModels)

        # Check for expected domain-related nested classes
        expected_nested_classes = [
            "DistinguishedName",
            "Filter",
            "Scope",
            "LdapUser",
            "Group",
            "Entry",
            "SearchRequest",
            "SearchResponse",
            "CreateUserRequest",
            "CreateGroupRequest",
            "ConnectionInfo",
            "LdapError",
            "OperationResult",
            "ConnectionConfig",
        ]

        for class_name in expected_nested_classes:
            assert hasattr(FlextLdapModels, class_name), f"Missing {class_name}"
            nested_class = getattr(FlextLdapModels, class_name)
            assert nested_class is not None

    def test_models_module_loads_without_errors(self) -> None:
        """Test that models module loads completely without import errors."""
        # Verify module has expected structure
        assert hasattr(FlextLdapModels, "LdapUser")

        # Check module-level functionality
        module_attrs = [
            attr for attr in dir(FlextLdapModels) if not attr.startswith("_")
        ]
        assert len(module_attrs) >= 5, (
            f"Expected substantial module content, got: {module_attrs}"
        )


class TestLdapModelsValidation:
    """Test LDAP Models validation - core validation business logic."""

    def test_ldap_user_creation_and_validation(self) -> None:
        """Test LdapUser creation and validation scenarios."""
        # Test with valid user data
        user = FlextLdapModels.LdapUser(
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            cn="John Doe",
            uid="john.doe",
            sn="Doe",
            given_name="John",
            mail="john.doe@example.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
            object_classes=["person", "top"],
        )

        assert user.dn == "cn=john.doe,ou=users,dc=example,dc=com"
        assert user.cn == "John Doe"
        assert user.uid == "john.doe"
        assert user.sn == "Doe"
        assert user.mail == "john.doe@example.com"

    def test_ldap_user_required_fields(self) -> None:
        """Test that required fields are enforced."""
        # Test missing required dn field
        with pytest.raises(ValueError):
            FlextLdapModels.LdapUser(
                cn="John Doe",
                uid=None,
                sn=None,
                mail=None,
                given_name="John",
                telephone_number="+1-555-123-4567",
                mobile="+1-555-987-6543",
                department="Engineering",
                title="Software Engineer",
                organization="Example Corp",
                organizational_unit="IT Department",
                user_password=None,
                created_timestamp=None,
                modified_timestamp=None,
                dn="",  # Empty DN should be invalid
            )

        # Test missing required cn field
        with pytest.raises(ValueError):
            FlextLdapModels.LdapUser(
                dn="cn=john.doe,ou=users,dc=example,dc=com",
                cn="",  # Empty CN should be invalid
                uid=None,
                sn=None,
                mail=None,
                given_name="John",
                telephone_number="+1-555-123-4567",
                mobile="+1-555-987-6543",
                department="Engineering",
                title="Software Engineer",
                organization="Example Corp",
                organizational_unit="IT Department",
                user_password=None,
                created_timestamp=None,
                modified_timestamp=None,
            )

    def test_group_creation_and_validation(self) -> None:
        """Test Group creation and validation scenarios."""
        # Test with valid group data
        group = FlextLdapModels.Group(
            dn="cn=engineers,ou=groups,dc=example,dc=com",
            cn="engineers",
            gid_number=1001,
            description="Engineering Team",
            object_classes=["groupOfNames", "top"],
            created_timestamp=None,
            modified_timestamp=None,
        )

        assert group.dn == "cn=engineers,ou=groups,dc=example,dc=com"
        assert group.cn == "engineers"
        assert group.description == "Engineering Team"

    def test_distinguished_name_creation(self) -> None:
        """Test DistinguishedName value object creation."""
        # Test valid DN creation
        dn_result = FlextLdapModels.DistinguishedName.create(
            "cn=test,ou=users,dc=example,dc=com"
        )
        assert dn_result.is_success
        assert dn_result.value.value == "cn=test,ou=users,dc=example,dc=com"

        # Test invalid DN creation
        invalid_dn_result = FlextLdapModels.DistinguishedName.create("")
        assert invalid_dn_result.is_failure
        assert invalid_dn_result.error is not None
        assert "cannot be empty" in invalid_dn_result.error

    def test_filter_creation(self) -> None:
        """Test Filter value object creation."""
        # Test valid filter creation
        filter_obj = FlextLdapModels.Filter(expression="(cn=test*)")
        assert filter_obj.expression == "(cn=test*)"

        # Test object class filter
        object_class_filter = FlextLdapModels.Filter.object_class("person")
        assert object_class_filter.expression == "(objectClass=person)"

    def test_search_request_creation(self) -> None:
        """Test SearchRequest creation."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(cn=test*)",
            scope="subtree",
            attributes=["cn", "mail"],
            page_size=None,
            paged_cookie=None,
        )

        assert search_request.base_dn == "dc=example,dc=com"
        assert search_request.filter_str == "(cn=test*)"
        assert search_request.scope == "subtree"
        assert search_request.attributes == ["cn", "mail"]

    def test_create_user_request_creation(self) -> None:
        """Test CreateUserRequest creation."""
        create_request = FlextLdapModels.CreateUserRequest(
            dn="cn=newuser,ou=users,dc=example,dc=com",
            cn="New User",
            uid="newuser",
            sn="User",
            given_name="New",
            mail="newuser@example.com",
            user_password="SecurePassword123!",
            telephone_number="+1-555-123-4567",
            description="A new user account",
            department="Engineering",
            title="Software Developer",
            organization="Example Corp",
        )

        assert create_request.dn == "cn=newuser,ou=users,dc=example,dc=com"
        assert create_request.cn == "New User"
        assert create_request.uid == "newuser"
        assert create_request.sn == "User"
        assert create_request.mail == "newuser@example.com"

    def test_create_group_request_creation(self) -> None:
        """Test CreateGroupRequest creation."""
        create_request = FlextLdapModels.CreateGroupRequest(
            dn="cn=newgroup,ou=groups,dc=example,dc=com",
            cn="New Group",
            description="A new group",
            members=["cn=user1,ou=users,dc=example,dc=com"],
        )

        assert create_request.dn == "cn=newgroup,ou=groups,dc=example,dc=com"
        assert create_request.cn == "New Group"
        assert create_request.description == "A new group"

    def test_connection_info_creation(self) -> None:
        """Test ConnectionInfo creation."""
        connection_info = FlextLdapModels.ConnectionInfo(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password=None,
            timeout=30,
            pool_size=10,
            pool_keepalive=3600,
            ca_certs_file=None,
        )

        assert connection_info.server == "ldap.example.com"
        assert connection_info.port == 389
        assert connection_info.use_ssl is False
        assert connection_info.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

    def test_operation_result_creation(self) -> None:
        """Test OperationResult creation."""
        # Test successful operation
        success_result = FlextLdapModels.OperationResult(
            success=True,
            result_code=0,
            result_message="Operation completed successfully",
            operation_type="search",
            target_dn="dc=example,dc=com",
            duration_ms=150.5,
        )

        assert success_result.success is True
        assert success_result.result_message == "Operation completed successfully"

        # Test failed operation
        failure_result = FlextLdapModels.OperationResult(
            success=False,
            result_code=49,
            result_message="Operation failed",
            operation_type="bind",
            target_dn="cn=user,dc=example,dc=com",
            duration_ms=25.0,
        )

        assert failure_result.success is False
        assert failure_result.result_message == "Operation failed"
        assert failure_result.result_code == 49

    def test_ldap_error_creation(self) -> None:
        """Test LdapError creation."""
        ldap_error = FlextLdapModels.LdapError(
            error_code=49,
            error_message="Invalid credentials",
            matched_dn="",
            operation="bind",
            target_dn="cn=user,dc=example,dc=com",
        )

        assert ldap_error.error_code == 49
        assert ldap_error.error_message == "Invalid credentials"
        assert ldap_error.target_dn == "cn=user,dc=example,dc=com"

    def test_model_validation_with_pydantic(self) -> None:
        """Test that Pydantic validation works correctly."""
        # Test valid data passes validation
        user = FlextLdapModels.LdapUser(
            dn="cn=valid.user,ou=users,dc=example,dc=com",
            cn="Valid User",
            uid="valid.user",
            sn="User",
            given_name="Valid",
            mail="valid.user@example.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

        assert user.dn == "cn=valid.user,ou=users,dc=example,dc=com"
        assert user.cn == "Valid User"

        # Test invalid data raises validation error
        with pytest.raises(ValueError):
            FlextLdapModels.LdapUser(
                dn="",  # Empty DN should be invalid
                cn="Invalid User",
                uid=None,
                sn=None,
                mail=None,
                given_name="Invalid",
                telephone_number="+1-555-123-4567",
                mobile="+1-555-987-6543",
                department="Engineering",
                title="Software Engineer",
                organization="Example Corp",
                organizational_unit="IT Department",
                user_password=None,
                created_timestamp=None,
                modified_timestamp=None,
            )

    def test_model_serialization(self) -> None:
        """Test that models can be serialized and deserialized."""
        user = FlextLdapModels.LdapUser(
            dn="cn=serialize.test,ou=users,dc=example,dc=com",
            cn="Serialize Test",
            uid="serialize.test",
            sn="Test",
            given_name="Serialize",
            mail="serialize.test@example.com",
            telephone_number="+1-555-123-4567",
            mobile="+1-555-987-6543",
            department="Engineering",
            title="Software Engineer",
            organization="Example Corp",
            organizational_unit="IT Department",
            user_password=None,
            created_timestamp=None,
            modified_timestamp=None,
        )

        # Test model_dump
        dumped_data = user.model_dump()
        assert dumped_data["dn"] == "cn=serialize.test,ou=users,dc=example,dc=com"
        assert dumped_data["cn"] == "Serialize Test"

        # Test model_dump_json
        json_data = user.model_dump_json()
        assert isinstance(json_data, str)
        assert "cn=serialize.test,ou=users,dc=example,dc=com" in json_data
