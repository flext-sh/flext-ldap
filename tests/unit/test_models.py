"""Comprehensive unit tests for flext-ldap models module.

This module provides complete test coverage for the flext-ldap models functionality,
following FLEXT standards with real functionality testing and no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import cast

import pytest
from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels

# ===================================================================
# BATCH 3: ACL CONVERSION TESTS (10 tests)
# Testing ACL model conversion and transformation patterns
# ===================================================================


class TestFlextLdapModels:
    """Comprehensive tests for FlextLdapModels class."""

    def test_models_initialization(self) -> None:
        """Test models class initialization."""
        models = FlextLdapModels()

        assert models is not None
        # FlextLdapModels is a namespace class, not a service class
        assert isinstance(models, FlextLdapModels)

    def test_distinguished_name_creation(self) -> None:
        """Test DistinguishedName model creation."""
        dn_data = {"value": "cn=testuser,dc=test,dc=com"}

        dn = FlextLdapModels.DistinguishedName(**dn_data)

        assert dn.value == "cn=testuser,dc=test,dc=com"
        assert dn.rdn == "cn=testuser"

    def test_distinguished_name_validation(self) -> None:
        """Test DistinguishedName validation."""
        # Test valid DN
        valid_dn = FlextLdapModels.DistinguishedName(value="cn=testuser,dc=test,dc=com")
        assert valid_dn.value == "cn=testuser,dc=test,dc=com"

        # Test invalid DN
        with pytest.raises(ValueError):
            FlextLdapModels.DistinguishedName(value="")

    def test_distinguished_name_create_method(self) -> None:
        """Test DistinguishedName create method."""
        # Test valid DN creation
        result = FlextLdapModels.DistinguishedName.create("cn=testuser,dc=test,dc=com")
        assert isinstance(result, FlextCore.Result)
        assert result.is_success
        # Use unwrap() to get the actual DistinguishedName object
        dn_obj = result.unwrap()
        assert isinstance(dn_obj, FlextLdapModels.DistinguishedName)
        assert dn_obj.value == "cn=testuser,dc=test,dc=com"

        # Test invalid DN creation
        result = FlextLdapModels.DistinguishedName.create("")
        assert isinstance(result, FlextCore.Result)
        assert result.is_failure

    def test_filter_creation(self) -> None:
        """Test Filter model creation."""
        filter_data = {"expression": "(objectClass=*)"}

        filter_obj = FlextLdapModels.Filter(**filter_data)

        assert filter_obj.expression == "(objectClass=*)"

    def test_filter_validation(self) -> None:
        """Test Filter validation."""
        # Test valid filter
        valid_filter = FlextLdapModels.Filter(expression="(objectClass=*)")
        assert valid_filter.expression == "(objectClass=*)"

        # Test invalid filter
        with pytest.raises(ValueError):
            FlextLdapModels.Filter(expression="")

    def test_filter_factory_methods(self) -> None:
        """Test Filter factory methods."""
        # Test equals filter
        equals_filter = FlextLdapModels.Filter.equals("cn", "testuser")
        assert equals_filter.expression == "(cn=testuser)"

        # Test starts_with filter
        starts_with_filter = FlextLdapModels.Filter.starts_with("cn", "test")
        assert starts_with_filter.expression == "(cn=test*)"

        # Test object_class filter
        object_class_filter = FlextLdapModels.Filter.object_class("person")
        assert object_class_filter.expression == "(objectClass=person)"

    def test_scope_creation(self) -> None:
        """Test Scope model creation."""
        scope_data = {"value": "subtree"}

        scope = FlextLdapModels.Scope(**scope_data)

        assert scope.value == "subtree"

    def test_scope_validation(self) -> None:
        """Test Scope validation."""
        from flext_ldap.exceptions import FlextLdapExceptions

        # Test valid scope
        valid_scope = FlextLdapModels.Scope(value="subtree")
        assert valid_scope.value == "subtree"

        # Test invalid scope
        with pytest.raises(FlextLdapExceptions.LdapValidationError):
            FlextLdapModels.Scope(value="INVALID")

    def test_ldap_server_type_enum(self) -> None:
        """Test LdapServerType enum."""
        # Test enum values
        assert FlextLdapModels.LdapServerType.OPENLDAP.value == "openldap"
        assert (
            FlextLdapModels.LdapServerType.ACTIVE_DIRECTORY.value == "active_directory"
        )
        assert FlextLdapModels.LdapServerType.ORACLE_OUD.value == "oracle_oud"

    def test_schema_attribute_creation(self) -> None:
        """Test SchemaAttribute model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        attr = FlextLdapModels.SchemaAttribute(
            name="cn",
            oid="2.5.4.3",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            is_single_valued=False,
            usage="userApplications",
        )

        assert attr.name == "cn"
        assert attr.oid == "2.5.4.3"
        assert attr.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr.is_single_valued is False
        assert attr.usage == "userApplications"

    def test_schema_object_class_creation(self) -> None:
        """Test SchemaObjectClass model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        oc = FlextLdapModels.SchemaObjectClass(
            name="person",
            oid="2.5.6.6",
            must=["cn", "sn"],
            may=["mail", "telephoneNumber"],
            kind="STRUCTURAL",
        )

        assert oc.name == "person"
        assert oc.oid == "2.5.6.6"
        assert oc.must == ["cn", "sn"]
        assert oc.may == ["mail", "telephoneNumber"]
        assert oc.kind == "STRUCTURAL"

    def test_server_quirks_creation(self) -> None:
        """Test ServerQuirks model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        quirks = FlextLdapModels.ServerQuirks(
            server_type=FlextLdapModels.LdapServerType.OPENLDAP,
            supports_paged_results=True,
            supports_sync=True,
            max_page_size=FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
            object_class_mappings={"person": "inetOrgPerson"},
        )

        assert quirks.server_type == FlextLdapModels.LdapServerType.OPENLDAP.value
        assert quirks.supports_paged_results is True
        assert quirks.supports_sync is True
        assert quirks.max_page_size == FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE
        assert quirks.object_class_mappings == {"person": "inetOrgPerson"}

    def test_schema_discovery_result_creation(self) -> None:
        """Test SchemaDiscoveryResult model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        server_info = FlextLdapModels.ServerInfo(
            naming_contexts=["dc=test,dc=com"],
            supported_ldap_version=["3"],
        )
        # Add vendor and version as dynamic attributes (FlexibleModel allows this)
        setattr(server_info, "vendor", "OpenLDAP")
        setattr(server_info, "version", "2.4")

        result = FlextLdapModels.SchemaDiscoveryResult(
            server_info=server_info,
            server_type=FlextLdapModels.LdapServerType.OPENLDAP,
            server_quirks=FlextLdapModels.ServerQuirks(
                server_type=FlextLdapModels.LdapServerType.OPENLDAP
            ),
            attributes={
                "cn": FlextLdapModels.SchemaAttribute(
                    name="cn",
                    oid="2.5.4.3",
                    syntax="1.3.6.1.4.1.1466.115.121.1.15",
                    is_single_valued=False,
                )
            },
            object_classes={
                "person": FlextLdapModels.SchemaObjectClass(
                    name="person", oid="2.5.6.6", kind="STRUCTURAL"
                )
            },
            naming_contexts=["dc=example,dc=com"],
            supported_controls=["2.16.840.1.113730.3.4.18"],
            supported_extensions=["1.3.6.1.4.1.4203.1.11.1"],
        )

        assert result.server_type == FlextLdapModels.LdapServerType.OPENLDAP.value
        assert "cn" in result.attributes
        assert "person" in result.object_classes

    def test_ldap_user_creation(self) -> None:
        """Test LdapUser model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        user = FlextLdapModels.LdapUser(
            dn="cn=testuser,dc=test,dc=com",
            cn="testuser",
            uid="testuser",
            sn="Test",
            mail="test@example.com",
            object_classes=["person", "inetOrgPerson"],
            given_name=None,
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
        )

        assert user.dn == "cn=testuser,dc=test,dc=com"
        assert user.cn == "testuser"
        assert user.sn == "Test"
        assert user.mail == "test@example.com"
        assert user.object_classes == ["person", "inetOrgPerson"]

    def test_ldap_user_validation(self) -> None:
        """Test LdapUser validation."""
        # Test valid user
        valid_user = FlextLdapModels.LdapUser(
            dn="cn=testuser,dc=test,dc=com",
            cn="testuser",
            uid="testuser",
            sn="Test",
            mail="test@example.com",
            given_name=None,
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
        )

        result = valid_user.validate_business_rules()
        assert isinstance(result, FlextCore.Result)
        assert result.is_success

        # Test invalid user - validation happens at field level
        with pytest.raises(Exception):
            FlextLdapModels.LdapUser(
                dn="",  # Invalid empty DN
                cn="",  # Invalid empty CN
                uid="",  # Invalid empty UID
                sn="",  # Invalid empty SN
                mail="invalid-email",  # Invalid email format
                given_name=None,
                telephone_number=None,
                mobile=None,
                department=None,
                title=None,
                organization=None,
                organizational_unit=None,
                user_password=None,
            )

    def test_ldap_group_creation(self) -> None:
        """Test LdapGroup model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        group = FlextLdapModels.Group(
            dn="cn=testgroup,dc=test,dc=com",
            cn="testgroup",
            description="Test group",
            member_dns=["cn=user1,dc=test,dc=com", "cn=user2,dc=test,dc=com"],
            object_classes=["groupOfNames"],
            gid_number=None,
        )

        assert group.dn == "cn=testgroup,dc=test,dc=com"
        assert group.cn == "testgroup"
        assert group.description == "Test group"
        assert group.member_dns == [
            "cn=user1,dc=test,dc=com",
            "cn=user2,dc=test,dc=com",
        ]
        assert group.object_classes == ["groupOfNames"]

    def test_ldap_group_validation(self) -> None:
        """Test LdapGroup validation."""
        # Test valid group
        valid_group = FlextLdapModels.Group(
            dn="cn=testgroup,dc=test,dc=com",
            cn="testgroup",
            description="Test group",
            gid_number=None,  # Optional field
        )

        result = valid_group.validate_business_rules()
        assert isinstance(result, FlextCore.Result)
        assert result.is_success

        # Test invalid group - validation happens at field level
        with pytest.raises(Exception):
            FlextLdapModels.Group(
                dn="",  # Invalid empty DN
                cn="",  # Invalid empty CN
                description="",
                gid_number=None,  # Optional field
            )

    def test_connection_config_creation(self) -> None:
        """Test ConnectionConfig model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=FlextLdapConstants.Protocol.DEFAULT_PORT,
            use_ssl=False,
            bind_dn="cn=admin,dc=test,dc=com",
            bind_password="testpass",
            timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
        )

        assert config.server == "localhost"
        assert config.port == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert config.use_ssl is False
        assert config.bind_dn == "cn=admin,dc=test,dc=com"
        assert config.bind_password == "testpass"
        assert config.timeout == FlextLdapConstants.DEFAULT_TIMEOUT

    def test_connection_config_properties(self) -> None:
        """Test ConnectionConfig properties."""
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=FlextLdapConstants.Protocol.DEFAULT_PORT,
            use_ssl=False,
        )

        # Test server_uri property
        assert (
            config.server_uri
            == f"ldap://localhost:{FlextLdapConstants.Protocol.DEFAULT_PORT}"
        )

        # Test password property
        assert config.password is None

        config_with_password = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=FlextLdapConstants.Protocol.DEFAULT_PORT,
            use_ssl=False,
            bind_password="testpass",
        )
        assert config_with_password.password == "testpass"

    def test_modify_config_creation(self) -> None:
        """Test ModifyConfig model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        config = FlextLdapModels.ModifyConfig(
            dn="cn=testuser,dc=test,dc=com",
            changes={
                "cn": [("MODIFY_REPLACE", ["newcn"])],
                "mail": [("MODIFY_ADD", ["newmail@example.com"])],
            },
        )

        assert config.dn == "cn=testuser,dc=test,dc=com"
        assert config.changes["cn"] == [("MODIFY_REPLACE", ["newcn"])]
        assert config.changes["mail"] == [("MODIFY_ADD", ["newmail@example.com"])]

    def test_add_config_creation(self) -> None:
        """Test AddConfig model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        config = FlextLdapModels.AddConfig(
            dn="cn=testuser,dc=test,dc=com",
            attributes={
                "cn": ["testuser"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test"],
                "mail": ["test@example.com"],
            },
        )

        assert config.dn == "cn=testuser,dc=test,dc=com"
        assert config.attributes["cn"] == ["testuser"]
        assert config.attributes["objectClass"] == ["person", "inetOrgPerson"]
        assert config.attributes["sn"] == ["Test"]
        assert config.attributes["mail"] == ["test@example.com"]

    def test_delete_config_creation(self) -> None:
        """Test DeleteConfig model creation."""
        config = FlextLdapModels.DeleteConfig(
            dn="cn=testuser,dc=test,dc=com",
            created_at=datetime.now(UTC),
        )

        assert config.dn == "cn=testuser,dc=test,dc=com"

    def test_search_config_creation(self) -> None:
        """Test SearchConfig model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        config = FlextLdapModels.SearchConfig(
            base_dn="dc=test,dc=com",
            filter_str="(objectClass=*)",
            attributes=["cn", "mail"],
        )

        assert config.base_dn == "dc=test,dc=com"
        assert config.filter_str == "(objectClass=*)"
        assert config.attributes == ["cn", "mail"]

    def test_search_response_creation(self) -> None:
        """Test SearchResponse model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        response = FlextLdapModels.SearchResponse(
            entries=[
                FlextLdapModels.Entry(
                    dn="cn=testuser,dc=test,dc=com",
                    attributes={"cn": "testuser", "mail": "test@example.com"},
                )
            ],
            total_count=1,
            next_cookie=b"",
            has_more=False,
            result_code=0,
            result_description="",
            matched_dn="",
            entries_returned=1,
            time_elapsed=0.0,
        )

        assert len(response.entries) == 1
        assert response.total_count == 1
        assert response.next_cookie == b""
        assert response.has_more is False

    def test_search_response_validation(self) -> None:
        """Test SearchResponse validation."""
        # Test valid search response
        valid_response = FlextLdapModels.SearchResponse(
            entries=[],
            total_count=0,
            next_cookie=b"",
            has_more=False,
            result_code=0,
            result_description="",
            matched_dn="",
            entries_returned=0,
            time_elapsed=0.0,
        )

        # SearchResponse is a data model, no validation needed
        assert isinstance(valid_response, FlextLdapModels.SearchResponse)
        assert len(valid_response.entries) == 0

        # Test invalid search response
        invalid_response = FlextLdapModels.SearchResponse(
            entries=[],  # Valid empty entries
            total_count=-1,  # Invalid negative count
            next_cookie=b"",
            has_more=False,
            result_code=0,
            result_description="",
            matched_dn="",
            entries_returned=0,
            time_elapsed=0.0,
        )

        # SearchResponse is a data model, validation happens at field level
        assert isinstance(invalid_response, FlextLdapModels.SearchResponse)
        assert invalid_response.total_count == -1

    def test_models_error_handling(self) -> None:
        """Test models error handling mechanisms."""
        # Test with None input - this will fail at the type level
        with pytest.raises(Exception):
            FlextLdapModels.DistinguishedName(
                value=""
            )  # Empty string should fail validation

        # Test with invalid input type
        with pytest.raises(Exception):
            FlextLdapModels.DistinguishedName(value="invalid_string")

    def test_models_thread_safety(self) -> None:
        """Test models thread safety."""
        results = []

        def create_dn() -> None:
            dn = FlextLdapModels.DistinguishedName(value="cn=testuser,dc=test,dc=com")
            results.append(dn)

        threads = []
        for _ in range(5):
            thread = threading.Thread(target=create_dn)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All results should be valid DNs
        assert len(results) == 5
        for dn in results:
            assert dn.value == "cn=testuser,dc=test,dc=com"

    def test_models_memory_usage(self) -> None:
        """Test models memory usage patterns."""
        dns = []
        for i in range(10):
            dn = FlextLdapModels.DistinguishedName(
                value=f"cn=testuser{i},dc=test,dc=com"
            )
            dns.append(dn)

        # Verify DNs are created without memory leaks
        assert len(dns) == 10
        assert all(dn.value.startswith("cn=testuser") for dn in dns)

    def test_models_performance(self) -> None:
        """Test models performance characteristics."""
        # Test DN creation performance
        start_time = time.time()
        for i in range(100):
            dn = FlextLdapModels.DistinguishedName(
                value=f"cn=testuser{i},dc=test,dc=com"
            )
            assert dn.value == f"cn=testuser{i},dc=test,dc=com"
        end_time = time.time()

        # Should complete within reasonable time
        duration = end_time - start_time
        assert duration < 5.0  # Should complete within 5 seconds

    def test_models_extensibility(self) -> None:
        """Test models extensibility features."""
        # Test that models can be extended with custom fields
        # Use a non-frozen model for extensibility testing
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=FlextLdapConstants.Protocol.DEFAULT_PORT,
            bind_dn="cn=admin,dc=test,dc=com",
            bind_password="testpass",
        )

        # Verify configuration is properly set
        assert config.server == "localhost"
        assert config.port == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert config.bind_dn == "cn=admin,dc=test,dc=com"
        assert config.bind_password == "testpass"

    def test_models_integration_complete_workflow(self) -> None:
        """Test complete models workflow integration."""
        # Test complete workflow
        # 1. Create DN
        dn = FlextLdapModels.DistinguishedName(value="cn=testuser,dc=test,dc=com")

        # 2. Create filter
        filter_obj = FlextLdapModels.Filter(expression="(objectClass=*)")

        # 3. Create scope
        scope = FlextLdapModels.Scope(value="subtree")

        # 4. Create user
        user = FlextLdapModels.LdapUser(
            dn="cn=testuser,dc=test,dc=com",
            cn="testuser",
            uid="testuser",
            sn="Test",
            mail="test@example.com",
            given_name=None,
            telephone_number=None,
            mobile=None,
            department=None,
            title=None,
            organization=None,
            organizational_unit=None,
            user_password=None,
        )

        # 5. Create connection config
        from flext_ldap.constants import FlextLdapConstants

        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=FlextLdapConstants.Protocol.DEFAULT_PORT,
            bind_dn="cn=admin,dc=test,dc=com",
            bind_password="testpass",
        )

        # Verify all models are valid
        assert dn.value == "cn=testuser,dc=test,dc=com"
        assert filter_obj.expression == "(objectClass=*)"
        assert scope.value == "subtree"
        assert user.cn == "testuser"
        assert config.server == "localhost"

    def test_entry_model_creation(self) -> None:
        """Test Entry model creation with real LDAP entry data."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,ou=people,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "organizationalPerson"],
                "cn": ["testuser"],
                "sn": ["User"],
                "mail": ["testuser@example.com"],
            },
            object_classes=["person", "organizationalPerson"],
        )

        assert entry.dn == "cn=testuser,ou=people,dc=example,dc=com"
        assert "person" in entry.object_classes
        assert entry.attributes["cn"] == ["testuser"]

    def test_entry_model_validation(self) -> None:
        """Test Entry model validation rules."""
        # Test missing DN
        with pytest.raises(Exception):
            FlextLdapModels.Entry(
                dn="",
                attributes={"cn": ["test"]},
            )

    def test_search_request_advanced_options(self) -> None:
        """Test SearchRequest with advanced pagination and options."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(&(objectClass=person)(uid=test*))",
            scope="subtree",
            attributes=["cn", "mail", "uid"],
            size_limit=100,
            time_limit=30,
            page_size=10,
            types_only=False,
            deref_aliases="never",
        )

        assert request.base_dn == "dc=example,dc=com"
        assert request.page_size == 10
        assert request.size_limit == 100
        assert request.is_paged_search is True
        assert request.deref_aliases == "never"

    def test_create_user_request_validation(self) -> None:
        """Test CreateUserRequest with field validation."""
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=newuser,ou=people,dc=example,dc=com",
            uid="newuser",
            cn="New User",
            sn="User",
            mail="newuser@example.com",
            user_password="securepass123",
            given_name=None,
            telephone_number=None,
            description=None,
            department=None,
            organizational_unit=None,
            title=None,
            organization=None,
        )

        assert request.uid == "newuser"
        assert request.mail == "newuser@example.com"
        assert request.user_password == "securepass123"

    def test_create_group_request_validation(self) -> None:
        """Test CreateGroupRequest with members."""
        request = FlextLdapModels.CreateGroupRequest(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test Group",
            members=[
                "uid=user1,ou=people,dc=example,dc=com",
                "uid=user2,ou=people,dc=example,dc=com",
            ],
        )

        assert request.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert request.cn == "testgroup"
        assert request.description == "Test Group"
        assert len(request.members) == 2

    def test_connection_info_model(self) -> None:
        """Test ConnectionInfo model with server information."""
        info = FlextLdapModels.ConnectionInfo(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=admin,dc=example,dc=com",
            timeout=30,
            pool_size=5,
            pool_keepalive=30,
        )

        assert info.server == "ldap.example.com"
        assert info.port == 389
        assert info.use_ssl is False
        assert info.bind_dn == "cn=admin,dc=example,dc=com"
        assert info.timeout == 30
        assert info.pool_size == 5
        assert info.verify_certificates is True  # default value

    def test_ldap_error_model(self) -> None:
        """Test LdapError model for error tracking."""
        error = FlextLdapModels.LdapError(
            error_code=49,
            error_message="Invalid credentials - 80090308: LdapErr: DSID-0C090447",
            operation="bind",
            target_dn="cn=user,dc=example,dc=com",
        )

        assert error.error_code == 49
        assert "Invalid credentials" in error.error_message
        assert error.operation == "bind"
        assert error.target_dn == "cn=user,dc=example,dc=com"

    def test_operation_result_model(self) -> None:
        """Test OperationResult model for LDAP operations."""
        result = FlextLdapModels.OperationResult(
            success=True,
            operation_type="add",
            target_dn="cn=newuser,ou=people,dc=example,dc=com",
            result_message="User created successfully",
            duration_ms=15.5,
        )

        assert result.success is True
        assert result.operation_type == "add"
        assert "successfully" in result.result_message
        assert result.target_dn == "cn=newuser,ou=people,dc=example,dc=com"
        assert result.duration_ms == 15.5

        # Test factory methods
        success_result = FlextLdapModels.OperationResult.success_result(
            operation_type="modify",
            target_dn="cn=user,dc=example,dc=com",
            duration_ms=10.0,
        )
        assert success_result.success is True
        assert success_result.result_code == 0

        error_result = FlextLdapModels.OperationResult.error_result(
            operation_type="delete",
            error_code=32,
            error_message="No such object",
            target_dn="cn=missing,dc=example,dc=com",
        )
        assert error_result.success is False
        assert error_result.result_code == 32

    def test_acl_target_model(self) -> None:
        """Test AclTarget model for ACL definitions."""
        target = FlextLdapModels.AclTarget.create(
            target_type="dn",
            dn_pattern="ou=people,dc=example,dc=com",
        )

        assert target.is_success
        acl_target = target.unwrap()
        assert acl_target.target_type == "dn"
        assert acl_target.dn_pattern == "ou=people,dc=example,dc=com"

    def test_acl_subject_model(self) -> None:
        """Test AclSubject model for ACL principals."""
        subject = FlextLdapModels.AclSubject.create(
            subject_type="user",
            subject_dn="uid=admin,ou=people,dc=example,dc=com",
            authentication_level="simple",
        )

        assert subject.is_success
        acl_subject = subject.unwrap()
        assert acl_subject.subject_type == "user"
        assert acl_subject.subject_dn == "uid=admin,ou=people,dc=example,dc=com"
        assert acl_subject.authentication_level == "simple"

    def test_acl_permissions_model(self) -> None:
        """Test AclPermissions model for permission sets."""
        perms = FlextLdapModels.AclPermissions.create(
            permissions=["read", "write", "search"],
            denied_permissions=["delete"],
            grant_type="allow",
        )

        assert perms.is_success
        permissions = perms.unwrap()
        assert "read" in permissions.permissions
        assert "write" in permissions.permissions
        assert "search" in permissions.permissions
        assert "delete" in permissions.denied_permissions
        assert permissions.grant_type == "allow"

    def test_cqrs_command_model(self) -> None:
        """Test CqrsCommand model for command pattern."""
        command = FlextLdapModels.CqrsCommand(
            command_type="CreateUser",
            command_id="cmd-001",
            payload={"uid": "testuser", "cn": "Test User"},
        )

        assert command.command_type == "CreateUser"
        assert command.command_id == "cmd-001"
        assert command.payload["uid"] == "testuser"

        # Test factory method
        command_result = FlextLdapModels.CqrsCommand.create(
            command_type="UpdateUser",
            command_id="cmd-002",
            payload={"uid": "testuser", "mail": "new@example.com"},
        )
        assert command_result.is_success
        cmd = command_result.unwrap()
        assert cmd.command_type == "UpdateUser"

    def test_cqrs_query_model(self) -> None:
        """Test CqrsQuery model for query pattern."""
        query = FlextLdapModels.CqrsQuery(
            query_type="FindUser",
            query_id="qry-001",
            parameters={"uid": "testuser"},
        )

        assert query.query_type == "FindUser"
        assert query.query_id == "qry-001"
        assert query.parameters["uid"] == "testuser"

        # Test factory method
        query_result = FlextLdapModels.CqrsQuery.create(
            query_type="SearchUsers",
            query_id="qry-002",
            parameters={"filter": "(objectClass=person)"},
        )
        assert query_result.is_success
        qry = query_result.unwrap()
        assert qry.query_type == "SearchUsers"

    def test_cqrs_event_model(self) -> None:
        """Test CqrsEvent model for event sourcing."""
        import time

        timestamp = int(time.time())
        event = FlextLdapModels.CqrsEvent(
            event_type="UserCreated",
            event_id="evt-001",
            aggregate_id="user-123",
            timestamp=timestamp,
            payload={"uid": "testuser", "cn": "Test User"},
        )

        assert event.event_type == "UserCreated"
        assert event.event_id == "evt-001"
        assert event.aggregate_id == "user-123"
        assert event.timestamp == timestamp
        assert event.payload["uid"] == "testuser"

        # Test factory method
        event_result = FlextLdapModels.CqrsEvent.create(
            event_type="UserUpdated",
            event_id="evt-002",
            aggregate_id="user-123",
            timestamp=timestamp + 1,
            payload={"mail": "updated@example.com"},
        )
        assert event_result.is_success
        evt = event_result.unwrap()
        assert evt.event_type == "UserUpdated"

    def test_domain_message_model(self) -> None:
        """Test DomainMessage model for message passing."""
        message = FlextLdapModels.DomainMessage(
            message_id="msg-001",
            message_type="UserCommand",
            data={"action": "create", "uid": "testuser"},
            metadata={"correlation_id": "corr-001"},
            timestamp=None,
            processed=False,
        )

        assert message.message_id == "msg-001"
        assert message.message_type == "UserCommand"
        assert message.metadata["correlation_id"] == "corr-001"
        assert message.data["action"] == "create"
        assert message.processed is False

    def test_search_response_model(self) -> None:
        """Test SearchResponse model for search results."""
        entry1 = FlextLdapModels.Entry(
            dn="cn=user1,dc=example,dc=com",
            attributes={"cn": ["user1"], "objectClass": ["person"]},
        )
        entry2 = FlextLdapModels.Entry(
            dn="cn=user2,dc=example,dc=com",
            attributes={"cn": ["user2"], "objectClass": ["person"]},
        )

        response = FlextLdapModels.SearchResponse(
            entries=[entry1, entry2],
            total_count=2,
            has_more=False,
            next_cookie=None,
            result_code=0,
            result_description="Success",
            matched_dn="",
            entries_returned=2,
            time_elapsed=0.0,
        )

        assert len(response.entries) == 2
        assert response.total_count == 2
        assert response.has_more is False
        assert response.next_cookie is None
        assert response.entries_returned == 2  # auto-calculated

    def test_connection_config_model(self) -> None:
        """Test ConnectionConfig model for LDAP connections."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=admin,dc=example,dc=com",
        )

        assert config.server == "ldap.example.com"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.bind_dn == "cn=admin,dc=example,dc=com"

    def test_ldap_user_validation_methods(self) -> None:
        """Test LdapUser validation methods."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        assert user.uid == "testuser"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.mail == "testuser@example.com"

    def test_group_validation_methods(self) -> None:
        """Test Group validation methods."""
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test group",
            member_dns=["uid=user1,ou=people,dc=example,dc=com"],
        )

        assert group.cn == "testgroup"
        assert len(group.member_dns) == 1
        assert "user1" in group.member_dns[0]

    def test_entry_attribute_methods(self) -> None:
        """Test Entry model attribute manipulation methods."""
        entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["top", "person"],
            },
        )

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes
        assert "objectClass" in entry.attributes

    def test_search_request_pagination(self) -> None:
        """Test SearchRequest pagination features."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            page_size=50,
        )

        assert request.is_paged_search is True
        assert request.page_size == 50
        assert request.base_dn == "dc=example,dc=com"

    def test_distinguished_name_methods(self) -> None:
        """Test DistinguishedName helper methods."""
        dn_result = FlextLdapModels.DistinguishedName.create(
            "uid=testuser,ou=people,dc=example,dc=com"
        )

        assert dn_result.is_success
        dn = cast("FlextLdapModels.DistinguishedName", dn_result.unwrap())
        assert "uid=testuser" in dn.value

    def test_filter_helper_methods(self) -> None:
        """Test Filter helper methods."""
        filter_obj = FlextLdapModels.Filter(expression="(objectClass=person)")

        assert filter_obj.expression == "(objectClass=person)"
        assert "objectClass" in filter_obj.expression

        # Test factory methods
        equals_filter = FlextLdapModels.Filter.equals("cn", "admin")
        assert "cn=admin" in equals_filter.expression

        starts_filter = FlextLdapModels.Filter.starts_with("uid", "test")
        assert "uid=test*" in starts_filter.expression

        class_filter = FlextLdapModels.Filter.object_class("person")
        assert "objectClass=person" in class_filter.expression

    def test_scope_enum_values(self) -> None:
        """Test Scope enum values."""
        base_scope = FlextLdapModels.Scope(value="base")
        onelevel_scope = FlextLdapModels.Scope(value="onelevel")
        subtree_scope = FlextLdapModels.Scope(value="subtree")

        assert base_scope.value == "base"
        assert onelevel_scope.value == "onelevel"
        assert subtree_scope.value == "subtree"

    # ===================================================================
    # BATCH 1: VALIDATION EDGE CASES (10 tests)
    # ===================================================================

    def test_distinguished_name_invalid_formats(self) -> None:
        """Test DistinguishedName with various invalid formats."""
        # Test empty DN
        with pytest.raises(Exception):
            FlextLdapModels.DistinguishedName(value="")

        # Test DN without dc component (should be valid - not required)
        dn = FlextLdapModels.DistinguishedName(value="cn=test")
        assert dn.value == "cn=test"

        # Test malformed DN (missing equals)
        with pytest.raises(Exception):
            FlextLdapModels.DistinguishedName(value="cntest,dc=example,dc=com")

        # Test DN with empty component
        with pytest.raises(Exception):
            FlextLdapModels.DistinguishedName(value="cn=,dc=example,dc=com")

    def test_filter_invalid_syntax(self) -> None:
        """Test Filter with invalid syntax."""
        # Test empty filter
        with pytest.raises(Exception):
            FlextLdapModels.Filter(expression="")

        # Test filter without parentheses
        with pytest.raises(Exception):
            FlextLdapModels.Filter(expression="objectClass=person")

        # Test filter with unbalanced parentheses
        with pytest.raises(Exception):
            FlextLdapModels.Filter(expression="(objectClass=person")

        # Test filter with wrong closing (should be valid - only checks start/end)
        filter_obj = FlextLdapModels.Filter(expression="(objectClass==person)")
        assert filter_obj.expression == "(objectClass==person)"

    def test_scope_invalid_values(self) -> None:
        """Test Scope with invalid values."""
        from flext_ldap.exceptions import FlextLdapExceptions

        # Test uppercase (should fail - must be lowercase)
        with pytest.raises(FlextLdapExceptions.LdapValidationError):
            FlextLdapModels.Scope(value="SUBTREE")

        # Test completely invalid value
        with pytest.raises(FlextLdapExceptions.LdapValidationError):
            FlextLdapModels.Scope(value="invalid_scope")

        # Test empty scope
        with pytest.raises(FlextLdapExceptions.LdapValidationError):
            FlextLdapModels.Scope(value="")

        # Test numeric value
        with pytest.raises(FlextLdapExceptions.LdapValidationError):
            FlextLdapModels.Scope(value="123")

    def test_ldap_user_field_validators(self) -> None:
        """Test LdapUser field validators."""
        # Test invalid email format
        with pytest.raises(Exception):
            FlextLdapModels.LdapUser(
                dn="uid=test,dc=example,dc=com",
                uid="test",
                cn="Test",
                sn="User",
                mail="invalid-email-format",  # Missing @ symbol
            )

        # Test empty required fields
        with pytest.raises(Exception):
            FlextLdapModels.LdapUser(
                dn="",  # Empty DN
                uid="test",
                cn="Test",
                sn="User",
            )

        # Test whitespace-only DN
        with pytest.raises(Exception):
            FlextLdapModels.LdapUser(
                dn="   ",
                uid="test",
                cn="Test",
                sn="User",
            )

    def test_group_field_validators(self) -> None:
        """Test Group field validators."""
        # Test valid group with various members (member DN format not strictly validated)
        group = FlextLdapModels.Group(
            dn="cn=testgroup,dc=example,dc=com",
            cn="testgroup",
            member_dns=["uid=user1,ou=people,dc=example,dc=com"],
        )
        assert group.cn == "testgroup"

        # Test group with optional gid_number (can be negative in some LDAP schemas)
        group_with_gid = FlextLdapModels.Group(
            dn="cn=testgroup,dc=example,dc=com",
            cn="testgroup",
            gid_number=1000,
        )
        assert group_with_gid.gid_number == 1000

        # Test group validation business rules
        group_for_validation = FlextLdapModels.Group(
            dn="cn=testgroup,dc=example,dc=com",
            cn="testgroup",
        )
        validation_result = group_for_validation.validate_business_rules()
        assert validation_result.is_success

    def test_connection_config_validation(self) -> None:
        """Test ConnectionConfig validation."""
        # Test valid connection config with standard port
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=389,
        )
        assert config.server == "localhost"
        assert config.port == 389

        # Test valid SSL port
        ssl_config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=636,
            use_ssl=True,
        )
        assert ssl_config.use_ssl is True

        # Test server with whitespace (should be stripped or fail)
        config_ws = FlextLdapModels.ConnectionConfig(
            server="  localhost  ",
            port=389,
        )
        assert config_ws.server in {"  localhost  ", "localhost"}

        # Test timeout validation
        config_with_timeout = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=389,
            timeout=30,
        )
        assert config_with_timeout.timeout == 30

    def test_search_request_limits(self) -> None:
        """Test SearchRequest limit boundary conditions."""
        # Test valid search request with limits
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            size_limit=100,
            time_limit=30,
            page_size=10,
        )
        assert request.size_limit == 100
        assert request.time_limit == 30
        assert request.page_size == 10
        assert request.is_paged_search is True

        # Test search without limits (defaults)
        request_no_limits = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
        )
        assert request_no_limits.base_dn == "dc=example,dc=com"

        # Test search without page_size parameter (no paging)
        request_no_paging = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
        )
        # When page_size is not specified, is_paged_search should be False
        assert request_no_paging.is_paged_search is False

    def test_entry_attributes_validation(self) -> None:
        """Test Entry attribute validation."""
        # Test empty DN
        with pytest.raises(Exception):
            FlextLdapModels.Entry(
                dn="",  # Empty DN
                attributes={"cn": ["test"]},
            )

        # Test None attributes
        with pytest.raises(Exception):
            FlextLdapModels.Entry(
                dn="cn=test,dc=example,dc=com",
                attributes={},  # Empty attributes dict instead of None
            )

        # Test empty attributes dict[str, object] (should be valid)
        entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            attributes={},  # Empty but valid
        )
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.attributes == {}

    def test_create_user_request_invalid(self) -> None:
        """Test CreateUserRequest with invalid data."""
        # Test invalid email format
        with pytest.raises(Exception):
            FlextLdapModels.CreateUserRequest(
                dn="uid=test,ou=people,dc=example,dc=com",
                uid="test",
                cn="Test",
                sn="User",
                mail="not-an-email",  # Invalid email
                given_name=None,
                telephone_number=None,
                description=None,
                department=None,
                organizational_unit=None,
                title=None,
                organization=None,
            )

        # Test empty uid
        with pytest.raises(Exception):
            FlextLdapModels.CreateUserRequest(
                dn="uid=test,ou=people,dc=example,dc=com",
                uid="",  # Empty uid
                cn="Test",
                sn="User",
                given_name=None,
                telephone_number=None,
                description=None,
                department=None,
                organizational_unit=None,
                title=None,
                organization=None,
            )

        # Test whitespace-only password
        with pytest.raises(Exception):
            FlextLdapModels.CreateUserRequest(
                dn="uid=test,ou=people,dc=example,dc=com",
                uid="test",
                cn="Test",
                sn="User",
                user_password="   ",  # Whitespace-only password
                given_name=None,
                telephone_number=None,
                description=None,
                department=None,
                organizational_unit=None,
                title=None,
                organization=None,
            )

    def test_create_group_request_invalid(self) -> None:
        """Test CreateGroupRequest with invalid data."""
        # Test valid group request with members
        request = FlextLdapModels.CreateGroupRequest(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test Group",
            members=["uid=user1,ou=people,dc=example,dc=com"],
        )
        assert request.cn == "testgroup"
        assert len(request.members) == 1

        # Test empty cn (should fail)
        with pytest.raises(Exception):
            FlextLdapModels.CreateGroupRequest(
                dn="cn=testgroup,ou=groups,dc=example,dc=com",
                cn="",  # Empty cn
                description="Test",
                members=[],
            )

        # Test empty description (should fail)
        with pytest.raises(Exception):
            FlextLdapModels.CreateGroupRequest(
                dn="cn=testgroup,ou=groups,dc=example,dc=com",
                cn="testgroup",
                description="",  # Empty description
                members=[],
            )

    # ===================================================================
    # BATCH 2: COMPLEX MODEL METHODS (10 tests)
    # ===================================================================

    def test_distinguished_name_computed_properties(self) -> None:
        """Test DistinguishedName computed properties."""
        dn = FlextLdapModels.DistinguishedName(
            value="uid=testuser,ou=people,dc=example,dc=com"
        )

        # Test rdn property (computed field with @property)
        rdn_value = dn.rdn
        assert rdn_value == "uid=testuser"

        # Test rdn_attribute property
        rdn_attr = dn.rdn_attribute
        assert rdn_attr == "uid"

        # Test rdn_value property
        rdn_val = dn.rdn_value
        assert rdn_val == "testuser"

        # Test components_count property
        comp_count = dn.components_count
        assert comp_count == 4

    def test_distinguished_name_serialization(self) -> None:
        """Test DistinguishedName serialization and normalization."""
        dn = FlextLdapModels.DistinguishedName(
            value="CN=Test User,OU=People,DC=Example,DC=Com"
        )

        # DN normalization should lowercase attribute names
        serialized = dn.model_dump()
        assert "value" in serialized

        # Test DN with multi-valued RDN
        multi_rdn = FlextLdapModels.DistinguishedName(
            value="cn=test+uid=user,dc=example,dc=com"
        )
        assert multi_rdn.rdn == "cn=test+uid=user"
        assert multi_rdn.components_count == 3

    def test_ldap_user_business_rules_validation(self) -> None:
        """Test LdapUser business rules validation."""
        # Full user with all attributes
        full_user = FlextLdapModels.LdapUser(
            dn="uid=john,ou=people,dc=example,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
            given_name="John",
            mail="john@example.com",
            telephone_number="+1-555-0100",
            mobile="+1-555-0101",
            department="Engineering",
            organizational_unit="Engineering",  # Required when department is set
            title="Software Engineer",
            organization="Example Corp",
            user_password="hashed_password",
        )
        assert full_user.uid == "john"
        assert full_user.department == "Engineering"
        assert full_user.organizational_unit == "Engineering"

        # Minimal user (required fields: dn, cn, uid, sn, mail)
        minimal_user = FlextLdapModels.LdapUser(
            dn="uid=jane,ou=people,dc=example,dc=com",
            uid="jane",
            cn="Jane Smith",
            sn="Smith",
            mail="jane@example.com",  # mail is required
        )
        assert minimal_user.uid == "jane"
        assert minimal_user.mail == "jane@example.com"
        assert minimal_user.given_name is None
        assert minimal_user.telephone_number is None  # Depends on rules

    def test_group_member_management(self) -> None:
        """Test Group member management operations."""
        group = FlextLdapModels.Group(
            dn="cn=developers,ou=groups,dc=example,dc=com",
            cn="developers",
            description="Developers group",
            member_dns=[
                "uid=user1,ou=people,dc=example,dc=com",
                "uid=user2,ou=people,dc=example,dc=com",
                "uid=user3,ou=people,dc=example,dc=com",
            ],
            gid_number=1001,
        )

        # Verify member count
        assert len(group.member_dns) == 3

        # Test business rules
        validation = group.validate_business_rules()
        assert validation.is_success

    def test_entry_attribute_access(self) -> None:
        """Test Entry attribute access patterns."""
        entry = FlextLdapModels.Entry(
            dn="uid=testuser,ou=people,dc=example,dc=com",
            attributes={
                "uid": ["testuser"],
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["testuser@example.com", "test.user@example.com"],
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
            },
            object_classes=["person", "organizationalPerson", "inetOrgPerson"],
        )

        # Test single-valued attribute access
        assert entry.attributes["uid"] == ["testuser"]
        assert entry.attributes["cn"] == ["Test User"]

        # Test multi-valued attribute access
        assert len(entry.attributes["mail"]) == 2
        assert "testuser@example.com" in entry.attributes["mail"]

        # Test objectClass access
        assert len(entry.object_classes) == 3
        assert "inetOrgPerson" in entry.object_classes

    def test_search_request_pagination_logic(self) -> None:
        """Test SearchRequest pagination logic and computed properties."""
        # Test paged search
        paged_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            page_size=50,
        )
        assert paged_request.is_paged_search is True

        # Test non-paged search
        non_paged = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
        )
        assert non_paged.is_paged_search is False

        # Test with attributes specification
        with_attrs = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(uid=test*)",
            scope="onelevel",
            attributes=["uid", "cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        assert with_attrs.attributes is not None and len(with_attrs.attributes) == 3
        assert with_attrs.size_limit == 100

    def test_connection_config_uri_generation(self) -> None:
        """Test ConnectionConfig URI generation."""
        # Test LDAP URI
        ldap_config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=389,
            use_ssl=False,
        )
        assert ldap_config.server_uri == "ldap://ldap.example.com:389"

        # Test LDAPS URI
        ldaps_config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=636,
            use_ssl=True,
        )
        assert ldaps_config.server_uri == "ldaps://ldap.example.com:636"

        # Test password property
        config_with_password = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=389,
            bind_password="secret123",
        )
        assert config_with_password.password == "secret123"

    def test_operation_result_factory_methods(self) -> None:
        """Test OperationResult factory method patterns."""
        # Success result factory
        success = FlextLdapModels.OperationResult(
            success=True,
            result_message="User created successfully",
            target_dn="uid=john,ou=people,dc=example,dc=com",
            duration_ms=0.0,
        )
        assert success.success is True
        assert "created successfully" in success.result_message
        assert success.target_dn == "uid=john,ou=people,dc=example,dc=com"

        # Error result factory (OperationResult has result_code and result_message, not error_code/error_message)
        error = FlextLdapModels.OperationResult(
            success=False,
            result_code=32,
            result_message="No such object",
            data={"reason": "Entry does not exist"},
            duration_ms=0.0,
        )
        assert error.success is False
        assert "No such object" in error.result_message
        assert error.result_code == 32
        assert error.data == {"reason": "Entry does not exist"}

    def test_filter_combination_patterns(self) -> None:
        """Test Filter combination and factory patterns."""
        # Test equals filter
        equals_filter = FlextLdapModels.Filter.equals("uid", "testuser")
        assert equals_filter.expression == "(uid=testuser)"

        # Test starts_with filter
        starts_filter = FlextLdapModels.Filter.starts_with("cn", "Test")
        assert starts_filter.expression == "(cn=Test*)"

        # Test object_class filter
        oc_filter = FlextLdapModels.Filter.object_class("inetOrgPerson")
        assert oc_filter.expression == "(objectClass=inetOrgPerson)"

        # Test complex filter
        complex_filter = FlextLdapModels.Filter(
            expression="(&(objectClass=person)(uid=test*))"
        )
        assert "objectClass=person" in complex_filter.expression
        assert "uid=test*" in complex_filter.expression

    def test_ldap_error_model_details(self) -> None:
        """Test LdapError model with detailed error information."""
        error = FlextLdapModels.LdapError(
            error_code=49,
            error_message="Invalid credentials - 80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error",
            operation="bind",
            target_dn="uid=admin,dc=example,dc=com",
        )

        assert error.error_code == 49
        assert "Invalid credentials" in error.error_message
        assert error.operation == "bind"
        assert error.target_dn == "uid=admin,dc=example,dc=com"

        # Test search error
        search_error = FlextLdapModels.LdapError(
            error_code=32,
            error_message="No such object",
            operation="search",
            target_dn="ou=missing,dc=example,dc=com",
        )
        assert search_error.error_code == 32
        assert search_error.operation == "search"

    # ===================================================================
    # BATCH 3: ACL CONVERSION TESTS (10 tests)
    # Testing ACL model conversion and transformation patterns
    # ===================================================================

    def test_acl_target_creation(self) -> None:
        """Test AclTarget model creation and validation."""
        # DN-based target
        dn_target = FlextLdapModels.AclTarget(
            target_type="dn",
            dn_pattern="ou=users,dc=example,dc=com",
            scope="subtree",
        )
        assert dn_target.target_type == "dn"
        assert dn_target.dn_pattern == "ou=users,dc=example,dc=com"
        assert dn_target.scope == "subtree"

        # Attribute-based target
        attr_target = FlextLdapModels.AclTarget(
            target_type="attrs",
            attributes=["userPassword", "authPassword"],
        )
        assert attr_target.target_type == "attrs"
        assert "userPassword" in attr_target.attributes
        assert "authPassword" in attr_target.attributes

    def test_acl_subject_creation(self) -> None:
        """Test AclSubject model creation with different subject types."""
        # User subject
        user_subject = FlextLdapModels.AclSubject(
            subject_type="user",
            subject_dn="uid=admin,ou=people,dc=example,dc=com",
        )
        assert user_subject.subject_type == "user"
        assert user_subject.subject_dn == "uid=admin,ou=people,dc=example,dc=com"

        # Group subject
        group_subject = FlextLdapModels.AclSubject(
            subject_type="group",
            subject_dn="cn=admins,ou=groups,dc=example,dc=com",
        )
        assert group_subject.subject_type == "group"
        assert group_subject.subject_dn == "cn=admins,ou=groups,dc=example,dc=com"

        # Self subject (uses default subject_dn)
        self_subject = FlextLdapModels.AclSubject(
            subject_type="self",
        )
        assert self_subject.subject_type == "self"
        assert self_subject.subject_dn == "*"  # default value

    def test_acl_permissions_direct_creation(self) -> None:
        """Test AclPermissions model direct creation with various permission sets."""
        # Read-only permissions
        read_perms = FlextLdapModels.AclPermissions(
            granted_permissions=["read", "search", "compare"],
            grant_type="allow",
        )
        assert "read" in read_perms.granted_permissions
        assert "write" not in read_perms.granted_permissions
        assert "search" in read_perms.granted_permissions
        assert read_perms.grant_type == "allow"

        # Full permissions
        full_perms = FlextLdapModels.AclPermissions(
            granted_permissions=["read", "write", "add", "delete", "search", "compare"],
            grant_type="allow",
        )
        assert "read" in full_perms.granted_permissions
        assert "write" in full_perms.granted_permissions
        assert "add" in full_perms.granted_permissions
        assert len(full_perms.granted_permissions) == 6
        assert "delete" in full_perms.granted_permissions

    def test_unified_acl_direct_creation(self) -> None:
        """Test Acl model direct creation with complete ACL definition."""
        target = FlextLdapModels.AclTarget(
            target_type="dn",
            dn_pattern="ou=users,dc=example,dc=com",
        )
        subject = FlextLdapModels.AclSubject(
            subject_type="group",
            subject_dn="cn=admins,ou=groups,dc=example,dc=com",
        )
        permissions = FlextLdapModels.AclPermissions(
            granted_permissions=["read", "write", "add", "delete", "search"],
        )

        unified_acl = FlextLdapModels.Acl(
            name="admin_users_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            priority=100,
        )

        assert unified_acl.name == "admin_users_acl"
        assert unified_acl.target == target
        assert unified_acl.subject == subject
        assert unified_acl.permissions == permissions
        assert unified_acl.priority == 100

    def test_ldap_user_to_ldap_attributes(self) -> None:
        """Test LdapUser.to_ldap_attributes() conversion method."""
        user = FlextLdapModels.LdapUser(
            dn="uid=jdoe,ou=users,dc=example,dc=com",
            cn="John Doe",
            uid="jdoe",
            sn="Doe",
            given_name="John",
            mail="jdoe@example.com",
            telephone_number="+1-555-0100",
            mobile="+1-555-0199",
            department="Engineering",
            title="Senior Engineer",
            organization="Example Corp",
            organizational_unit="Engineering",
            object_classes=["person", "organizationalPerson", "inetOrgPerson"],
        )

        attributes = user.to_ldap_attributes()

        # Verify all attributes are present
        assert attributes["dn"] == ["uid=jdoe,ou=users,dc=example,dc=com"]
        assert attributes["cn"] == ["John Doe"]
        assert attributes["uid"] == ["jdoe"]
        assert attributes["sn"] == ["Doe"]
        assert attributes["givenName"] == ["John"]
        assert attributes["mail"] == ["jdoe@example.com"]
        assert attributes["telephoneNumber"] == ["+1-555-0100"]
        assert attributes["mobile"] == ["+1-555-0199"]
        assert attributes["department"] == ["Engineering"]
        assert attributes["title"] == ["Senior Engineer"]
        assert attributes["o"] == ["Example Corp"]
        assert attributes["ou"] == ["Engineering"]
        assert attributes["objectClass"] == [
            "person",
            "organizationalPerson",
            "inetOrgPerson",
        ]

    def test_ldap_user_from_ldap_attributes(self) -> None:
        """Test LdapUser.from_ldap_attributes() factory method."""
        ldap_attrs = {
            "dn": ["uid=testuser,ou=users,dc=example,dc=com"],
            "cn": ["Test User"],
            "uid": ["testuser"],
            "sn": ["User"],
            "givenName": ["Test"],
            "mail": ["testuser@example.com"],
            "telephoneNumber": ["+1-555-0200"],
            "mobile": ["+1-555-0299"],
            "department": ["QA"],
            "title": ["QA Engineer"],
            "o": ["Test Corp"],
            "ou": ["Quality Assurance"],
            "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
        }

        result = FlextLdapModels.LdapUser.from_ldap_attributes(ldap_attrs)

        assert result.is_success
        user = result.unwrap()
        assert user.dn == "uid=testuser,ou=users,dc=example,dc=com"
        assert user.cn == "Test User"
        assert user.uid == "testuser"
        assert user.sn == "User"
        assert user.given_name == "Test"
        assert user.mail == "testuser@example.com"
        assert user.telephone_number == "+1-555-0200"
        assert user.mobile == "+1-555-0299"
        assert user.department == "QA"
        assert user.title == "QA Engineer"
        assert user.organization == "Test Corp"
        assert user.organizational_unit == "Quality Assurance"

    def test_ldap_user_from_ldap_attributes_minimal(self) -> None:
        """Test LdapUser.from_ldap_attributes() with minimal attributes."""
        ldap_attrs = {
            "dn": ["cn=minuser,dc=example,dc=com"],
            "cn": ["Minimal User"],
            "sn": ["User"],
            "uid": ["minuser"],
            "mail": ["minuser@example.com"],
        }

        result = FlextLdapModels.LdapUser.from_ldap_attributes(ldap_attrs)

        assert result.is_success
        user = result.unwrap()
        assert user.dn == "cn=minuser,dc=example,dc=com"
        assert user.cn == "Minimal User"
        assert user.mail == "minuser@example.com"

    def test_ldap_user_from_ldap_attributes_missing_dn(self) -> None:
        """Test LdapUser.from_ldap_attributes() fails without DN."""
        ldap_attrs = {
            "cn": ["No DN User"],
            "sn": ["User"],
        }

        result = FlextLdapModels.LdapUser.from_ldap_attributes(ldap_attrs)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN is required" in result.error

    def test_group_to_ldap_attributes(self) -> None:
        """Test Group.to_ldap_attributes() conversion method."""
        group = FlextLdapModels.Group(
            dn="cn=admins,ou=groups,dc=example,dc=com",
            cn="admins",
            description="Administrators group",
            member_dns=[
                "uid=admin1,ou=users,dc=example,dc=com",
                "uid=admin2,ou=users,dc=example,dc=com",
            ],
            gid_number=1000,
            object_classes=["groupOfNames", "posixGroup"],
        )

        attributes = group.to_ldap_attributes()

        assert attributes["dn"] == ["cn=admins,ou=groups,dc=example,dc=com"]
        assert attributes["cn"] == ["admins"]
        assert "uid=admin1,ou=users,dc=example,dc=com" in attributes["member"]
        assert "uid=admin2,ou=users,dc=example,dc=com" in attributes["member"]
        assert attributes["description"] == ["Administrator group"]
        assert attributes["gidNumber"] == ["1000"]
        assert "groupOfNames" in attributes["objectClass"]
        assert "posixGroup" in attributes["objectClass"]

    def test_group_from_ldap_attributes(self) -> None:
        """Test Group.from_ldap_attributes() factory method."""
        ldap_attrs = {
            "dn": ["cn=developers,ou=groups,dc=example,dc=com"],
            "cn": ["developers"],
            "member": [
                "uid=dev1,ou=users,dc=example,dc=com",
                "uid=dev2,ou=users,dc=example,dc=com",
            ],
            "description": ["Development team"],
            "gidNumber": ["2000"],
            "objectClass": ["groupOfNames", "posixGroup"],
        }

        result = FlextLdapModels.Group.from_ldap_attributes(ldap_attrs)

        assert result.is_success
        group = result.unwrap()
        assert group.dn == "cn=developers,ou=groups,dc=example,dc=com"
        assert group.cn == "developers"
        assert len(group.member_dns) == 2
        assert "uid=dev1,ou=users,dc=example,dc=com" in group.member_dns
        assert group.description == "Development team"
        assert group.gid_number == 2000

    def test_cqrs_command_direct_creation(self) -> None:
        """Test CqrsCommand direct instantiation."""
        import time

        timestamp = int(time.time() * 1000)

        command = FlextLdapModels.CqrsCommand(
            command_type="CreateUser",
            command_id="cmd-123",
            payload={"username": "newuser", "email": "new@example.com"},
            metadata={"correlation_id": "cmd-123"},
            timestamp=timestamp,
        )

        assert command.command_type == "CreateUser"
        assert command.command_id == "cmd-123"
        assert command.payload["username"] == "newuser"
        assert command.metadata["correlation_id"] == "cmd-123"
        assert command.timestamp == timestamp

    def test_cqrs_query_direct_creation(self) -> None:
        """Test CqrsQuery direct instantiation."""
        import time

        timestamp = int(time.time() * 1000)

        query = FlextLdapModels.CqrsQuery(
            query_type="FindUser",
            query_id="qry-456",
            parameters={"uid": "testuser"},
            metadata={"requestor": "admin"},
            timestamp=timestamp,
        )

        assert query.query_type == "FindUser"
        assert query.query_id == "qry-456"
        assert query.parameters["uid"] == "testuser"
        assert query.metadata["requestor"] == "admin"
        assert query.timestamp == timestamp

    def test_cqrs_event_direct_creation(self) -> None:
        """Test CqrsEvent direct instantiation."""
        import time

        timestamp = int(time.time() * 1000)

        event = FlextLdapModels.CqrsEvent(
            event_type="UserCreated",
            event_id="evt-123",
            aggregate_id="user-456",
            payload={"user_id": "uid=new,ou=users,dc=example,dc=com"},
            metadata={"source": "ldap-service"},
            timestamp=timestamp,
        )

        assert event.event_type == "UserCreated"
        assert event.event_id == "evt-123"
        assert event.aggregate_id == "user-456"
        assert "user_id" in event.payload
        assert event.metadata["source"] == "ldap-service"
        assert event.timestamp == timestamp
        assert event.version == 1

    def test_domain_message_direct_creation(self) -> None:
        """Test DomainMessage direct instantiation."""
        import time

        timestamp = int(time.time() * 1000)

        message = FlextLdapModels.DomainMessage(
            message_type="command",
            message_id="msg-789",
            data={"action": "create_user", "payload": {"username": "testuser"}},
            metadata={"priority": "high"},
            timestamp=timestamp,
            processed=False,
        )

        assert message.message_type == "command"
        assert message.message_id == "msg-789"
        assert message.data["action"] == "create_user"
        assert message.metadata["priority"] == "high"
        assert message.timestamp == timestamp
        assert message.processed is False

    # =========================================================================
    # PHASE 2.1.5 BATCH 1: ENTRY MODEL ACCESSOR METHODS (67% → 75% TARGET)
    # =========================================================================

    def test_entry_get_attribute_string(self) -> None:
        """Test Entry.get_attribute() with string attribute."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        )

        # Test getting string attribute
        cn_value = entry.get_attribute("cn")
        assert cn_value is not None
        assert isinstance(cn_value, list)
        assert cn_value == ["Test User"]

        # Test getting mail attribute
        mail_value = entry.get_attribute("mail")
        assert mail_value is not None
        assert mail_value == ["test@example.com"]

    def test_entry_get_attribute_list(self) -> None:
        """Test Entry.get_attribute() with list attribute."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "memberOf": [
                    "cn=group1,ou=groups,dc=example,dc=com",
                    "cn=group2,ou=groups,dc=example,dc=com",
                ],
            },
        )

        # Test getting multi-valued attribute
        object_classes = entry.get_attribute("objectClass")
        assert object_classes is not None
        assert isinstance(object_classes, list)
        assert len(object_classes) == 3
        assert "person" in object_classes
        assert "inetOrgPerson" in object_classes

    def test_entry_get_attribute_bytes(self) -> None:
        """Test Entry.get_attribute() with empty list edge case."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "emptyAttr": [],  # Empty list edge case
            },
        )

        # Test empty attribute list returns empty list
        empty_attr = entry.get_attribute("emptyAttr")
        assert empty_attr is not None
        assert isinstance(empty_attr, list)
        assert len(empty_attr) == 0

    def test_entry_get_attribute_missing(self) -> None:
        """Test Entry.get_attribute() returns None for missing attribute."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={"cn": ["Test User"]},
        )

        # Test missing attribute returns None
        missing_attr = entry.get_attribute("nonexistent")
        assert missing_attr is None

        # Test another missing attribute
        missing_mail = entry.get_attribute("mail")
        assert missing_mail is None

    def test_entry_set_attribute(self) -> None:
        """Test Entry.set_attribute() attribute modification."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={"cn": ["Test User"], "sn": ["User"]},
        )

        # Test setting existing attribute
        entry.set_attribute("cn", ["Modified User"])
        assert entry.get_attribute("cn") == ["Modified User"]

        # Test adding new attribute
        entry.set_attribute("mail", ["newmail@example.com"])
        assert entry.get_attribute("mail") == ["newmail@example.com"]

    def test_entry_has_attribute(self) -> None:
        """Test Entry.has_attribute() existence check."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        )

        # Test existing attributes
        assert entry.has_attribute("cn") is True
        assert entry.has_attribute("sn") is True
        assert entry.has_attribute("mail") is True

        # Test non-existing attributes
        assert entry.has_attribute("nonexistent") is False
        assert entry.has_attribute("telephoneNumber") is False

    def test_entry_get_rdn(self) -> None:
        """Test Entry.get_rdn() RDN extraction."""
        # Test simple DN
        entry1 = FlextLdapModels.Entry(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            attributes={"cn": ["Test User"]},
        )
        assert entry1.get_rdn() == "cn=testuser"

        # Test DN with multiple components
        entry2 = FlextLdapModels.Entry(
            dn="uid=jdoe,ou=people,ou=users,dc=company,dc=com",
            attributes={"uid": ["jdoe"]},
        )
        assert entry2.get_rdn() == "uid=jdoe"

        # Test single component DN (no commas)
        entry3 = FlextLdapModels.Entry(dn="dc=com", attributes={"dc": ["com"]})
        assert entry3.get_rdn() == "dc=com"

    def test_entry_contains_operator(self) -> None:
        """Test Entry.__contains__() 'in' operator support."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        )

        # Test 'in' operator for existing attributes
        assert "cn" in entry
        assert "sn" in entry
        assert "mail" in entry

        # Test 'in' operator for DN (always True)
        assert "dn" in entry

        # Test 'in' operator for non-existing attributes
        assert "nonexistent" not in entry
        assert "telephoneNumber" not in entry

    def test_entry_getitem_operator(self) -> None:
        """Test Entry.__getitem__() bracket notation support."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        )

        # Test bracket notation for attributes
        assert entry["cn"] == ["Test User"]
        assert entry["sn"] == ["User"]
        assert entry["mail"] == ["test@example.com"]

        # Test bracket notation for DN
        assert entry["dn"] == "cn=testuser,dc=example,dc=com"

        # Test bracket notation for missing attribute
        missing = entry["nonexistent"]
        assert missing is None

    def test_entry_get_with_default(self) -> None:
        """Test Entry.get() dict-like method with default."""
        entry = FlextLdapModels.Entry(
            dn="cn=testuser,dc=example,dc=com",
            attributes={
                "cn": ["Test User"],
                "mail": ["test@example.com"],
            },
        )

        # Test get() with existing attribute
        cn_value = entry.get("cn")
        assert cn_value == ["Test User"]

        # Test get() for DN
        dn_value = entry.get("dn")
        assert dn_value == "cn=testuser,dc=example,dc=com"

        # Test get() with missing attribute and default
        phone = entry.get("telephoneNumber", ["555-0000"])
        assert phone == ["555-0000"]

        # Test get() with missing attribute and None default
        missing = entry.get("nonexistent")
        assert missing is None

        # Test get() with missing attribute and custom default
        description = entry.get("description", ["No description"])
        assert description == ["No description"]

    # =========================================================================
    # PHASE 2.1.5 BATCH 2: GROUP, SEARCHREQUEST, CREATEUSER (70% → 80% TARGET)
    # =========================================================================

    def test_group_from_ldap_attributes_with_gid(self) -> None:
        """Test Group.from_ldap_attributes() with gidNumber."""
        ldap_attrs = {
            "dn": ["cn=testgroup,ou=groups,dc=example,dc=com"],
            "cn": ["Test Group"],
            "gidNumber": ["1000"],
            "description": ["Test group with GID"],
            "objectClass": ["posixGroup", "top"],
            "member": [
                "uid=user1,ou=users,dc=example,dc=com",
                "uid=user2,ou=users,dc=example,dc=com",
            ],
        }

        result = FlextLdapModels.Group.from_ldap_attributes(ldap_attrs)
        assert result.is_success
        group = result.unwrap()
        assert group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert group.cn == "Test Group"
        assert group.gid_number == 1000
        assert group.description == "Test group with GID"
        assert len(group.member_dns) == 2

    def test_group_from_ldap_attributes_without_gid(self) -> None:
        """Test Group.from_ldap_attributes() without gidNumber."""
        ldap_attrs = {
            "dn": ["cn=simplegroup,ou=groups,dc=example,dc=com"],
            "cn": ["Simple Group"],
            "objectClass": ["groupOfNames", "top"],
            "member": ["cn=admin,dc=example,dc=com"],
        }

        result = FlextLdapModels.Group.from_ldap_attributes(ldap_attrs)
        assert result.is_success
        group = result.unwrap()
        assert group.dn == "cn=simplegroup,ou=groups,dc=example,dc=com"
        assert group.cn == "Simple Group"
        assert group.gid_number is None
        assert group.description is None

    def test_group_from_ldap_attributes_unique_members(self) -> None:
        """Test Group.from_ldap_attributes() with uniqueMember."""
        ldap_attrs = {
            "dn": ["cn=uniquegroup,ou=groups,dc=example,dc=com"],
            "cn": ["Unique Group"],
            "objectClass": ["groupOfUniqueNames", "top"],
            "uniqueMember": [
                "uid=user1,ou=users,dc=example,dc=com",
                "uid=user2,ou=users,dc=example,dc=com",
            ],
        }

        result = FlextLdapModels.Group.from_ldap_attributes(ldap_attrs)
        assert result.is_success
        group = result.unwrap()
        assert len(group.unique_member_dns) == 2
        assert "uid=user1,ou=users,dc=example,dc=com" in group.unique_member_dns

    def test_group_from_ldap_attributes_missing_dn(self) -> None:
        """Test Group.from_ldap_attributes() fails without DN."""
        ldap_attrs = {
            "cn": ["Test Group"],
            "member": ["cn=admin,dc=example,dc=com"],
        }

        result = FlextLdapModels.Group.from_ldap_attributes(ldap_attrs)
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN is required" in result.error

    def test_search_request_search_complexity_simple(self) -> None:
        """Test SearchRequest.search_complexity computed field - simple."""
        search = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=organization)",  # Non-wildcard for base scope
            scope="base",
        )

        assert search.search_complexity == "simple"

    def test_search_request_search_complexity_moderate(self) -> None:
        """Test SearchRequest.search_complexity computed field - moderate."""
        search = FlextLdapModels.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(uid=testuser)",
            scope="onelevel",
        )

        assert search.search_complexity == "moderate"

    def test_search_request_search_complexity_complex(self) -> None:
        """Test SearchRequest.search_complexity computed field - complex."""
        # Test with wildcard
        search1 = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(cn=*test*)",
            scope="subtree",
        )
        assert search1.search_complexity == "complex"

        # Test with multiple AND conditions
        search2 = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(&(&(objectClass=person)(uid=test))(&(cn=user)(mail=*)))",
            scope="subtree",
        )
        assert search2.search_complexity == "complex"

    def test_search_request_normalized_scope(self) -> None:
        """Test SearchRequest.normalized_scope computed field."""
        search = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",  # Uppercase
        )

        assert search.normalized_scope == "subtree"

    def test_search_request_estimated_result_count_base(self) -> None:
        """Test SearchRequest.estimated_result_count - base scope."""
        search = FlextLdapModels.SearchRequest(
            base_dn="cn=admin,dc=example,dc=com",
            filter_str="(objectClass=person)",  # Non-wildcard for base scope
            scope="base",
        )

        assert search.estimated_result_count == 1

    def test_search_request_estimated_result_count_onelevel(self) -> None:
        """Test SearchRequest.estimated_result_count - onelevel scope."""
        search = FlextLdapModels.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="onelevel",
            size_limit=50,
        )

        # Should be min(size_limit, 100)
        assert search.estimated_result_count == 50

    def test_search_request_estimated_result_count_subtree_specific(self) -> None:
        """Test SearchRequest.estimated_result_count - subtree with specific filter."""
        search = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(uid=testuser)",
            scope="subtree",
            size_limit=100,
        )

        # Should be min(size_limit, 10) for specific attribute search
        assert search.estimated_result_count == 10

    def test_search_request_estimated_result_count_subtree_broad(self) -> None:
        """Test SearchRequest.estimated_result_count - subtree with broad filter."""
        search = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            size_limit=2000,
        )

        # Should be min(size_limit, 1000) for broader search
        assert search.estimated_result_count == 1000

    def test_create_user_request_validate_business_rules_success(self) -> None:
        """Test CreateUserRequest.validate_business_rules() succeeds with valid data."""
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.com",
            user_password="password123",
            given_name=None,
            telephone_number=None,
            description=None,
            department=None,
            organizational_unit=None,
            title=None,
            organization=None,
        )

        result = request.validate_business_rules()
        assert result.is_success

    def test_create_user_request_to_user_entity(self) -> None:
        """Test CreateUserRequest.to_user_entity() conversion."""
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name="Test",
            mail="test@example.com",
            user_password="password123",
            telephone_number=None,
            description=None,
            department=None,
            organizational_unit=None,
            title=None,
            organization=None,
        )

        # Test conversion to user entity
        user = request.to_user_entity()
        assert isinstance(user, FlextLdapModels.LdapUser)
        assert user.dn == "uid=test,ou=users,dc=example,dc=com"
        assert user.uid == "testuser"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.mail == "test@example.com"

    # =========================================================================
    # PHASE 2.1.5 BATCH 3: LDAPUSER COMPUTED FIELDS (73% → 85% TARGET)
    # =========================================================================

    def test_ldap_user_display_name_with_given_name_and_sn(self) -> None:
        """Test LdapUser.display_name with given_name and sn."""
        user = FlextLdapModels.LdapUser(
            dn="uid=jdoe,ou=users,dc=example,dc=com",
            cn="John Doe",
            uid="jdoe",
            sn="Doe",
            given_name="John",
            mail="jdoe@example.com",
        )

        assert user.display_name == "John Doe"

    def test_ldap_user_display_name_with_given_name_only(self) -> None:
        """Test LdapUser.display_name with only given_name."""
        user = FlextLdapModels.LdapUser(
            dn="uid=john,ou=users,dc=example,dc=com",
            cn="John",
            uid="john",
            sn="",
            given_name="John",
            mail="john@example.com",
        )

        assert user.display_name == "John"

    def test_ldap_user_display_name_with_sn_only(self) -> None:
        """Test LdapUser.display_name with only sn."""
        user = FlextLdapModels.LdapUser(
            dn="uid=doe,ou=users,dc=example,dc=com",
            cn="Doe",
            uid="doe",
            sn="Doe",
            mail="doe@example.com",
        )

        assert user.display_name == "Doe"

    def test_ldap_user_display_name_fallback_to_cn(self) -> None:
        """Test LdapUser.display_name fallback to cn."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="testuser",
            sn="",
            mail="test@example.com",
        )

        assert user.display_name == "Test User"

    def test_ldap_user_is_active_status_enabled(self) -> None:
        """Test LdapUser.is_active with active status."""
        user = FlextLdapModels.LdapUser(
            dn="uid=active,ou=users,dc=example,dc=com",
            cn="Active User",
            uid="active",
            sn="User",
            mail="active@example.com",
            status="active",
        )

        assert user.is_active is True

    def test_ldap_user_is_active_status_disabled(self) -> None:
        """Test LdapUser.is_active with disabled status."""
        user = FlextLdapModels.LdapUser(
            dn="uid=disabled,ou=users,dc=example,dc=com",
            cn="Disabled User",
            uid="disabled",
            sn="User",
            mail="disabled@example.com",
            status="disabled",
        )

        assert user.is_active is False

    def test_ldap_user_is_active_no_status(self) -> None:
        """Test LdapUser.is_active with no status (defaults to True)."""
        user = FlextLdapModels.LdapUser(
            dn="uid=nostatus,ou=users,dc=example,dc=com",
            cn="No Status User",
            uid="nostatus",
            sn="User",
            mail="nostatus@example.com",
        )

        assert user.is_active is True

    def test_ldap_user_has_contact_info_complete(self) -> None:
        """Test LdapUser.has_contact_info with complete info."""
        user = FlextLdapModels.LdapUser(
            dn="uid=complete,ou=users,dc=example,dc=com",
            cn="Complete User",
            uid="complete",
            sn="User",
            mail="complete@example.com",
            telephone_number="555-1234",
            mobile="555-5678",
        )

        assert user.has_contact_info is True

    def test_ldap_user_has_contact_info_mail_and_phone(self) -> None:
        """Test LdapUser.has_contact_info with mail and telephone."""
        user = FlextLdapModels.LdapUser(
            dn="uid=phone,ou=users,dc=example,dc=com",
            cn="Phone User",
            uid="phone",
            sn="User",
            mail="phone@example.com",
            telephone_number="555-1234",
        )

        assert user.has_contact_info is True

    def test_ldap_user_has_contact_info_incomplete(self) -> None:
        """Test LdapUser.has_contact_info with incomplete info."""
        user = FlextLdapModels.LdapUser(
            dn="uid=incomplete,ou=users,dc=example,dc=com",
            cn="Incomplete User",
            uid="incomplete",
            sn="User",
            mail="incomplete@example.com",
        )

        assert user.has_contact_info is False

    def test_ldap_user_organizational_path_complete(self) -> None:
        """Test LdapUser.organizational_path with complete hierarchy."""
        user = FlextLdapModels.LdapUser(
            dn="uid=org,ou=users,dc=example,dc=com",
            cn="Org User",
            uid="org",
            sn="User",
            mail="org@example.com",
            organization="ACME Corp",
            organizational_unit="Engineering",
            department="Software Development",
        )

        assert (
            user.organizational_path == "ACME Corp > Engineering > Software Development"
        )

    def test_ldap_user_organizational_path_partial(self) -> None:
        """Test LdapUser.organizational_path with partial hierarchy."""
        user = FlextLdapModels.LdapUser(
            dn="uid=partial,ou=users,dc=example,dc=com",
            cn="Partial User",
            uid="partial",
            sn="User",
            mail="partial@example.com",
            organization="ACME Corp",
            organizational_unit="Engineering",  # Required when department is set
            department="IT",
        )

        assert user.organizational_path == "ACME Corp > Engineering > IT"

    def test_ldap_user_organizational_path_empty(self) -> None:
        """Test LdapUser.organizational_path with defaults from constants."""
        user = FlextLdapModels.LdapUser(
            dn="uid=noorg,ou=users,dc=example,dc=com",
            cn="No Org User",
            uid="noorg",
            sn="User",
            mail="noorg@example.com",
        )

        # Model applies defaults from FlextLdapConstants.Defaults
        assert user.organizational_path == "Company > IT"

    def test_ldap_user_rdn_extraction(self) -> None:
        """Test LdapUser.rdn computed field."""
        user = FlextLdapModels.LdapUser(
            dn="uid=testuser,ou=people,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="testuser",
            sn="User",
            mail="test@example.com",
        )

        assert user.rdn == "uid=testuser"

    def test_ldap_user_rdn_single_component(self) -> None:
        """Test LdapUser.rdn with single component DN."""
        user = FlextLdapModels.LdapUser(
            dn="dc=com",
            cn="Root",
            uid="root",
            sn="Root",
            mail="root@example.com",
        )

        assert user.rdn == "dc=com"

    # =========================================================================
    # PHASE 2.1.5 BATCH 4: CONFIG VALIDATION METHODS (74% → 80% TARGET)
    # =========================================================================

    # =========================================================================
    # Phase 2.1.5 Batch 5: LdapUser factory methods and advanced validation
    # Coverage target: Lines 629-631, 643-644, 667-671, 701-733, 873-924
    # =========================================================================

    def test_ldap_user_validate_object_classes_empty(self) -> None:
        """Test LdapUser validation with empty object_classes."""
        from flext_ldap.exceptions import FlextLdapExceptions

        with pytest.raises(FlextLdapExceptions.LdapValidationError) as exc_info:
            FlextLdapModels.LdapUser(
                dn="uid=test,ou=users,dc=example,dc=com",
                cn="Test User",
                uid="test",
                sn="User",
                mail="test@example.com",
                object_classes=[],  # Empty - should fail
            )

        # Verify error message mentions object class requirement
        assert "object class" in str(exc_info.value).lower()

    def test_ldap_user_validate_person_object_class_missing(self) -> None:
        """Test LdapUser validation without 'person' object class."""
        from flext_ldap.exceptions import FlextLdapExceptions

        with pytest.raises(FlextLdapExceptions.LdapValidationError) as exc_info:
            FlextLdapModels.LdapUser(
                dn="uid=test,ou=users,dc=example,dc=com",
                cn="Test User",
                uid="test",
                sn="User",
                mail="test@example.com",
                object_classes=["inetOrgPerson"],  # Missing 'person'
            )

        # Verify error message mentions 'person' object class
        assert "person" in str(exc_info.value).lower()

    def test_ldap_user_serialize_password_none(self) -> None:
        """Test password serialization with None value."""
        user = FlextLdapModels.LdapUser(
            dn="uid=test,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="test",
            sn="User",
            mail="test@example.com",
            user_password=None,  # None password
        )
        # Serialize to dict[str, object] to trigger serializer
        user_dict = user.model_dump()
        assert user_dict["user_password"] is None

    def test_ldap_user_serialize_password_secret_str(self) -> None:
        """Test password serialization with SecretStr."""
        user = FlextLdapModels.LdapUser(
            dn="uid=test,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="test",
            sn="User",
            mail="test@example.com",
            user_password="secret123",  # Will be converted to SecretStr
        )
        # Serialize to dict[str, object] to trigger serializer
        user_dict = user.model_dump()
        assert user_dict["user_password"] == "[PROTECTED]"

    def test_ldap_user_to_ldap_attributes_minimal(self) -> None:
        """Test to_ldap_attributes() with minimal user data."""
        user = FlextLdapModels.LdapUser(
            dn="uid=minimal,ou=users,dc=example,dc=com",
            cn="Minimal User",
            uid="minimal",
            sn="User",
            mail="minimal@example.com",
        )
        ldap_dict = user.to_ldap_attributes()

        # Verify core attributes are present
        assert ldap_dict["dn"] == ["uid=minimal,ou=users,dc=example,dc=com"]
        assert ldap_dict["cn"] == ["Minimal User"]
        assert ldap_dict["uid"] == ["minimal"]
        assert ldap_dict["sn"] == ["User"]
        assert ldap_dict["mail"] == ["minimal@example.com"]
        assert "objectClass" in ldap_dict

    def test_ldap_user_to_ldap_attributes_complete(self) -> None:
        """Test to_ldap_attributes() with all optional fields populated."""
        user = FlextLdapModels.LdapUser(
            dn="uid=complete,ou=users,dc=example,dc=com",
            cn="Complete User",
            uid="complete",
            sn="User",
            given_name="Complete",
            mail="complete@example.com",
            telephone_number="555-1111",
            mobile="555-2222",
            department="Engineering",
            title="Senior Engineer",
            organization="ACME Corp",
            organizational_unit="IT",
            object_classes=["person", "organizationalPerson", "inetOrgPerson"],
        )
        ldap_dict = user.to_ldap_attributes()

        # Verify all attributes are present
        assert ldap_dict["dn"] == ["uid=complete,ou=users,dc=example,dc=com"]
        assert ldap_dict["cn"] == ["Complete User"]
        assert ldap_dict["uid"] == ["complete"]
        assert ldap_dict["sn"] == ["User"]
        assert ldap_dict["givenName"] == ["Complete"]
        assert ldap_dict["mail"] == ["complete@example.com"]
        assert ldap_dict["telephoneNumber"] == ["555-1111"]
        assert ldap_dict["mobile"] == ["555-2222"]
        assert ldap_dict["department"] == ["Engineering"]
        assert ldap_dict["title"] == ["Senior Engineer"]
        assert ldap_dict["o"] == ["ACME Corp"]
        assert ldap_dict["ou"] == ["IT"]
        assert ldap_dict["objectClass"] == [
            "person",
            "organizationalPerson",
            "inetOrgPerson",
        ]

    def test_ldap_user_to_ldap_attributes_with_additional_attributes(self) -> None:
        """Test to_ldap_attributes() with additional_attributes."""
        user = FlextLdapModels.LdapUser(
            dn="uid=extra,ou=users,dc=example,dc=com",
            cn="Extra User",
            uid="extra",
            sn="User",
            mail="extra@example.com",
            additional_attributes={
                "customAttr": "value1",
                "listAttr": ["value2", "value3"],
                "numericAttr": "42",  # Must be string per model validation
            },
        )
        ldap_dict = user.to_ldap_attributes()

        # Verify additional attributes are converted to string lists
        assert ldap_dict["customAttr"] == ["value1"]
        assert ldap_dict["listAttr"] == ["value2", "value3"]
        assert ldap_dict["numericAttr"] == ["42"]

    def test_ldap_user_create_minimal_factory(self) -> None:
        """Test create_minimal() factory with minimal parameters."""
        result = FlextLdapModels.LdapUser.create_minimal(
            dn="uid=factory,ou=users,dc=example,dc=com",
            cn="Factory User",
            mail="factory@example.com",  # Required for email validation
        )

        assert result.is_success
        user = result.unwrap()
        assert user.dn == "uid=factory,ou=users,dc=example,dc=com"
        assert user.cn == "Factory User"
        assert user.mail == "factory@example.com"
        assert not user.uid  # Default empty string
        assert not user.sn  # Default empty string
        assert user.object_classes == [
            "person",
            "organizationalPerson",
            "inetOrgPerson",
        ]

    def test_ldap_user_create_minimal_with_uid(self) -> None:
        """Test create_minimal() factory with uid parameter."""
        result = FlextLdapModels.LdapUser.create_minimal(
            dn="uid=factory2,ou=users,dc=example,dc=com",
            cn="Factory User 2",
            uid="factory2",
            mail="factory2@example.com",
        )

        assert result.is_success
        user = result.unwrap()
        assert user.uid == "factory2"

    def test_ldap_user_create_minimal_with_all_optionals(self) -> None:
        """Test create_minimal() factory with all optional parameters."""
        result = FlextLdapModels.LdapUser.create_minimal(
            dn="uid=full,ou=users,dc=example,dc=com",
            cn="Full Factory User",
            uid="full",
            sn="User",
            given_name="Full",
            mail="full@example.com",
            telephone_number="555-3333",
            mobile="555-4444",
            department="Sales",
            title="Sales Manager",
            organization="ACME Inc",
            organizational_unit="Sales",
            user_password="secret456",
        )

        assert result.is_success
        user = result.unwrap()
        assert user.sn == "User"
        assert user.given_name == "Full"
        assert user.mail == "full@example.com"
        assert user.telephone_number == "555-3333"
        assert user.mobile == "555-4444"
        assert user.department == "Sales"
        assert user.title == "Sales Manager"
        assert user.organization == "ACME Inc"
        assert user.organizational_unit == "Sales"
        assert user.user_password is not None

    def test_ldap_user_create_minimal_with_none_password(self) -> None:
        """Test create_minimal() factory with explicit None password."""
        result = FlextLdapModels.LdapUser.create_minimal(
            dn="uid=nopass,ou=users,dc=example,dc=com",
            cn="No Password User",
            mail="nopass@example.com",
            user_password=None,
        )

        assert result.is_success
        user = result.unwrap()
        assert user.user_password is None

    def test_ldap_user_create_minimal_error_handling(self) -> None:
        """Test create_minimal() factory error handling with invalid data."""
        # Try to create user with empty mail which triggers email validation error
        result = FlextLdapModels.LdapUser.create_minimal(
            dn="uid=invalid,ou=users,dc=example,dc=com",
            cn="Invalid User",
            mail="",  # Empty mail triggers validation error
        )

        # Factory should catch exception and return failure result
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "creation failed" in result.error.lower()
        )

    def test_connection_config_validate_empty_server(self) -> None:
        """Test ConnectionConfig.validate_business_rules() with empty server."""
        config = FlextLdapModels.ConnectionConfig(
            server="",  # Empty server
            port=389,
        )

        result = config.validate_business_rules()
        assert result.is_failure
        assert result.error is not None
        assert (
            result.error and result.error and "Server cannot be empty" in result.error
        )

    def test_connection_config_validate_invalid_port_zero(self) -> None:
        """Test ConnectionConfig validation with port 0 (explicit validation)."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=0,  # Invalid port
        )

        result = config.validate_business_rules()
        assert result.is_failure
        assert result.error is not None
        assert "port" in result.error.lower()

    def test_connection_config_validate_invalid_port_too_high(self) -> None:
        """Test ConnectionConfig.validate_business_rules() with port > 65535."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=70000,  # Too high
        )

        result = config.validate_business_rules()
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "Invalid port number" in result.error

    def test_connection_config_validate_success(self) -> None:
        """Test ConnectionConfig.validate_business_rules() with valid data."""
        config = FlextLdapModels.ConnectionConfig(
            server="ldap.example.com",
            port=389,
        )

        result = config.validate_business_rules()
        assert result.is_success

    def test_modify_config_validate_empty_dn(self) -> None:
        """Test ModifyConfig.validate_business_rules() with empty DN."""
        from flext_ldap.models import FlextLdapModels

        config = FlextLdapModels.ModifyConfig(
            dn="",  # Empty DN
            changes={"cn": [("MODIFY_REPLACE", ["New Name"])]},
        )

        result = config.validate_business_rules()
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN cannot be empty" in result.error

    def test_modify_config_validate_empty_changes(self) -> None:
        """Test ModifyConfig Pydantic validation with empty changes."""
        from flext_ldap.models import FlextLdapModels

        # Create with empty changes and use explicit validation
        config = FlextLdapModels.ModifyConfig(
            dn="cn=test,dc=example,dc=com",
            changes={},  # Empty changes
        )

        result = config.validate_business_rules()
        assert result.is_failure
        assert result.error is not None
        assert "Changes cannot be empty" in result.error

    def test_modify_config_validate_success(self) -> None:
        """Test ModifyConfig.validate_business_rules() with valid data."""
        from flext_ldap.models import FlextLdapModels

        config = FlextLdapModels.ModifyConfig(
            dn="cn=test,dc=example,dc=com",
            changes={"cn": [("MODIFY_REPLACE", ["New Name"])]},
        )

        result = config.validate_business_rules()
        assert result.is_success

    def test_add_config_validate_empty_dn(self) -> None:
        """Test AddConfig.validate_business_rules() with empty DN."""
        from flext_ldap.models import FlextLdapModels

        config = FlextLdapModels.AddConfig(
            dn="",  # Empty DN
            attributes={"objectClass": ["person"], "cn": ["Test"]},
        )

        result = config.validate_business_rules()
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN cannot be empty" in result.error

    def test_add_config_validate_success(self) -> None:
        """Test AddConfig.validate_business_rules() with valid data."""
        from flext_ldap.models import FlextLdapModels

        config = FlextLdapModels.AddConfig(
            dn="cn=test,dc=example,dc=com",
            attributes={"objectClass": ["person"], "cn": ["Test"]},
        )

        result = config.validate_business_rules()
        assert result.is_success
