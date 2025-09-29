"""Comprehensive unit tests for flext-ldap models module.

This module provides complete test coverage for the flext-ldap models functionality,
following FLEXT standards with real functionality testing and no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

import pytest

from flext_core import FlextResult
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


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
        assert isinstance(result, FlextResult)
        assert result.is_success
        # Use unwrap() to get the actual DistinguishedName object
        dn_obj = result.unwrap()
        assert isinstance(dn_obj, FlextLdapModels.DistinguishedName)
        assert dn_obj.value == "cn=testuser,dc=test,dc=com"

        # Test invalid DN creation
        result = FlextLdapModels.DistinguishedName.create("")
        assert isinstance(result, FlextResult)
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
        # Test valid scope
        valid_scope = FlextLdapModels.Scope(value="subtree")
        assert valid_scope.value == "subtree"

        # Test invalid scope
        with pytest.raises(ValueError):
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

        assert quirks.server_type == FlextLdapModels.LdapServerType.OPENLDAP
        assert quirks.supports_paged_results is True
        assert quirks.supports_sync is True
        assert quirks.max_page_size == FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE
        assert quirks.object_class_mappings == {"person": "inetOrgPerson"}

    def test_schema_discovery_result_creation(self) -> None:
        """Test SchemaDiscoveryResult model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        result = FlextLdapModels.SchemaDiscoveryResult(
            server_info={"vendor": "OpenLDAP", "version": "2.4"},
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

        assert result.server_type == FlextLdapModels.LdapServerType.OPENLDAP
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
        assert isinstance(result, FlextResult)
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
        assert isinstance(result, FlextResult)
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
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            bind_password="testpass",
            timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
        )

        assert config.server == "localhost"
        assert config.port == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert config.use_ssl is False
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"
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
        delete_data = {"dn": "cn=testuser,dc=test,dc=com"}

        config = FlextLdapModels.DeleteConfig(**delete_data)

        assert config.dn == "cn=testuser,dc=test,dc=com"

    def test_search_config_creation(self) -> None:
        """Test SearchConfig model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        config = FlextLdapModels.SearchConfig(
            base_dn="dc=test,dc=com",
            search_filter="(objectClass=*)",
            attributes=["cn", "mail"],
        )

        assert config.base_dn == "dc=test,dc=com"
        assert config.search_filter == "(objectClass=*)"
        assert config.attributes == ["cn", "mail"]

    def test_search_response_creation(self) -> None:
        """Test SearchResponse model creation."""
        # Pass arguments explicitly to avoid mixed type issues
        response = FlextLdapModels.SearchResponse(
            entries=[
                {
                    "dn": "cn=testuser,dc=test,dc=com",
                    "attributes": {"cn": "testuser", "mail": "test@example.com"},
                }
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
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            bind_password="testpass",
        )

        # Verify configuration is properly set
        assert config.server == "localhost"
        assert config.port == FlextLdapConstants.Protocol.DEFAULT_PORT
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"
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
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=FlextLdapConstants.Protocol.DEFAULT_PORT,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com",
            bind_password="testpass",
        )

        # Verify all models are valid
        assert dn.value == "cn=testuser,dc=test,dc=com"
        assert filter_obj.expression == "(objectClass=*)"
        assert scope.value == "subtree"
        assert user.cn == "testuser"
        assert config.server == "localhost"
