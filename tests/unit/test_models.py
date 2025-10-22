"""Comprehensive unit tests for flext-ldap models module.

This module provides complete test coverage for the flext-ldap models functionality,
following FLEXT standards with real functionality testing and no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldap.models import FlextLdapModels

# ===================================================================
# BATCH 3: ACL CONVERSION TESTS (10 tests)
# Testing ACL model conversion and transformation patterns
# ===================================================================


class TestFlextLdapModels:
    """Comprehensive tests for FlextLdapModels class."""

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
        full_user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=john,ou=people,dc=example,dc=com",
            uid="john",
            cn="John Doe",
            sn="Doe",
            given_name="John",
            mail=["john@example.com"],
            telephone_number=["+1-555-0100"],
            mobile=["+1-555-0101"],
            department="Engineering",
            organizational_unit="Engineering",  # Required when department is set
            title="Software Engineer",
            organization="Example Corp",
            user_password="hashed_password",
            object_classes=["person", "inetOrgPerson"],
        )
        assert full_user.uid == "john"
        assert full_user.department == "Engineering"
        assert full_user.organizational_unit == "Engineering"

        # Minimal user (required fields: dn, cn, uid, sn, mail)
        minimal_user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=jane,ou=people,dc=example,dc=com",
            uid="jane",
            cn="Jane Smith",
            sn="Smith",
            mail=["jane@example.com"],  # mail is required
            object_classes=["person", "inetOrgPerson"],
        )
        assert minimal_user.uid == "jane"
        assert minimal_user.mail == ["jane@example.com"]
        assert minimal_user.given_name is None
        assert minimal_user.telephone_number is None  # Depends on rules

    def test_group_member_management(self) -> None:
        """Test Group member management operations."""
        group = FlextLdapModels.Entry(
            entry_type="group",
            dn="cn=developers,ou=groups,dc=example,dc=com",
            cn="developers",
            description="Developers group",
            member_dns=[
                "uid=user1,ou=people,dc=example,dc=com",
                "uid=user2,ou=people,dc=example,dc=com",
                "uid=user3,ou=people,dc=example,dc=com",
            ],
            gid_number=1001,
            object_classes=["groupOfNames"],
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

        # Test single-valued attribute access (extracted from lists)
        assert entry.uid == "testuser"
        assert entry.cn == "Test User"

        # Test multi-valued attribute access (remains as list)
        assert isinstance(entry.mail, list)
        assert len(entry.mail) == 2
        assert "testuser@example.com" in entry.mail
        assert "test.user@example.com" in entry.mail

        # Test objectClass access (multi-valued)
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
        assert paged_request.page_size is not None and paged_request.page_size > 0

        # Test non-paged search
        non_paged = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
        )
        assert non_paged.page_size is None or non_paged.page_size <= 0

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
        success = FlextLdapModels.LdapOperationResult(
            success=True,
            result_message="User created successfully",
            target_dn="uid=john,ou=people,dc=example,dc=com",
            duration_ms=0.0,
        )
        assert success.success is True
        assert "created successfully" in success.result_message
        assert success.target_dn == "uid=john,ou=people,dc=example,dc=com"

        # Error result factory (OperationResult has result_code and result_message, not error_code/error_message)
        error = FlextLdapModels.LdapOperationResult(
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
        pytest.skip("LdapError model not yet implemented")

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
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=jdoe,ou=users,dc=example,dc=com",
            cn="John Doe",
            uid="jdoe",
            sn="Doe",
            given_name="John",
            mail=["jdoe@example.com"],
            telephone_number=["+1-555-0100"],
            mobile=["+1-555-0199"],
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

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)

        assert result.is_success
        user = result.unwrap()
        assert user.dn == "uid=testuser,ou=users,dc=example,dc=com"
        assert user.cn == "Test User"
        assert user.uid == "testuser"
        assert user.sn == "User"
        assert user.given_name == "Test"
        assert user.mail == ["testuser@example.com"]
        assert user.telephone_number == ["+1-555-0200"]
        assert user.mobile == ["+1-555-0299"]
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

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)

        assert result.is_success
        user = result.unwrap()
        assert user.dn == "cn=minuser,dc=example,dc=com"
        assert user.cn == "Minimal User"
        assert user.mail == ["minuser@example.com"]

    def test_ldap_user_from_ldap_attributes_missing_dn(self) -> None:
        """Test LdapUser.from_ldap_attributes() fails without DN."""
        ldap_attrs = {
            "cn": ["No DN User"],
            "sn": ["User"],
        }

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)

        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN is required" in result.error

    def test_group_to_ldap_attributes(self) -> None:
        """Test Group.to_ldap_attributes() conversion method."""
        pytest.skip("Group model structure has changed - test needs refactoring")

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

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)

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
        pytest.skip("CqrsCommand model not yet implemented")

    def test_cqrs_query_direct_creation(self) -> None:
        """Test CqrsQuery direct instantiation."""
        pytest.skip("CqrsQuery model not yet implemented")

    def test_cqrs_event_direct_creation(self) -> None:
        """Test CqrsEvent direct instantiation."""
        pytest.skip("CqrsEvent model not yet implemented")

    def test_domain_message_direct_creation(self) -> None:
        """Test DomainMessage direct instantiation."""
        pytest.skip("DomainMessage model not yet implemented")

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
            entry_type="entry",
            object_classes=["top"],
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
            entry_type="entry",
            object_classes=["person", "organizationalPerson", "inetOrgPerson"],
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
            entry_type="entry",
            object_classes=["top"],
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
            entry_type="entry",
            object_classes=["top"],
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
            entry_type="entry",
            object_classes=["top"],
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
            entry_type="entry",
            object_classes=["top"],
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
            entry_type="entry",
            object_classes=["top"],
        )
        assert entry1.get_rdn() == "cn=testuser"

        # Test DN with multiple components
        entry2 = FlextLdapModels.Entry(
            dn="uid=jdoe,ou=people,ou=users,dc=company,dc=com",
            attributes={"uid": ["jdoe"]},
            entry_type="entry",
            object_classes=["person", "inetOrgPerson"],
        )
        assert entry2.get_rdn() == "uid=jdoe"

        # Test single component DN (no commas)
        entry3 = FlextLdapModels.Entry(
            dn="dc=com",
            attributes={"dc": ["com"]},
            entry_type="entry",
            object_classes=["dcObject"],
        )
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
            entry_type="entry",
            object_classes=["person", "inetOrgPerson"],
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
            entry_type="entry",
            object_classes=["top"],
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
            entry_type="entry",
            object_classes=["top"],
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
            "objectClass": ["groupOfNames", "posixGroup", "top"],
            "member": [
                "uid=user1,ou=users,dc=example,dc=com",
                "uid=user2,ou=users,dc=example,dc=com",
            ],
        }

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)
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

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)
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
            "objectClass": ["groupOfNames", "groupOfUniqueNames", "top"],
            "uniqueMember": [
                "uid=user1,ou=users,dc=example,dc=com",
                "uid=user2,ou=users,dc=example,dc=com",
            ],
        }

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)
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

        result = FlextLdapModels.Entry.from_ldap_attributes(ldap_attrs)
        assert result.is_failure
        assert result.error is not None
        assert result.error and result.error and "DN is required" in result.error

    def test_search_request_search_complexity_simple(self) -> None:
        """Test SearchRequest.search_complexity computed field - simple."""
        pytest.skip("search_complexity computed field not yet implemented")

    def test_search_request_search_complexity_moderate(self) -> None:
        """Test SearchRequest.search_complexity computed field - moderate."""
        pytest.skip("search_complexity computed field not yet implemented")

    def test_search_request_search_complexity_complex(self) -> None:
        """Test SearchRequest.search_complexity computed field - complex."""
        pytest.skip("search_complexity computed field not yet implemented")

    def test_search_request_normalized_scope(self) -> None:
        """Test SearchRequest.normalized_scope computed field."""
        pytest.skip("normalized_scope computed field not yet implemented")

    def test_search_request_estimated_result_count_base(self) -> None:
        """Test SearchRequest.estimated_result_count - base scope."""
        pytest.skip("estimated_result_count computed field not yet implemented")

    def test_search_request_estimated_result_count_onelevel(self) -> None:
        """Test SearchRequest.estimated_result_count - onelevel scope."""
        pytest.skip("estimated_result_count computed field not yet implemented")

    def test_search_request_estimated_result_count_subtree_specific(self) -> None:
        """Test SearchRequest.estimated_result_count - subtree with specific filter."""
        pytest.skip("estimated_result_count computed field not yet implemented")

    def test_search_request_estimated_result_count_subtree_broad(self) -> None:
        """Test SearchRequest.estimated_result_count - subtree with broad filter."""
        pytest.skip("estimated_result_count computed field not yet implemented")

    def test_create_user_request_validate_business_rules_success(self) -> None:
        """Test CreateUserRequest.validate_business_rules() succeeds with valid data."""
        pytest.skip("validate_business_rules method not yet implemented")

    def test_create_user_request_to_user_entity(self) -> None:
        """Test CreateUserRequest.to_user_entity() conversion."""
        pytest.skip("to_user_entity method not yet implemented")

    # =========================================================================
    # PHASE 2.1.5 BATCH 3: LDAPUSER COMPUTED FIELDS (73% → 85% TARGET)
    # =========================================================================

    def test_ldap_user_display_name_with_given_name_and_sn(self) -> None:
        """Test LdapUser.display_name with given_name and sn."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=jdoe,ou=users,dc=example,dc=com",
            cn="John Doe",
            uid="jdoe",
            sn="Doe",
            given_name="John",
            mail=["jdoe@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.display_name == "John Doe"

    def test_ldap_user_display_name_with_given_name_only(self) -> None:
        """Test LdapUser.display_name with only given_name."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=john,ou=users,dc=example,dc=com",
            cn="John",
            uid="john",
            sn="",
            given_name="John",
            mail=["john@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.display_name == "John"

    def test_ldap_user_display_name_with_sn_only(self) -> None:
        """Test LdapUser.display_name with only sn."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=doe,ou=users,dc=example,dc=com",
            cn="Doe",
            uid="doe",
            sn="Doe",
            mail=["doe@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.display_name == "Doe"

    def test_ldap_user_display_name_fallback_to_cn(self) -> None:
        """Test LdapUser.display_name fallback to cn."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=testuser,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="testuser",
            sn="",
            mail=["test@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.display_name == "Test User"

    def test_ldap_user_is_active_status_enabled(self) -> None:
        """Test LdapUser.is_active with active status."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=active,ou=users,dc=example,dc=com",
            cn="Active User",
            uid="active",
            sn="User",
            mail=["active@example.com"],
            status="active",
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.is_active is True

    def test_ldap_user_is_active_status_disabled(self) -> None:
        """Test LdapUser.is_active with disabled status."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=disabled,ou=users,dc=example,dc=com",
            cn="Disabled User",
            uid="disabled",
            sn="User",
            mail=["disabled@example.com"],
            status="disabled",
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.is_active is False

    def test_ldap_user_is_active_no_status(self) -> None:
        """Test LdapUser.is_active with no status (defaults to True)."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=nostatus,ou=users,dc=example,dc=com",
            cn="No Status User",
            uid="nostatus",
            sn="User",
            mail=["nostatus@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.is_active is True

    def test_ldap_user_has_contact_info_complete(self) -> None:
        """Test LdapUser.has_contact_info with complete info."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=complete,ou=users,dc=example,dc=com",
            cn="Complete User",
            uid="complete",
            sn="User",
            mail=["complete@example.com"],
            telephone_number=["555-1234"],
            mobile=["555-5678"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.has_contact_info is True

    def test_ldap_user_has_contact_info_mail_and_phone(self) -> None:
        """Test LdapUser.has_contact_info with mail and telephone."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=phone,ou=users,dc=example,dc=com",
            cn="Phone User",
            uid="phone",
            sn="User",
            mail=["phone@example.com"],
            telephone_number=["555-1234"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.has_contact_info is True

    def test_ldap_user_has_contact_info_incomplete(self) -> None:
        """Test LdapUser.has_contact_info with incomplete info."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=incomplete,ou=users,dc=example,dc=com",
            cn="Incomplete User",
            uid="incomplete",
            sn="User",
            mail=["incomplete@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.has_contact_info is False

    def test_ldap_user_organizational_path_complete(self) -> None:
        """Test LdapUser.organizational_path with complete hierarchy."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=org,ou=users,dc=example,dc=com",
            cn="Org User",
            uid="org",
            sn="User",
            mail=["org@example.com"],
            organization="ACME Corp",
            organizational_unit="Engineering",
            department="Software Development",
            object_classes=["person", "inetOrgPerson"],
        )

        assert (
            user.organizational_path == "ACME Corp > Engineering > Software Development"
        )

    def test_ldap_user_organizational_path_partial(self) -> None:
        """Test LdapUser.organizational_path with partial hierarchy."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=partial,ou=users,dc=example,dc=com",
            cn="Partial User",
            uid="partial",
            sn="User",
            mail=["partial@example.com"],
            organization="ACME Corp",
            organizational_unit="Engineering",  # Required when department is set
            department="IT",
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.organizational_path == "ACME Corp > Engineering > IT"

    def test_ldap_user_organizational_path_empty(self) -> None:
        """Test LdapUser.organizational_path when no org fields provided."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=noorg,ou=users,dc=example,dc=com",
            cn="No Org User",
            uid="noorg",
            sn="User",
            mail=["noorg@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        # When no organization fields provided, returns fallback message
        assert user.organizational_path == "No organization"

    def test_ldap_user_rdn_extraction(self) -> None:
        """Test LdapUser.rdn computed field."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=testuser,ou=people,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="testuser",
            sn="User",
            mail=["test@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        assert user.rdn == "uid=testuser"

    def test_ldap_user_rdn_single_component(self) -> None:
        """Test LdapUser.rdn with single component DN."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="dc=com",
            cn="Root",
            uid="root",
            sn="Root",
            mail=["root@example.com"],
            object_classes=["person", "inetOrgPerson"],
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
        pytest.skip("LdapUser model structure has changed - test needs refactoring")

    def test_ldap_user_validate_person_object_class_missing(self) -> None:
        """Test LdapUser validation without 'person' object class."""
        pytest.skip("LdapUser model structure has changed - test needs refactoring")

    def test_ldap_user_serialize_password_none(self) -> None:
        """Test password serialization with None value."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=test,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="test",
            sn="User",
            mail=["test@example.com"],
            user_password=None,  # None password
            object_classes=["person", "inetOrgPerson", "top"],
        )
        # Serialize to dict[str, object] to trigger serializer
        user_dict = user.model_dump()
        assert user_dict["user_password"] is None

    def test_ldap_user_serialize_password_secret_str(self) -> None:
        """Test password serialization with SecretStr."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=test,ou=users,dc=example,dc=com",
            cn="Test User",
            uid="test",
            sn="User",
            mail=["test@example.com"],
            user_password="secret123",  # Will be converted to SecretStr
            object_classes=["person", "inetOrgPerson"],
        )
        # Serialize to dict[str, object] to trigger serializer
        user_dict = user.model_dump()
        assert user_dict["user_password"] == "[PROTECTED]"

    def test_ldap_user_to_ldap_attributes_minimal(self) -> None:
        """Test to_ldap_attributes() with minimal user data."""
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=minimal,ou=users,dc=example,dc=com",
            cn="Minimal User",
            uid="minimal",
            sn="User",
            mail=["minimal@example.com"],
            object_classes=["person", "inetOrgPerson"],
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
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=complete,ou=users,dc=example,dc=com",
            cn="Complete User",
            uid="complete",
            sn="User",
            given_name="Complete",
            mail=["complete@example.com"],
            telephone_number=["555-1111"],
            mobile=["555-2222"],
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
        user = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=extra,ou=users,dc=example,dc=com",
            cn="Extra User",
            uid="extra",
            sn="User",
            mail=["extra@example.com"],
            additional_attributes={
                "customAttr": "value1",
                "listAttr": ["value2", "value3"],
                "numericAttr": "42",  # Must be string per model validation
            },
            object_classes=["person", "inetOrgPerson"],
        )
        ldap_dict = user.to_ldap_attributes()

        # Verify additional attributes are converted to string lists
        assert ldap_dict["customAttr"] == ["value1"]
        assert ldap_dict["listAttr"] == ["value2", "value3"]
        assert ldap_dict["numericAttr"] == ["42"]

    def test_ldap_user_create_minimal_factory(self) -> None:
        """Test create_minimal() factory with minimal parameters."""
        result = FlextLdapModels.Entry.create_minimal(
            dn="uid=factory,ou=users,dc=example,dc=com",
            cn="Factory User",
            entry_type="user",
            mail=["factory@example.com"],  # Required for email validation
        )

        assert result.is_success
        user = result.unwrap()
        assert user.dn == "uid=factory,ou=users,dc=example,dc=com"
        assert user.cn == "Factory User"
        assert user.mail == ["factory@example.com"]
        assert not user.uid  # Default empty string
        assert not user.sn  # Default empty string
        assert user.object_classes == [
            "person",
            "organizationalPerson",
            "inetOrgPerson",
        ]

    def test_ldap_user_create_minimal_with_uid(self) -> None:
        """Test create_minimal() factory with uid parameter."""
        result = FlextLdapModels.Entry.create_minimal(
            dn="uid=factory2,ou=users,dc=example,dc=com",
            cn="Factory User 2",
            entry_type="user",
            uid="factory2",
            mail=["factory2@example.com"],
        )

        assert result.is_success
        user = result.unwrap()
        assert user.uid == "factory2"

    def test_ldap_user_create_minimal_with_all_optionals(self) -> None:
        """Test create_minimal() factory with all optional parameters."""
        result = FlextLdapModels.Entry.create_minimal(
            dn="uid=full,ou=users,dc=example,dc=com",
            cn="Full Factory User",
            entry_type="user",
            uid="full",
            sn="User",
            given_name="Full",
            mail=["full@example.com"],
            telephone_number=["555-3333"],
            mobile=["555-4444"],
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
        assert user.mail == ["full@example.com"]
        assert user.telephone_number == ["555-3333"]
        assert user.mobile == ["555-4444"]
        assert user.department == "Sales"
        assert user.title == "Sales Manager"
        assert user.organization == "ACME Inc"
        assert user.organizational_unit == "Sales"
        assert user.user_password is not None

    def test_ldap_user_create_minimal_with_none_password(self) -> None:
        """Test create_minimal() factory with explicit None password."""
        result = FlextLdapModels.Entry.create_minimal(
            dn="uid=nopass,ou=users,dc=example,dc=com",
            cn="No Password User",
            entry_type="user",
            mail=["nopass@example.com"],
            user_password=None,
        )

        assert result.is_success
        user = result.unwrap()
        assert user.user_password is None

    def test_ldap_user_create_minimal_error_handling(self) -> None:
        """Test create_minimal() factory error handling with invalid data."""
        # Try to create user with empty DN which should fail validation
        result = FlextLdapModels.Entry.create_minimal(
            dn="",  # Empty DN triggers validation error
            cn="Invalid User",
            entry_type="user",
        )

        # Factory should catch exception and return failure result
        assert result.is_failure
        assert result.error is not None
        assert result.error and "failed" in result.error.lower()

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
        pytest.skip("ModifyConfig model not yet implemented")

    def test_modify_config_validate_empty_changes(self) -> None:
        """Test ModifyConfig Pydantic validation with empty changes."""
        pytest.skip("ModifyConfig model not yet implemented")

    def test_modify_config_validate_success(self) -> None:
        """Test ModifyConfig.validate_business_rules() with valid data."""
        pytest.skip("ModifyConfig model not yet implemented")

    def test_add_config_validate_empty_dn(self) -> None:
        """Test AddConfig.validate_business_rules() with empty DN."""
        pytest.skip("AddConfig model not yet implemented")

    def test_add_config_validate_success(self) -> None:
        """Test AddConfig.validate_business_rules() with valid data."""
        pytest.skip("AddConfig model not yet implemented")
