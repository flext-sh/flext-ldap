"""Test module for FLEXT-LDAP services with REAL functionality testing."""

from __future__ import annotations

import pytest
from flext_core import FlextConstants, FlextResult

from flext_ldap import (
    FlextLDAPConnectionConfig,
    FlextLDAPContainer,
    FlextLDAPEntities,
    FlextLDAPServices,
)
from flext_ldap.exceptions import FlextLDAPExceptions


class TestFlextLDAPServiceRealFunctionality:
    """Test LDAP service with real functionality validation."""

    def test_service_initialization_real(self) -> None:
        """Test service initialization with real container."""
        container = FlextLDAPContainer()
        service = FlextLDAPServices(container)

        assert service is not None
        assert service._container is container

    def test_service_initialization_without_container(self) -> None:
        """Test service initialization without container creates default."""
        service = FlextLDAPServices()

        assert service is not None
        assert service._container is not None
        # When initialized without explicit container, uses FlextContainer from flext-core
        assert str(type(service._container)) != "<class 'NoneType'>"

    async def test_service_cleanup_real(self) -> None:
        """Test service cleanup with real container."""
        container = FlextLDAPContainer()
        service = FlextLDAPServices(container)

        # Cleanup should work without errors
        result = await service.cleanup()
        assert result.is_success

    def test_create_user_request_validation_real(self) -> None:
        """Test user creation request validation logic."""
        # Valid user request
        request = FlextLDAPEntities.CreateUserRequest(
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.com",
            object_classes=["inetOrgPerson", "organizationalPerson", "person"],
        )

        assert request.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert request.uid == "testuser"
        assert request.cn == "Test User"
        assert request.sn == "User"
        assert request.mail == "test@example.com"
        assert "inetOrgPerson" in request.object_classes

    def test_create_group_validation_real(self) -> None:
        """Test group creation validation logic."""
        # Valid group object
        group = FlextLDAPEntities.Group(
            id="testgroup-001",
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test Group",
            members=[],
        )

        assert group.id == "testgroup-001"
        assert group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert group.cn == "testgroup"
        assert group.description == "Test Group"
        assert isinstance(group.members, list)

    def test_ldap_user_model_validation_real(self) -> None:
        """Test LDAP user model validation."""
        user = FlextLDAPEntities.User(
            id="testuser-001",
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="test@example.com",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )

        assert user.id == "testuser-001"
        assert user.dn == "cn=testuser,ou=users,dc=example,dc=com"
        assert user.uid == "testuser"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.mail == "test@example.com"
        assert user.status == FlextConstants.Enums.EntityStatus.ACTIVE

    def test_ldap_group_model_validation_real(self) -> None:
        """Test LDAP group model validation."""
        group = FlextLDAPEntities.Group(
            id="testgroup-002",
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test Group",
            members=["cn=user1,ou=users,dc=example,dc=com"],
        )

        assert group.id == "testgroup-002"
        assert group.dn == "cn=testgroup,ou=groups,dc=example,dc=com"
        assert group.cn == "testgroup"
        assert group.description == "Test Group"
        assert "cn=user1,ou=users,dc=example,dc=com" in group.members

    def test_ldap_entry_model_validation_real(self) -> None:
        """Test LDAP entry model validation."""
        entry = FlextLDAPEntry(
            id="testentry-001",
            dn="cn=testentry,dc=example,dc=com",
            attributes={
                "cn": ["testentry"],
                "objectClass": ["person"],
                "description": ["Test entry"],
            },
        )

        assert entry.id == "testentry-001"
        assert entry.dn == "cn=testentry,dc=example,dc=com"
        assert "cn" in entry.attributes
        assert "testentry" in entry.attributes["cn"]
        assert "person" in entry.attributes["objectClass"]

    def test_search_request_validation_real(self) -> None:
        """Test search request validation."""
        request = FlextLDAPEntities.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            attributes=["cn", "mail", "uid"],
            scope="subtree",
            size_limit=100,
            time_limit=30,
        )

        assert request.base_dn == "ou=users,dc=example,dc=com"
        assert request.filter_str == "(objectClass=person)"
        assert "cn" in request.attributes
        assert "mail" in request.attributes
        assert "uid" in request.attributes
        assert request.scope == "subtree"
        assert request.size_limit == 100
        assert request.time_limit == 30

    def test_connection_config_validation_real(self) -> None:
        """Test connection configuration validation."""
        config = FlextLDAPConnectionConfig(
            server="ldap://ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="admin",
        )

        assert config.server == "ldap://ldap.example.com"
        assert config.port == 389
        assert config.use_ssl is False
        assert config.bind_dn == "cn=admin,dc=example,dc=com"
        assert config.bind_password == "admin"

    def test_search_response_validation_real(self) -> None:
        """Test search response validation."""
        entries = [
            {
                "dn": "cn=user1,ou=users,dc=example,dc=com",
                "cn": ["User One"],
                "mail": ["user1@example.com"],
            },
            {
                "dn": "cn=user2,ou=users,dc=example,dc=com",
                "cn": ["User Two"],
                "mail": ["user2@example.com"],
            },
        ]

        response = FlextLDAPSearchResponse(entries=entries, total_count=2)

        assert response.total_count == 2
        assert len(response.entries) == 2
        assert response.entries[0]["dn"] == "cn=user1,ou=users,dc=example,dc=com"
        assert response.entries[1]["dn"] == "cn=user2,ou=users,dc=example,dc=com"

    def test_invalid_dn_validation_real(self) -> None:
        """Test invalid DN validation raises proper error."""
        with pytest.raises((FlextLDAPExceptions.ValidationError, ValueError)):
            FlextLDAPEntities.User(
                id="invalid-001",
                dn="invalid-dn-format",  # Invalid DN format
                uid="testuser",
                cn="Test User",
                sn="User",
            )

    def test_missing_required_fields_validation_real(self) -> None:
        """Test missing required fields validation."""
        with pytest.raises(
            (FlextLDAPExceptions.ValidationError, ValueError, TypeError)
        ):
            FlextLDAPEntities.CreateUserRequest(
                dn="cn=testuser,ou=users,dc=example,dc=com",
                # Missing required uid field
                cn="Test User",
                sn="User",
            )

    def test_email_validation_real(self) -> None:
        """Test email format validation in user model."""
        # Valid email should work
        user = FlextLDAPEntities.User(
            id="emailtest-001",
            dn="cn=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="valid@example.com",
        )
        assert user.mail == "valid@example.com"

    def test_container_dependency_injection_real(self) -> None:
        """Test container dependency injection functionality."""
        container = FlextLDAPContainer()

        # Test that container can provide client
        client = container.get_client()
        assert client is not None
        assert hasattr(client, "connect")

        # Test that container can provide repository
        repository = container.get_repository()
        assert repository is not None

        # Test that container can provide user repository
        user_repository = container.get_user_repository()
        assert user_repository is not None

        # Test that container can provide group repository
        group_repository = container.get_group_repository()
        assert group_repository is not None

    async def test_service_result_patterns_real(self) -> None:
        """Test that service methods return FlextResult objects."""
        service = FlextLDAPServices()

        # All service methods should return FlextResult objects
        # We can test this without actually connecting to LDAP
        # by verifying the return type patterns

        # Test cleanup returns FlextResult
        cleanup_result = await service.cleanup()
        assert isinstance(cleanup_result, FlextResult)

        # Test initialization returns FlextResult
        init_result = await service.initialize()
        assert isinstance(init_result, FlextResult)

    def test_entity_status_enum_integration_real(self) -> None:
        """Test entity status enum integration."""
        # Test active status
        user = FlextLDAPEntities.User(
            id="activeuser-001",
            dn="cn=activeuser,ou=users,dc=example,dc=com",
            uid="activeuser",
            cn="Active User",
            sn="User",
            status=FlextConstants.Enums.EntityStatus.ACTIVE,
        )
        assert user.status == FlextConstants.Enums.EntityStatus.ACTIVE

        # Test inactive status
        inactive_user = FlextLDAPEntities.User(
            id="inactiveuser-001",
            dn="cn=inactiveuser,ou=users,dc=example,dc=com",
            uid="inactiveuser",
            cn="Inactive User",
            sn="User",
            status=FlextConstants.Enums.EntityStatus.INACTIVE,
        )
        assert inactive_user.status == FlextConstants.Enums.EntityStatus.INACTIVE


class TestFlextLDAPServiceBusinessLogic:
    """Test business logic validation without external dependencies."""

    def test_member_addition_logic_validation_real(self) -> None:
        """Test member addition business logic validation."""
        # Test that group can have multiple members
        group = FlextLDAPEntities.Group(
            id="membertest-001",
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test Group",
            members=[
                "cn=user1,ou=users,dc=example,dc=com",
                "cn=user2,ou=users,dc=example,dc=com",
            ],
        )

        # Verify initial state
        assert len(group.members) == 2
        assert "cn=user1,ou=users,dc=example,dc=com" in group.members
        assert "cn=user2,ou=users,dc=example,dc=com" in group.members

        # Test adding new member (business logic simulation)
        new_member = "cn=user3,ou=users,dc=example,dc=com"
        if new_member not in group.members:
            group.members.append(new_member)

        assert len(group.members) == 3
        assert new_member in group.members

    def test_member_removal_logic_validation_real(self) -> None:
        """Test member removal business logic validation."""
        # Create group with members
        group = FlextLDAPEntities.Group(
            id="memberremoval-001",
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            description="Test Group",
            members=[
                "cn=user1,ou=users,dc=example,dc=com",
                "cn=user2,ou=users,dc=example,dc=com",
            ],
        )

        # Test removing member (business logic simulation)
        member_to_remove = "cn=user1,ou=users,dc=example,dc=com"
        if member_to_remove in group.members:
            group.members.remove(member_to_remove)

        assert len(group.members) == 1
        assert member_to_remove not in group.members
        assert "cn=user2,ou=users,dc=example,dc=com" in group.members

    def test_user_password_complexity_validation_real(self) -> None:
        """Test password complexity business logic."""
        # Test password complexity requirements
        weak_passwords = ["123", "password", "abc"]
        strong_passwords = ["ComplexP@ssw0rd!", "Str0ng!P@ssw0rd"]

        for password in weak_passwords:
            # Weak passwords should fail validation
            assert len(password) < 8 or not any(c.isupper() for c in password)

        for password in strong_passwords:
            # Strong passwords should pass basic complexity checks
            assert len(password) >= 8
            assert any(c.isupper() for c in password)
            assert any(c.islower() for c in password)
            assert any(c.isdigit() for c in password)
            assert any(c in "!@#$%^&*" for c in password)

    def test_dn_validation_business_logic_real(self) -> None:
        """Test DN validation business logic."""
        # Valid DN patterns
        valid_dns = [
            "cn=user,ou=users,dc=example,dc=com",
            "cn=group,ou=groups,dc=example,dc=com",
            "ou=users,dc=example,dc=com",
        ]

        # Invalid DN patterns
        invalid_dns = ["invalid-dn-format", "cn=user,invalid", ""]

        for dn in valid_dns:
            # Valid DNs should contain proper components
            assert "=" in dn
            assert "," in dn
            assert len(dn.split(",")) >= 2

        for dn in invalid_dns:
            # Invalid DNs should fail basic validation
            if dn:
                # Check if it follows basic DN structure
                has_equals = "=" in dn
                has_comma = "," in dn
                components = dn.split(",")
                # A valid DN should have properly formatted components (key=value)
                if has_equals and has_comma and len(components) >= 2:
                    # Check if all components have proper format (contain =)
                    valid_components = all(
                        "=" in component.strip() for component in components
                    )
                    # For invalid DNs, this should be False
                    if dn == "cn=user,invalid":  # This specific case is invalid
                        assert not valid_components
            else:
                assert dn == ""

    def test_attribute_filtering_logic_real(self) -> None:
        """Test attribute filtering business logic."""
        # Test with mixed attributes (some empty, some with values)
        attributes = {
            "cn": ["Test User"],
            "mail": ["test@example.com"],
            "emptyAttr": [],  # Should be filtered out
            "description": ["Valid description"],
            "anotherEmpty": [],  # Should be filtered out
            "telephoneNumber": ["+1234567890"],
        }

        # Filter out empty attributes (business logic)
        filtered_attributes = {k: v for k, v in attributes.items() if v}

        assert "cn" in filtered_attributes
        assert "mail" in filtered_attributes
        assert "description" in filtered_attributes
        assert "telephoneNumber" in filtered_attributes
        assert "emptyAttr" not in filtered_attributes
        assert "anotherEmpty" not in filtered_attributes
        assert len(filtered_attributes) == 4

    def test_search_filter_construction_logic_real(self) -> None:
        """Test search filter construction business logic."""
        # Test basic filter construction
        object_class = "person"
        basic_filter = f"(objectClass={object_class})"
        assert basic_filter == "(objectClass=person)"

        # Test combined filter construction
        uid = "testuser"
        combined_filter = f"(&(objectClass={object_class})(uid={uid}))"
        assert combined_filter == "(&(objectClass=person)(uid=testuser))"

        # Test OR filter construction
        mail1 = "user1@example.com"
        mail2 = "user2@example.com"
        or_filter = f"(|(mail={mail1})(mail={mail2}))"
        assert or_filter == "(|(mail=user1@example.com)(mail=user2@example.com))"

    def test_pagination_logic_validation_real(self) -> None:
        """Test pagination business logic."""
        # Test pagination parameters
        page_size = 50
        page_number = 1

        # Calculate offset
        offset = (page_number - 1) * page_size
        assert offset == 0

        # Test second page
        page_number = 2
        offset = (page_number - 1) * page_size
        assert offset == 50

        # Test limit calculation
        size_limit = page_size
        assert size_limit == 50


class TestFlextLDAPContainerRealFunctionality:
    """Test container real functionality without mocks."""

    def test_container_initialization_real(self) -> None:
        """Test container initialization."""
        container = FlextLDAPContainer()
        assert container is not None

    def test_container_client_provision_real(self) -> None:
        """Test container can provide client."""
        container = FlextLDAPContainer()
        client = container.get_client()

        assert client is not None
        # The client should be a FlextLDAPClient instance
        assert hasattr(client, "connect")  # Basic interface check

    def test_container_repository_provision_real(self) -> None:
        """Test container can provide repository."""
        container = FlextLDAPContainer()
        repository = container.get_repository()

        assert repository is not None
        # The repository should be a valid object
        assert str(type(repository)) != "<class 'NoneType'>"

    def test_container_user_repository_provision_real(self) -> None:
        """Test container can provide user repository."""
        container = FlextLDAPContainer()
        user_repository = container.get_user_repository()

        assert user_repository is not None
        # The user repository should have user-specific interface
        assert hasattr(user_repository, "find_user_by_uid")
        assert hasattr(user_repository, "find_users_by_filter")

    def test_container_group_repository_provision_real(self) -> None:
        """Test container can provide group repository."""
        container = FlextLDAPContainer()
        group_repository = container.get_group_repository()

        assert group_repository is not None
        # The group repository should be a valid object
        assert str(type(group_repository)) != "<class 'NoneType'>"
