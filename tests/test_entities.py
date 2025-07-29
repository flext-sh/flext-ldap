"""Enterprise-grade tests for FlextLdap domain entities.

Tests all domain entities without mockups or fake data.
"""

from uuid import uuid4

import pytest

from flext_ldap.entities import (
    FlextLdapConnection,
    FlextLdapEntityStatus,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapOperation,
    FlextLdapUser,
)


class TestFlextLdapEntry:
    """Test base LDAP entry entity."""

    def test_entry_creation(self):
        """Test entry creation with required fields."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            object_classes=["inetOrgPerson"],
        )

        assert entry.dn == "cn=test,dc=example,dc=com"
        assert "inetOrgPerson" in entry.object_classes
        assert entry.is_active()

    def test_entry_domain_validation(self):
        """Test domain rule validation."""
        with pytest.raises(ValueError):
            entry = FlextLdapEntry(
                id=str(uuid4()),
                dn="",  # Empty DN should fail
                object_classes=[],
            )
            entry.validate_domain_rules()

    def test_entry_object_class_management(self):
        """Test object class operations."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
        )

        # Test adding object class
        entry.add_object_class("organizationalPerson")
        assert "organizationalPerson" in entry.object_classes

        # Test duplicate prevention
        entry.add_object_class("person")  # Already exists
        assert entry.object_classes.count("person") == 1

        # Test removal
        entry.remove_object_class("person")
        assert "person" not in entry.object_classes

    def test_entry_attribute_management(self):
        """Test attribute operations."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
        )

        # Test adding attributes
        entry.add_attribute("mail", "test@example.com")
        assert entry.has_attribute("mail", "test@example.com")

        # Test multi-value attributes
        entry.add_attribute("mail", "test2@example.com")
        assert len(entry.get_attribute("mail")) == 2

        # Test attribute removal
        entry.remove_attribute("mail", "test@example.com")
        assert not entry.has_attribute("mail", "test@example.com")
        assert entry.has_attribute("mail", "test2@example.com")

    def test_entry_rdn_operations(self):
        """Test RDN and parent DN operations."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=john,ou=users,dc=example,dc=com",
            object_classes=["person"],
        )

        assert entry.get_rdn() == "cn=john"
        assert entry.get_parent_dn() == "ou=users,dc=example,dc=com"

    def test_entry_status_management(self):
        """Test entry status operations."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
        )

        assert entry.is_active()

        # Test deactivation (immutable pattern)
        deactivated = entry.deactivate()
        assert not deactivated.is_active()
        assert entry.is_active()  # Original unchanged

        # Test reactivation
        reactivated = deactivated.activate()
        assert reactivated.is_active()


class TestFlextLdapUser:
    """Test FlextLdapUser entity."""

    def test_user_creation(self):
        """Test user creation with all fields."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=john.doe,ou=users,dc=example,dc=com",
            uid="john.doe",
            cn="John Doe",
            sn="Doe",
            mail="john.doe@example.com",
            phone="+1-555-0123",
            ou="Engineering",
            department="Software",
            title="Developer",
        )

        assert user.uid == "john.doe"
        assert user.cn == "John Doe"
        assert user.has_mail()
        assert user.is_active()

    def test_user_domain_validation(self):
        """Test user business rules."""
        # Test invalid email
        with pytest.raises(ValueError):
            user = FlextLdapUser(
                id=str(uuid4()),
                dn="cn=test,dc=example,dc=com",
                mail="invalid-email",  # Should fail validation
            )
            user.validate_domain_rules()

    def test_user_attribute_management(self):
        """Test user-specific attribute operations."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )

        # Test custom attribute addition
        updated = user.add_attribute("customField", "customValue")
        assert updated.get_attribute("customField") == "customValue"
        assert user.get_attribute("customField") is None  # Immutable

        # Test attribute removal
        removed = updated.remove_attribute("customField")
        assert removed.get_attribute("customField") is None

    def test_user_account_locking(self):
        """Test user account locking/unlocking."""
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )

        assert user.is_active()

        # Test locking
        locked = user.lock_account()
        assert not locked.is_active()
        assert user.is_active()  # Original unchanged

        # Test unlocking
        unlocked = locked.unlock_account()
        assert unlocked.is_active()


class TestFlextLdapGroup:
    """Test FlextLdapGroup entity."""

    def test_group_creation(self):
        """Test group creation."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=developers,ou=groups,dc=example,dc=com",
            cn="Developers",
            ou="Engineering",
        )

        assert group.cn == "Developers"
        assert group.ou == "Engineering"
        assert len(group.members) == 0

    def test_group_domain_validation(self):
        """Test group business rules."""
        with pytest.raises(ValueError):
            group = FlextLdapGroup(
                id=str(uuid4()),
                dn="cn=test,dc=example,dc=com",
                cn="",  # Empty CN should fail
            )
            group.validate_domain_rules()

    def test_group_member_management(self):
        """Test group member operations."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            cn="Test Group",
        )

        # Test member addition
        updated = group.add_member("cn=user1,dc=example,dc=com")
        assert updated.has_member("cn=user1,dc=example,dc=com")
        assert not group.has_member("cn=user1,dc=example,dc=com")  # Immutable

        # Test duplicate prevention
        duplicate = updated.add_member("cn=user1,dc=example,dc=com")
        assert len(duplicate.members) == 1

        # Test member removal
        removed = updated.remove_member("cn=user1,dc=example,dc=com")
        assert not removed.has_member("cn=user1,dc=example,dc=com")

    def test_group_owner_management(self):
        """Test group owner operations."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            cn="Test Group",
        )

        # Test owner addition
        updated = group.add_owner("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert updated.is_owner("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        # Test owner removal
        removed = updated.remove_owner("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert not removed.is_owner("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")


class TestFlextLdapConnection:
    """Test FlextLdapConnection entity."""

    def test_connection_creation(self):
        """Test connection creation."""
        connection = FlextLdapConnection(
            id=str(uuid4()),
            server_url="ldap://test.example.com:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        )

        assert connection.server_url == "ldap://test.example.com:389"
        assert connection.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert not connection.is_connected  # Not connected initially
        assert not connection.is_bound

    def test_connection_lifecycle(self):
        """Test connection state management."""
        connection = FlextLdapConnection(
            id=str(uuid4()),
            server_url="ldap://test.example.com:389",
        )

        # Test connection
        connected = connection.connect()
        assert connected.is_connected
        assert not connection.is_connected  # Immutable

        # Test binding
        bound = connected.bind("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
        assert bound.is_bound
        assert bound.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert bound.can_search()

        # Test disconnection
        disconnected = bound.disconnect()
        assert not disconnected.is_connected
        assert not disconnected.is_bound

    def test_connection_domain_validation(self):
        """Test connection business rules."""
        with pytest.raises(ValueError):
            connection = FlextLdapConnection(
                id=str(uuid4()),
                server_url="",  # Empty URL should fail
            )
            connection.validate_domain_rules()


class TestFlextLdapOperation:
    """Test FlextLdapOperation entity."""

    def test_operation_creation(self):
        """Test operation creation."""
        operation = FlextLdapOperation(
            id=str(uuid4()),
            operation_type="search",
            target_dn="ou=users,dc=example,dc=com",
            connection_id=str(uuid4()),
            filter_expression="(objectClass=person)",
            attributes=["cn", "mail"],
        )

        assert operation.operation_type == "search"
        assert operation.target_dn == "ou=users,dc=example,dc=com"
        assert operation.status == FlextLdapEntityStatus.PENDING

    def test_operation_lifecycle(self):
        """Test operation execution lifecycle."""
        operation = FlextLdapOperation(
            id=str(uuid4()),
            operation_type="search",
            target_dn="ou=users,dc=example,dc=com",
            connection_id=str(uuid4()),
        )

        # Test operation start
        started = operation.start_operation()
        assert started.status == FlextLdapEntityStatus.ACTIVE
        assert started.started_at is not None
        assert operation.started_at is None  # Immutable

        # Test operation completion
        completed = started.complete_operation(
            success=True,
            result_count=5,
        )
        assert completed.success is True
        assert completed.result_count == 5
        assert completed.is_completed()
        assert completed.is_successful() is not False  # success=True

    def test_operation_domain_validation(self):
        """Test operation business rules."""
        with pytest.raises(ValueError):
            operation = FlextLdapOperation(
                id=str(uuid4()),
                operation_type="",  # Empty type should fail
                target_dn="dc=example,dc=com",
                connection_id=str(uuid4()),
            )
            operation.validate_domain_rules()


class TestEntityImmutability:
    """Test immutability patterns across all entities."""

    def test_user_immutability(self):
        """Test user entity immutability."""
        original_user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test",
            sn="User",
        )

        # Modifications should return new instances
        locked_user = original_user.lock_account()

        assert original_user.is_active()
        assert not locked_user.is_active()
        assert original_user is not locked_user

    def test_group_immutability(self):
        """Test group entity immutability."""
        original_group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            cn="Test",
        )

        # Member operations should return new instances
        with_member = original_group.add_member("cn=user1,dc=example,dc=com")

        assert len(original_group.members) == 0
        assert len(with_member.members) == 1
        assert original_group is not with_member
