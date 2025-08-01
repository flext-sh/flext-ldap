"""Enterprise-grade tests for FlextLdap domain entities.

Tests all domain entities without mockups or fake data.
"""

from uuid import uuid4

# Constants
EXPECTED_BULK_SIZE = 2

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

    def test_entry_creation(self) -> None:
        """Test entry creation with required fields."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            object_classes=["inetOrgPerson"],
        )

        if entry.dn != "cn=test,dc=example,dc=com":
            raise AssertionError(
                f"Expected {'cn=test,dc=example,dc=com'}, got {entry.dn}"
            )
        if "inetOrgPerson" not in entry.object_classes:
            raise AssertionError(
                f"Expected {'inetOrgPerson'} in {entry.object_classes}"
            )
        assert entry.is_active()

    def test_entry_domain_validation(self) -> None:
        """Test domain rule validation."""
        # Test domain validation with empty DN
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="",  # Empty DN should fail
            object_classes=[],
        )
        result = entry.validate_domain_rules()
        assert not result.is_success
        assert "distinguished name" in result.error.lower()

    def test_entry_object_class_management(self) -> None:
        """Test object class operations."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            object_classes=["person"],
        )

        # Test adding object class
        entry.add_object_class("organizationalPerson")
        if "organizationalPerson" not in entry.object_classes:
            raise AssertionError(
                f"Expected {'organizationalPerson'} in {entry.object_classes}"
            )

        # Test duplicate prevention
        entry.add_object_class("person")  # Already exists
        if entry.object_classes.count("person") != 1:
            raise AssertionError(
                f"Expected {1}, got {entry.object_classes.count('person')}"
            )

        # Test removal
        entry.remove_object_class("person")
        if "person" in entry.object_classes:
            raise AssertionError(
                f"Expected 'person' to be removed from {entry.object_classes}"
            )

    def test_entry_attribute_management(self) -> None:
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
        if len(entry.get_attribute("mail")) != EXPECTED_BULK_SIZE:
            raise AssertionError(
                f"Expected {2}, got {len(entry.get_attribute('mail'))}"
            )

        # Test attribute removal
        entry.remove_attribute("mail", "test@example.com")
        assert not entry.has_attribute("mail", "test@example.com")
        assert entry.has_attribute("mail", "test2@example.com")

    def test_entry_rdn_operations(self) -> None:
        """Test RDN and parent DN operations."""
        entry = FlextLdapEntry(
            id=str(uuid4()),
            dn="cn=john,ou=users,dc=example,dc=com",
            object_classes=["person"],
        )

        if entry.get_rdn() != "cn=john":
            raise AssertionError(f"Expected {'cn=john'}, got {entry.get_rdn()}")
        assert entry.get_parent_dn() == "ou=users,dc=example,dc=com"

    def test_entry_status_management(self) -> None:
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

    def test_user_creation(self) -> None:
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

        if user.uid != "john.doe":
            raise AssertionError(f"Expected {'john.doe'}, got {user.uid}")
        assert user.cn == "John Doe"
        assert user.has_mail()
        assert user.is_active()

    def test_user_domain_validation(self) -> None:
        """Test user business rules."""
        # Test invalid email
        user = FlextLdapUser(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            mail="invalid-email",  # Should fail validation
        )
        result = user.validate_domain_rules()
        assert not result.is_success
        assert "email" in result.error.lower()

    def test_user_attribute_management(self) -> None:
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
        if updated.get_attribute("customField") != "customValue":
            raise AssertionError(
                f"Expected {'customValue'}, got {updated.get_attribute('customField')}"
            )
        assert user.get_attribute("customField") is None  # Immutable

        # Test attribute removal
        removed = updated.remove_attribute("customField")
        assert removed.get_attribute("customField") is None

    def test_user_account_locking(self) -> None:
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

    def test_group_creation(self) -> None:
        """Test group creation."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=developers,ou=groups,dc=example,dc=com",
            cn="Developers",
            ou="Engineering",
        )

        if group.cn != "Developers":
            raise AssertionError(f"Expected {'Developers'}, got {group.cn}")
        assert group.ou == "Engineering"
        if len(group.members) != 0:
            raise AssertionError(f"Expected {0}, got {len(group.members)}")

    def test_group_domain_validation(self) -> None:
        """Test group business rules."""
        group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            cn="",  # Empty CN should fail
        )
        result = group.validate_domain_rules()
        assert not result.is_success
        assert "common name" in result.error.lower()

    def test_group_member_management(self) -> None:
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
        if len(duplicate.members) != 1:
            raise AssertionError(f"Expected {1}, got {len(duplicate.members)}")

        # Test member removal
        removed = updated.remove_member("cn=user1,dc=example,dc=com")
        assert not removed.has_member("cn=user1,dc=example,dc=com")

    def test_group_owner_management(self) -> None:
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

    def test_connection_creation(self) -> None:
        """Test connection creation."""
        connection = FlextLdapConnection(
            id=str(uuid4()),
            server_url="ldap://test.example.com:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        )

        if connection.server_url != "ldap://test.example.com:389":
            raise AssertionError(
                f"Expected {'ldap://test.example.com:389'}, got {connection.server_url}"
            )
        assert connection.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert not connection.is_connected  # Not connected initially
        assert not connection.is_bound

    def test_connection_lifecycle(self) -> None:
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
        if bound.bind_dn != "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com":
            raise AssertionError(
                f"Expected {'cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com'}, got {bound.bind_dn}"
            )
        assert bound.can_search()

        # Test disconnection
        disconnected = bound.disconnect()
        assert not disconnected.is_connected
        assert not disconnected.is_bound

    def test_connection_domain_validation(self) -> None:
        """Test connection business rules."""
        connection = FlextLdapConnection(
            id=str(uuid4()),
            server_url="",  # Empty URL should fail
        )
        result = connection.validate_domain_rules()
        assert not result.is_success
        assert "server" in result.error.lower()


class TestFlextLdapOperation:
    """Test FlextLdapOperation entity."""

    def test_operation_creation(self) -> None:
        """Test operation creation."""
        operation = FlextLdapOperation(
            id=str(uuid4()),
            operation_type="search",
            target_dn="ou=users,dc=example,dc=com",
            connection_id=str(uuid4()),
            filter_expression="(objectClass=person)",
            attributes=["cn", "mail"],
        )

        if operation.operation_type != "search":
            raise AssertionError(f"Expected {'search'}, got {operation.operation_type}")
        assert operation.target_dn == "ou=users,dc=example,dc=com"
        if operation.status != FlextLdapEntityStatus.PENDING:
            raise AssertionError(
                f"Expected {FlextLdapEntityStatus.PENDING}, got {operation.status}"
            )

    def test_operation_lifecycle(self) -> None:
        """Test operation execution lifecycle."""
        operation = FlextLdapOperation(
            id=str(uuid4()),
            operation_type="search",
            target_dn="ou=users,dc=example,dc=com",
            connection_id=str(uuid4()),
        )

        # Test operation start
        started = operation.start_operation()
        if started.status != FlextLdapEntityStatus.ACTIVE:
            raise AssertionError(
                f"Expected {FlextLdapEntityStatus.ACTIVE}, got {started.status}"
            )
        assert started.started_at is not None
        assert operation.started_at is None  # Immutable

        # Test operation completion
        completed = started.complete_operation(
            success=True,
            result_count=5,
        )
        if not (completed.success):
            raise AssertionError(f"Expected True, got {completed.success}")
        if completed.result_count != 5:
            raise AssertionError(f"Expected {5}, got {completed.result_count}")
        assert completed.is_completed()
        assert completed.is_successful() is not False  # success=True

    def test_operation_domain_validation(self) -> None:
        """Test operation business rules."""
        operation = FlextLdapOperation(
            id=str(uuid4()),
            operation_type="",  # Empty type should fail
            target_dn="dc=example,dc=com",
            connection_id=str(uuid4()),
        )
        result = operation.validate_domain_rules()
        assert not result.is_success
        assert "operation type" in result.error.lower()


class TestEntityImmutability:
    """Test immutability patterns across all entities."""

    def test_user_immutability(self) -> None:
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

    def test_group_immutability(self) -> None:
        """Test group entity immutability."""
        original_group = FlextLdapGroup(
            id=str(uuid4()),
            dn="cn=test,dc=example,dc=com",
            cn="Test",
        )

        # Member operations should return new instances
        with_member = original_group.add_member("cn=user1,dc=example,dc=com")

        if len(original_group.members) != 0:
            raise AssertionError(f"Expected {0}, got {len(original_group.members)}")
        assert len(with_member.members) == 1
        assert original_group is not with_member
