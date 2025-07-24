"""Tests for domain entities in FLEXT-LDAP."""

from uuid import uuid4

import pytest

from flext_ldap.domain.entities import (
    FlextLdapConnection,
    FlextLdapEntityStatus,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapOperation,
    FlextLdapUser,
)


class TestFlextLdapUser:
    """Test FlextLdapUser entity."""

    def test_user_creation(self) -> None:
        """Test creating a user entity."""
        user = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.org",
        )

        assert user.dn == "uid=test,ou=users,dc=example,dc=org"
        assert user.uid == "test"
        assert user.cn == "Test User"
        assert user.sn == "User"
        assert user.mail == "test@example.org"
        assert user.version == 1
        assert user.is_active() is True

    def test_user_lock_unlock(self) -> None:
        """Test user lock/unlock functionality."""
        user = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
        )

        # Lock user
        locked_user = user.lock_account()
        assert locked_user.is_active() is False
        assert locked_user.version == user.version + 1

        # Unlock user
        unlocked_user = locked_user.unlock_account()
        assert unlocked_user.is_active() is True
        assert unlocked_user.version == locked_user.version + 1

    def test_user_has_attribute(self) -> None:
        """Test user attribute checking."""
        user = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.org",
        )

        assert user.has_attribute("mail") is True
        assert user.has_attribute("phone") is False

    def test_user_validation_rules(self) -> None:
        """Test user domain validation rules."""
        # Valid user
        user = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            mail="test@example.org"
        )
        user.validate_domain_rules()  # Should not raise

        # Invalid DN
        with pytest.raises(
            ValueError, match="LDAP user must have a distinguished name"
        ):
            FlextLdapUser(dn="", uid="test").validate_domain_rules()

        # Invalid email
        with pytest.raises(ValueError, match="User email must be valid format"):
            FlextLdapUser(
                dn="uid=test,ou=users,dc=example,dc=org",
                uid="test",
                mail="invalid-email"
            ).validate_domain_rules()

    def test_user_attribute_management(self) -> None:
        """Test user custom attribute management."""
        user = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test"
        )

        # Add attribute
        user_with_attr = user.add_attribute("department", "Engineering")
        assert user_with_attr.get_attribute("department") == "Engineering"
        assert user_with_attr.version == user.version + 1

        # Remove attribute
        user_without_attr = user_with_attr.remove_attribute("department")
        assert user_without_attr.get_attribute("department") is None
        assert user_without_attr.version == user_with_attr.version + 1

    def test_user_has_mail(self) -> None:
        """Test user email checking."""
        user_with_mail = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            mail="test@example.org"
        )
        assert user_with_mail.has_mail() is True

        user_without_mail = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test"
        )
        assert user_without_mail.has_mail() is False

    def test_user_deactivate(self) -> None:
        """Test user deactivation."""
        user = FlextLdapUser(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test"
        )

        deactivated = user.deactivate()
        assert deactivated.status == FlextLdapEntityStatus.INACTIVE
        assert deactivated.is_active() is False
        assert deactivated.version == user.version + 1


class TestFlextLdapGroup:
    """Test FlextLdapGroup entity."""

    def test_group_creation(self) -> None:
        """Test creating a group entity."""
        group = FlextLdapGroup(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=org",
            cn="REDACTED_LDAP_BIND_PASSWORDs",
            members=["uid=user1,ou=users,dc=example,dc=org"],
        )

        assert group.dn == "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=org"
        assert group.cn == "REDACTED_LDAP_BIND_PASSWORDs"
        assert len(group.members) == 1
        assert "uid=user1,ou=users,dc=example,dc=org" in group.members

    def test_group_member_management(self) -> None:
        """Test adding and removing group members."""
        group = FlextLdapGroup(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=org",
            cn="REDACTED_LDAP_BIND_PASSWORDs",
            members=[],
        )

        # Add member
        user_dn = "uid=test,ou=users,dc=example,dc=org"
        group_with_member = group.add_member(user_dn)
        assert user_dn in group_with_member.members
        assert group_with_member.version == group.version + 1

        # Remove member
        group_without_member = group_with_member.remove_member(user_dn)
        assert user_dn not in group_without_member.members
        assert group_without_member.version == group_with_member.version + 1

    def test_group_has_member(self) -> None:
        """Test checking group membership."""
        user_dn = "uid=test,ou=users,dc=example,dc=org"
        group = FlextLdapGroup(
            dn="cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=org",
            cn="REDACTED_LDAP_BIND_PASSWORDs",
            members=[user_dn],
        )

        assert group.has_member(user_dn) is True
        assert group.has_member("uid=other,ou=users,dc=example,dc=org") is False

    def test_group_validation_rules(self) -> None:
        """Test group domain validation rules."""
        # Valid group
        group = FlextLdapGroup(
            dn="cn=test,ou=groups,dc=example,dc=org",
            cn="test"
        )
        group.validate_domain_rules()  # Should not raise

        # Invalid DN
        with pytest.raises(
            ValueError, match="LDAP group must have a distinguished name"
        ):
            FlextLdapGroup(dn="", cn="test").validate_domain_rules()

        # Invalid CN
        with pytest.raises(ValueError, match="LDAP group must have a common name"):
            FlextLdapGroup(
                dn="cn=test,ou=groups,dc=example,dc=org",
                cn=""
            ).validate_domain_rules()

    def test_group_owner_management(self) -> None:
        """Test group owner management."""
        group = FlextLdapGroup(
            dn="cn=test,ou=groups,dc=example,dc=org",
            cn="test"
        )

        owner_dn = "uid=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=org"

        # Add owner
        group_with_owner = group.add_owner(owner_dn)
        assert group_with_owner.is_owner(owner_dn) is True
        assert group_with_owner.version == group.version + 1

        # Remove owner
        group_without_owner = group_with_owner.remove_owner(owner_dn)
        assert group_without_owner.is_owner(owner_dn) is False
        assert group_without_owner.version == group_with_owner.version + 1

    def test_group_deactivate(self) -> None:
        """Test group deactivation."""
        group = FlextLdapGroup(
            dn="cn=test,ou=groups,dc=example,dc=org",
            cn="test"
        )

        deactivated = group.deactivate()
        assert deactivated.status == FlextLdapEntityStatus.INACTIVE
        assert deactivated.version == group.version + 1


class TestFlextLdapConnection:
    """Test FlextLdapConnection entity."""

    def test_connection_creation(self) -> None:
        """Test creating a connection entity."""
        connection = FlextLdapConnection(
            server_url="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",
        )

        assert connection.server_url == "ldap://localhost:389"
        assert connection.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org"
        assert connection.is_connected is False
        assert connection.is_bound is False

    def test_connection_lifecycle(self) -> None:
        """Test connection connect/disconnect cycle."""
        connection = FlextLdapConnection(
            server_url="ldap://localhost:389",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org",
        )

        # Connect
        connected_connection = connection.connect()
        assert connected_connection.is_connected is True

        # Bind
        bound_connection = connected_connection.bind("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=org")
        assert bound_connection.is_bound is True

        # Unbind
        unbound_connection = bound_connection.unbind()
        assert unbound_connection.is_bound is False

        # Disconnect
        disconnected_connection = unbound_connection.disconnect()
        assert disconnected_connection.is_connected is False


class TestFlextLdapOperation:
    """Test FlextLdapOperation entity."""

    def test_operation_creation(self) -> None:
        """Test creating an operation entity."""
        connection_id = str(uuid4())
        operation = FlextLdapOperation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id,
            filter_expression="(objectClass=inetOrgPerson)",
        )

        assert operation.operation_type == "search"
        assert operation.target_dn == "ou=users,dc=example,dc=org"
        assert operation.connection_id == connection_id
        assert operation.filter_expression == "(objectClass=inetOrgPerson)"

    def test_operation_lifecycle(self) -> None:
        """Test operation start/complete cycle."""
        connection_id = str(uuid4())
        operation = FlextLdapOperation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id,
        )

        # Start operation - returns new immutable entity
        started_operation = operation.start_operation()
        assert started_operation.started_at is not None

        # Complete operation successfully - returns new immutable entity
        completed_operation = started_operation.complete_operation(
            success=True, result_count=5
        )
        assert completed_operation.completed_at is not None
        assert completed_operation.success is True
        assert completed_operation.result_count == 5

    def test_operation_failure(self) -> None:
        """Test operation failure handling."""
        connection_id = str(uuid4())
        operation = FlextLdapOperation(
            operation_type="add",
            target_dn="uid=test,ou=users,dc=example,dc=org",
            connection_id=connection_id,
        )

        # Start operation - returns new immutable entity
        started_operation = operation.start_operation()
        # Complete operation - returns new immutable entity
        completed_operation = started_operation.complete_operation(
            success=False,
            error_message="Entry already exists"
        )

        assert completed_operation.success is False
        assert completed_operation.error_message == "Entry already exists"

    def test_operation_validation_rules(self) -> None:
        """Test operation domain validation rules."""
        connection_id = str(uuid4())

        # Valid operation
        operation = FlextLdapOperation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id
        )
        operation.validate_domain_rules()  # Should not raise

        # Invalid operation type
        with pytest.raises(
            ValueError, match="LDAP operation must have an operation type"
        ):
            FlextLdapOperation(
                operation_type="",
                target_dn="ou=users,dc=example,dc=org",
                connection_id=connection_id
            ).validate_domain_rules()

        # Invalid target DN
        with pytest.raises(ValueError, match="LDAP operation must have a target DN"):
            FlextLdapOperation(
                operation_type="search",
                target_dn="",
                connection_id=connection_id
            ).validate_domain_rules()

        # Invalid connection ID
        with pytest.raises(
            ValueError, match="LDAP operation must have a connection ID"
        ):
            FlextLdapOperation(
                operation_type="search",
                target_dn="ou=users,dc=example,dc=org",
                connection_id=""
            ).validate_domain_rules()

    def test_operation_status_checking(self) -> None:
        """Test operation status checking methods."""
        connection_id = str(uuid4())
        operation = FlextLdapOperation(
            operation_type="search",
            target_dn="ou=users,dc=example,dc=org",
            connection_id=connection_id
        )

        # Initially not completed or successful
        assert operation.is_completed() is False
        assert operation.is_successful() is False

        # After starting, still not completed
        started = operation.start_operation()
        assert started.is_completed() is False
        assert started.is_successful() is False

        # After successful completion
        successful = started.complete_operation(success=True)
        assert successful.is_completed() is True
        assert successful.is_successful() is True

        # After failed completion
        failed = started.complete_operation(success=False, error_message="Failed")
        assert failed.is_completed() is True
        assert failed.is_successful() is False
