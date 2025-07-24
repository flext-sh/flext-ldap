"""Tests for LDAP domain value objects in FLEXT-LDAP."""

import pytest
from pydantic import ValidationError

from flext_ldap.domain.value_objects import FlextLdapCreateUserRequest


class TestFlextLdapCreateUserRequest:
    """Test FlextLdapCreateUserRequest value object."""

    def test_initialization_minimal(self) -> None:
        """Test initialization with minimal required fields."""
        request = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )

        assert request.dn == "uid=test,ou=users,dc=example,dc=org"
        assert request.uid == "test"
        assert request.cn == "Test User"
        assert request.sn == "User"
        assert request.mail is None
        assert request.phone is None
        assert request.ou is None
        assert request.department is None
        assert request.title is None
        assert request.object_classes is None

    def test_initialization_complete(self) -> None:
        """Test initialization with all fields."""
        request = FlextLdapCreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=org",
            uid="testuser",
            cn="Test User Full",
            sn="User",
            mail="test@example.org",
            phone="+1234567890",
            ou="Engineering",
            department="IT",
            title="Software Engineer",
            object_classes=["inetOrgPerson", "organizationalPerson"]
        )

        assert request.dn == "uid=testuser,ou=users,dc=example,dc=org"
        assert request.uid == "testuser"
        assert request.cn == "Test User Full"
        assert request.sn == "User"
        assert request.mail == "test@example.org"
        assert request.phone == "+1234567890"
        assert request.ou == "Engineering"
        assert request.department == "IT"
        assert request.title == "Software Engineer"
        assert request.object_classes == ["inetOrgPerson", "organizationalPerson"]

    def test_value_object_immutability(self) -> None:
        """Test that value object is immutable."""
        request = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )

        # Value objects should be immutable - attempting to modify should raise
        # ValidationError
        with pytest.raises(ValidationError):
            request.uid = "modified"  # type: ignore[misc]

    def test_equality(self) -> None:
        """Test value object equality."""
        request1 = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.org"
        )

        request2 = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.org"
        )

        request3 = FlextLdapCreateUserRequest(
            dn="uid=different,ou=users,dc=example,dc=org",
            uid="different",
            cn="Different User",
            sn="User"
        )

        assert request1 == request2
        assert request1 != request3

    def test_hash_consistency(self) -> None:
        """Test that equal value objects have same hash."""
        request1 = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )

        request2 = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )

        assert hash(request1) == hash(request2)

    def test_representation(self) -> None:
        """Test string representation of value object."""
        request = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )

        repr_str = repr(request)
        assert "FlextLdapCreateUserRequest" in repr_str
        assert "uid='test'" in repr_str
        assert "dn='uid=test,ou=users,dc=example,dc=org'" in repr_str

    def test_serialization(self) -> None:
        """Test value object serialization."""
        request = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="test@example.org"
        )

        # Convert to dict for serialization
        data = request.model_dump()

        assert data["dn"] == "uid=test,ou=users,dc=example,dc=org"
        assert data["uid"] == "test"
        assert data["cn"] == "Test User"
        assert data["sn"] == "User"
        assert data["mail"] == "test@example.org"

    def test_deserialization(self) -> None:
        """Test value object deserialization."""
        from typing import Any

        data: dict[str, Any] = {
            "dn": "uid=test,ou=users,dc=example,dc=org",
            "uid": "test",
            "cn": "Test User",
            "sn": "User",
            "mail": "test@example.org"
        }

        request = FlextLdapCreateUserRequest(**data)

        assert request.dn == "uid=test,ou=users,dc=example,dc=org"
        assert request.uid == "test"
        assert request.cn == "Test User"
        assert request.sn == "User"
        assert request.mail == "test@example.org"

    def test_validation(self) -> None:
        """Test value object validation."""
        # Valid request should not raise
        request = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )
        assert request.dn == "uid=test,ou=users,dc=example,dc=org"

        # Test with empty strings (should be converted to None or validated
        # appropriately)
        request_with_empty = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail="",  # Empty string
            phone=""  # Empty string
        )
        # Empty strings should be handled gracefully by Pydantic
        assert request_with_empty.mail == ""
        assert request_with_empty.phone == ""

    def test_optional_fields_none(self) -> None:
        """Test handling of None values for optional fields."""
        request = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User",
            mail=None,
            phone=None,
            ou=None,
            department=None,
            title=None,
            object_classes=None
        )

        assert request.mail is None
        assert request.phone is None
        assert request.ou is None
        assert request.department is None
        assert request.title is None
        assert request.object_classes is None

    def test_copy_with_modifications(self) -> None:
        """Test creating modified copies of value object."""
        original = FlextLdapCreateUserRequest(
            dn="uid=test,ou=users,dc=example,dc=org",
            uid="test",
            cn="Test User",
            sn="User"
        )

        # Create modified copy
        modified = original.model_copy(
            update={"mail": "test@example.org", "phone": "+1234567890"}
        )

        # Original should be unchanged
        assert original.mail is None
        assert original.phone is None

        # Modified should have new values
        assert modified.mail == "test@example.org"
        assert modified.phone == "+1234567890"

        # Other fields should be preserved
        assert modified.dn == original.dn
        assert modified.uid == original.uid
        assert modified.cn == original.cn
        assert modified.sn == original.sn
