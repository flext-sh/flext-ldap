"""Repository protocol compliance tests for FlextLdap.

Tests the Domain.Repository protocol implementation in flext-ldap,
verifying that repository base classes correctly implement the repository interface
with proper FlextResult error handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import LdapEntryRepository, RepositoryBase


class MockEntity:
    """Mock entity for testing repository operations."""

    def __init__(self, entity_id: str, name: str) -> None:
        """Initialize mock entity."""
        self.id = entity_id
        self.name = name

    def __eq__(self, other: object) -> bool:
        """Compare entities by ID."""
        if not isinstance(other, MockEntity):
            return NotImplemented
        return self.id == other.id and self.name == other.name

    def __repr__(self) -> str:
        """Return string representation."""
        return f"MockEntity(id={self.id!r}, name={self.name!r})"


class MockRepository(RepositoryBase[MockEntity]):
    """Concrete mock repository implementation for testing."""

    def __init__(self) -> None:
        """Initialize mock repository with in-memory storage."""
        self._storage: dict[str, MockEntity] = {}

    def get_by_id(self, entity_id: str) -> FlextResult[MockEntity | None]:
        """Retrieve entity by ID from mock storage."""
        if not entity_id:
            return FlextResult[MockEntity | None].fail("Entity ID required")

        entity = self._storage.get(entity_id)
        return FlextResult[MockEntity | None].ok(entity)

    def get_all(self) -> FlextResult[list[MockEntity]]:
        """Retrieve all entities from mock storage."""
        entities = list(self._storage.values())
        return FlextResult[list[MockEntity]].ok(entities)

    def add(self, entity: MockEntity) -> FlextResult[MockEntity]:
        """Add entity to mock storage."""
        if not entity.id:
            return FlextResult[MockEntity].fail("Entity ID required")

        if entity.id in self._storage:
            return FlextResult[MockEntity].fail(f"Entity {entity.id} already exists")

        self._storage[entity.id] = entity
        return FlextResult[MockEntity].ok(entity)

    def update(self, entity: MockEntity) -> FlextResult[MockEntity]:
        """Update entity in mock storage."""
        if not entity.id:
            return FlextResult[MockEntity].fail("Entity ID required")

        if entity.id not in self._storage:
            return FlextResult[MockEntity].fail(f"Entity {entity.id} not found")

        self._storage[entity.id] = entity
        return FlextResult[MockEntity].ok(entity)

    def delete(self, entity_id: str) -> FlextResult[bool]:
        """Delete entity from mock storage."""
        if not entity_id:
            return FlextResult[bool].fail("Entity ID required")

        if entity_id in self._storage:
            del self._storage[entity_id]
            return FlextResult[bool].ok(True)

        return FlextResult[bool].ok(False)

    def exists(self, entity_id: str) -> FlextResult[bool]:
        """Check if entity exists in mock storage."""
        if not entity_id:
            return FlextResult[bool].fail("Entity ID required")

        exists = entity_id in self._storage
        return FlextResult[bool].ok(exists)


class MockLdapEntry:
    """Mock LDAP entry for testing LDAP-specific repository."""

    def __init__(self, dn: str, cn: str, mail: str | None = None) -> None:
        """Initialize mock LDAP entry.

        Args:
            dn: Distinguished Name (unique identifier)
            cn: Common Name
            mail: Email address (optional)

        """
        self.dn = dn  # Distinguished Name as unique identifier
        self.cn = cn
        self.mail = mail

    def __eq__(self, other: object) -> bool:
        """Compare entries by DN."""
        if not isinstance(other, MockLdapEntry):
            return NotImplemented
        return self.dn == other.dn and self.cn == other.cn and self.mail == other.mail

    def __repr__(self) -> str:
        """Return string representation."""
        return f"MockLdapEntry(dn={self.dn!r}, cn={self.cn!r}, mail={self.mail!r})"


class MockLdapRepository(LdapEntryRepository[MockLdapEntry]):
    """Concrete mock LDAP repository implementation for testing."""

    def __init__(self) -> None:
        """Initialize mock LDAP repository with in-memory storage."""
        self._storage: dict[str, MockLdapEntry] = {}

    def get_by_id(self, entity_id: str) -> FlextResult[MockLdapEntry | None]:
        """Retrieve LDAP entry by DN."""
        if not entity_id:
            return FlextResult[MockLdapEntry | None].fail("DN required")

        entry = self._storage.get(entity_id)
        return FlextResult[MockLdapEntry | None].ok(entry)

    def get_all(self) -> FlextResult[list[MockLdapEntry]]:
        """Retrieve all LDAP entries."""
        entries = list(self._storage.values())
        return FlextResult[list[MockLdapEntry]].ok(entries)

    def add(self, entity: MockLdapEntry) -> FlextResult[MockLdapEntry]:
        """Add LDAP entry to mock storage."""
        if not entity.dn:
            return FlextResult[MockLdapEntry].fail("DN required")

        if entity.dn in self._storage:
            return FlextResult[MockLdapEntry].fail(f"Entry {entity.dn} already exists")

        self._storage[entity.dn] = entity
        return FlextResult[MockLdapEntry].ok(entity)

    def update(self, entity: MockLdapEntry) -> FlextResult[MockLdapEntry]:
        """Update LDAP entry in mock storage."""
        if not entity.dn:
            return FlextResult[MockLdapEntry].fail("DN required")

        if entity.dn not in self._storage:
            return FlextResult[MockLdapEntry].fail(f"Entry {entity.dn} not found")

        self._storage[entity.dn] = entity
        return FlextResult[MockLdapEntry].ok(entity)

    def delete(self, entity_id: str) -> FlextResult[bool]:
        """Delete LDAP entry from mock storage."""
        if not entity_id:
            return FlextResult[bool].fail("DN required")

        if entity_id in self._storage:
            del self._storage[entity_id]
            return FlextResult[bool].ok(True)

        return FlextResult[bool].ok(False)

    def exists(self, entity_id: str) -> FlextResult[bool]:
        """Check if LDAP entry exists by DN."""
        if not entity_id:
            return FlextResult[bool].fail("DN required")

        exists = entity_id in self._storage
        return FlextResult[bool].ok(exists)

    def search_by_attribute(
        self, attribute: str, value: str
    ) -> FlextResult[list[MockLdapEntry]]:
        """Search LDAP entries by attribute.

        Args:
            attribute: LDAP attribute name (cn, mail, etc.)
            value: Value to search for

        Returns:
            FlextResult[list[MockLdapEntry]]: Matching entries

        """
        if not attribute or not value:
            return FlextResult[list[MockLdapEntry]].fail("Attribute and value required")

        results: list[MockLdapEntry] = []

        if attribute.lower() == "cn":
            results = [entry for entry in self._storage.values() if entry.cn == value]
        elif attribute.lower() == "mail":
            results = [entry for entry in self._storage.values() if entry.mail == value]

        return FlextResult[list[MockLdapEntry]].ok(results)


@pytest.mark.unit
class TestRepositoryBaseProtocol:
    """Tests for RepositoryBase protocol compliance."""

    def test_repository_base_is_abstract(self) -> None:
        """Test that RepositoryBase is an abstract class."""
        assert hasattr(RepositoryBase, "__abstractmethods__")
        # Should not be able to instantiate directly
        with pytest.raises(TypeError):
            RepositoryBase()

    def test_repository_has_get_by_id_method(self) -> None:
        """Test that RepositoryBase defines get_by_id method."""
        assert hasattr(RepositoryBase, "get_by_id")
        assert RepositoryBase.get_by_id.__isabstractmethod__

    def test_repository_has_get_all_method(self) -> None:
        """Test that RepositoryBase defines get_all method."""
        assert hasattr(RepositoryBase, "get_all")
        assert RepositoryBase.get_all.__isabstractmethod__

    def test_repository_has_add_method(self) -> None:
        """Test that RepositoryBase defines add method."""
        assert hasattr(RepositoryBase, "add")
        assert RepositoryBase.add.__isabstractmethod__

    def test_repository_has_update_method(self) -> None:
        """Test that RepositoryBase defines update method."""
        assert hasattr(RepositoryBase, "update")
        assert RepositoryBase.update.__isabstractmethod__

    def test_repository_has_delete_method(self) -> None:
        """Test that RepositoryBase defines delete method."""
        assert hasattr(RepositoryBase, "delete")
        assert RepositoryBase.delete.__isabstractmethod__

    def test_repository_has_exists_method(self) -> None:
        """Test that RepositoryBase defines exists method."""
        assert hasattr(RepositoryBase, "exists")
        assert RepositoryBase.exists.__isabstractmethod__


@pytest.mark.unit
class TestRepositoryCRUDOperations:
    """Tests for repository CRUD operations with FlextResult."""

    def test_get_by_id_returns_flext_result(self) -> None:
        """Test that get_by_id returns FlextResult."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")
        repo.add(entity)

        result = repo.get_by_id("1")
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_get_by_id_success_returns_entity(self) -> None:
        """Test that get_by_id returns entity when found."""
        repo = MockRepository()
        entity = MockEntity("1", "Test Entity")
        repo.add(entity)

        result = repo.get_by_id("1")
        assert result.is_success
        assert result.unwrap() == entity

    def test_get_by_id_not_found_returns_none(self) -> None:
        """Test that get_by_id returns None when entity not found."""
        repo = MockRepository()

        result = repo.get_by_id("nonexistent")
        assert result.is_success
        assert result.unwrap() is None

    def test_get_by_id_empty_id_returns_failure(self) -> None:
        """Test that get_by_id returns failure for empty ID."""
        repo = MockRepository()

        result = repo.get_by_id("")
        assert result.is_failure
        assert "required" in result.error.lower()

    def test_get_all_returns_flext_result(self) -> None:
        """Test that get_all returns FlextResult."""
        repo = MockRepository()

        result = repo.get_all()
        assert isinstance(result, FlextResult)

    def test_get_all_returns_empty_list(self) -> None:
        """Test that get_all returns empty list when no entities."""
        repo = MockRepository()

        result = repo.get_all()
        assert result.is_success
        assert result.unwrap() == []

    def test_get_all_returns_all_entities(self) -> None:
        """Test that get_all returns all entities."""
        repo = MockRepository()
        entity1 = MockEntity("1", "Entity 1")
        entity2 = MockEntity("2", "Entity 2")
        repo.add(entity1)
        repo.add(entity2)

        result = repo.get_all()
        assert result.is_success
        entities = result.unwrap()
        assert len(entities) == 2
        assert entity1 in entities
        assert entity2 in entities

    def test_add_returns_flext_result(self) -> None:
        """Test that add returns FlextResult."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")

        result = repo.add(entity)
        assert isinstance(result, FlextResult)

    def test_add_success_returns_created_entity(self) -> None:
        """Test that add returns created entity on success."""
        repo = MockRepository()
        entity = MockEntity("1", "Test Entity")

        result = repo.add(entity)
        assert result.is_success
        assert result.unwrap() == entity

    def test_add_duplicate_returns_failure(self) -> None:
        """Test that add returns failure for duplicate entity."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")
        repo.add(entity)

        result = repo.add(MockEntity("1", "Another"))
        assert result.is_failure
        assert "already exists" in result.error

    def test_update_returns_flext_result(self) -> None:
        """Test that update returns FlextResult."""
        repo = MockRepository()
        entity = MockEntity("1", "Original")
        repo.add(entity)

        updated = MockEntity("1", "Updated")
        result = repo.update(updated)
        assert isinstance(result, FlextResult)

    def test_update_success_returns_updated_entity(self) -> None:
        """Test that update returns updated entity on success."""
        repo = MockRepository()
        entity = MockEntity("1", "Original")
        repo.add(entity)

        updated = MockEntity("1", "Updated")
        result = repo.update(updated)
        assert result.is_success
        assert result.unwrap() == updated

    def test_update_not_found_returns_failure(self) -> None:
        """Test that update returns failure for nonexistent entity."""
        repo = MockRepository()

        entity = MockEntity("1", "Nonexistent")
        result = repo.update(entity)
        assert result.is_failure
        assert "not found" in result.error

    def test_delete_returns_flext_result(self) -> None:
        """Test that delete returns FlextResult."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")
        repo.add(entity)

        result = repo.delete("1")
        assert isinstance(result, FlextResult)

    def test_delete_success_returns_true(self) -> None:
        """Test that delete returns True when entity deleted."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")
        repo.add(entity)

        result = repo.delete("1")
        assert result.is_success
        assert result.unwrap() is True

    def test_delete_not_found_returns_false(self) -> None:
        """Test that delete returns False when entity not found."""
        repo = MockRepository()

        result = repo.delete("nonexistent")
        assert result.is_success
        assert result.unwrap() is False

    def test_exists_returns_flext_result(self) -> None:
        """Test that exists returns FlextResult."""
        repo = MockRepository()

        result = repo.exists("1")
        assert isinstance(result, FlextResult)

    def test_exists_true_when_entity_exists(self) -> None:
        """Test that exists returns True when entity exists."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")
        repo.add(entity)

        result = repo.exists("1")
        assert result.is_success
        assert result.unwrap() is True

    def test_exists_false_when_entity_not_exists(self) -> None:
        """Test that exists returns False when entity does not exist."""
        repo = MockRepository()

        result = repo.exists("nonexistent")
        assert result.is_success
        assert result.unwrap() is False


@pytest.mark.unit
class TestLdapEntryRepositoryProtocol:
    """Tests for LdapEntryRepository protocol compliance."""

    def test_ldap_repository_inherits_from_base(self) -> None:
        """Test that LdapEntryRepository inherits from RepositoryBase."""
        repo = MockLdapRepository()
        assert isinstance(repo, RepositoryBase)

    def test_ldap_repository_has_search_by_attribute(self) -> None:
        """Test that LdapEntryRepository has search_by_attribute method."""
        assert hasattr(LdapEntryRepository, "search_by_attribute")
        assert LdapEntryRepository.search_by_attribute.__isabstractmethod__

    def test_ldap_search_by_attribute_returns_flext_result(self) -> None:
        """Test that search_by_attribute returns FlextResult."""
        repo = MockLdapRepository()
        entry = MockLdapEntry(
            "cn=user,ou=people,dc=example,dc=com", "user", "user@example.com"
        )
        repo.add(entry)

        result = repo.search_by_attribute("mail", "user@example.com")
        assert isinstance(result, FlextResult)

    def test_ldap_search_by_cn_returns_matching_entries(self) -> None:
        """Test that search_by_attribute finds entries by cn."""
        repo = MockLdapRepository()
        entry1 = MockLdapEntry("cn=john,ou=people,dc=example,dc=com", "john")
        entry2 = MockLdapEntry("cn=jane,ou=people,dc=example,dc=com", "jane")
        repo.add(entry1)
        repo.add(entry2)

        result = repo.search_by_attribute("cn", "john")
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0] == entry1

    def test_ldap_search_by_mail_returns_matching_entries(self) -> None:
        """Test that search_by_attribute finds entries by mail."""
        repo = MockLdapRepository()
        entry1 = MockLdapEntry(
            "cn=user1,ou=people,dc=example,dc=com",
            "user1",
            "user1@example.com",
        )
        entry2 = MockLdapEntry(
            "cn=user2,ou=people,dc=example,dc=com",
            "user2",
            "user2@example.com",
        )
        repo.add(entry1)
        repo.add(entry2)

        result = repo.search_by_attribute("mail", "user1@example.com")
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 1
        assert entries[0] == entry1

    def test_ldap_search_empty_attribute_returns_failure(self) -> None:
        """Test that search_by_attribute returns failure for empty attribute."""
        repo = MockLdapRepository()

        result = repo.search_by_attribute("", "value")
        assert result.is_failure

    def test_ldap_search_empty_value_returns_failure(self) -> None:
        """Test that search_by_attribute returns failure for empty value."""
        repo = MockLdapRepository()

        result = repo.search_by_attribute("cn", "")
        assert result.is_failure

    def test_ldap_repository_crud_operations(self) -> None:
        """Test that LDAP repository supports all CRUD operations."""
        repo = MockLdapRepository()
        dn = "cn=user,ou=people,dc=example,dc=com"
        entry = MockLdapEntry(dn, "user", "user@example.com")

        # Create
        add_result = repo.add(entry)
        assert add_result.is_success

        # Read
        get_result = repo.get_by_id(dn)
        assert get_result.is_success
        assert get_result.unwrap() == entry

        # Update
        updated_entry = MockLdapEntry(dn, "user", "newemail@example.com")
        update_result = repo.update(updated_entry)
        assert update_result.is_success

        # Check update
        get_result = repo.get_by_id(dn)
        assert get_result.unwrap().mail == "newemail@example.com"

        # Delete
        delete_result = repo.delete(dn)
        assert delete_result.is_success
        assert delete_result.unwrap() is True

        # Verify deletion
        exists_result = repo.exists(dn)
        assert exists_result.is_success
        assert exists_result.unwrap() is False


@pytest.mark.unit
class TestRepositoryErrorHandling:
    """Tests for repository error handling with FlextResult."""

    def test_all_operations_return_flext_result(self) -> None:
        """Test that all repository operations return FlextResult."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")

        assert isinstance(repo.get_by_id("1"), FlextResult)
        assert isinstance(repo.get_all(), FlextResult)
        assert isinstance(repo.add(entity), FlextResult)
        assert isinstance(repo.update(entity), FlextResult)
        assert isinstance(repo.delete("1"), FlextResult)
        assert isinstance(repo.exists("1"), FlextResult)

    def test_failure_results_contain_error_message(self) -> None:
        """Test that failure results contain descriptive error messages."""
        repo = MockRepository()

        # Invalid operation
        result = repo.get_by_id("")
        assert result.is_failure
        assert len(result.error) > 0
        assert isinstance(result.error, str)

    def test_success_results_contain_data(self) -> None:
        """Test that success results contain expected data."""
        repo = MockRepository()
        entity = MockEntity("1", "Test")
        repo.add(entity)

        result = repo.get_by_id("1")
        assert result.is_success
        assert result.unwrap() is not None

    def test_error_propagation_in_operations(self) -> None:
        """Test that errors propagate through operations."""
        repo = MockRepository()

        # Try to update non-existent entity
        entity = MockEntity("1", "Test")
        result = repo.update(entity)
        assert result.is_failure

        # Error message should be informative
        assert "not found" in result.error.lower()


@pytest.mark.unit
class TestRepositoryTypeConsistency:
    """Tests for repository type consistency."""

    def test_repository_preserves_entity_type(self) -> None:
        """Test that repository preserves entity type through operations."""
        repo = MockRepository()
        original = MockEntity("1", "Test")

        # Add and retrieve
        repo.add(original)
        result = repo.get_by_id("1")
        retrieved = result.unwrap()

        # Should be same entity
        assert isinstance(retrieved, MockEntity)
        assert retrieved.id == original.id
        assert retrieved.name == original.name

    def test_ldap_repository_preserves_ldap_entry_type(self) -> None:
        """Test that LDAP repository preserves entry type."""
        repo = MockLdapRepository()
        original = MockLdapEntry(
            "cn=user,ou=people,dc=example,dc=com", "user", "user@example.com"
        )

        repo.add(original)
        result = repo.get_by_id("cn=user,ou=people,dc=example,dc=com")
        retrieved = result.unwrap()

        assert isinstance(retrieved, MockLdapEntry)
        assert retrieved.dn == original.dn
        assert retrieved.cn == original.cn


@pytest.mark.unit
class TestRepositoryCompleteWorkflow:
    """Tests for complete repository workflows."""

    def test_complete_crud_workflow(self) -> None:
        """Test complete CRUD workflow on repository."""
        repo = MockRepository()

        # Create
        entity1 = MockEntity("1", "Entity 1")
        entity2 = MockEntity("2", "Entity 2")

        add1 = repo.add(entity1)
        add2 = repo.add(entity2)

        assert add1.is_success
        assert add2.is_success

        # Read all
        get_all = repo.get_all()
        assert get_all.is_success
        assert len(get_all.unwrap()) == 2

        # Update
        updated = MockEntity("1", "Updated Entity 1")
        update = repo.update(updated)
        assert update.is_success

        # Verify update
        get_one = repo.get_by_id("1")
        assert get_one.unwrap().name == "Updated Entity 1"

        # Check exists
        exists = repo.exists("1")
        assert exists.is_success
        assert exists.unwrap() is True

        # Delete
        delete = repo.delete("1")
        assert delete.is_success
        assert delete.unwrap() is True

        # Verify deletion
        not_exists = repo.exists("1")
        assert not_exists.unwrap() is False

    def test_complete_ldap_workflow(self) -> None:
        """Test complete LDAP repository workflow."""
        repo = MockLdapRepository()

        dn1 = "cn=john,ou=people,dc=example,dc=com"
        dn2 = "cn=jane,ou=people,dc=example,dc=com"

        entry1 = MockLdapEntry(dn1, "john", "john@example.com")
        entry2 = MockLdapEntry(dn2, "jane", "jane@example.com")

        # Create
        repo.add(entry1)
        repo.add(entry2)

        # Search by attribute
        search = repo.search_by_attribute("cn", "john")
        assert search.is_success
        assert len(search.unwrap()) == 1

        # Update
        updated = MockLdapEntry(dn1, "john", "newemail@example.com")
        repo.update(updated)

        # Verify update
        get = repo.get_by_id(dn1)
        assert get.unwrap().mail == "newemail@example.com"

        # Delete
        delete = repo.delete(dn1)
        assert delete.is_success

        # Verify deletion
        get_all = repo.get_all()
        assert len(get_all.unwrap()) == 1
