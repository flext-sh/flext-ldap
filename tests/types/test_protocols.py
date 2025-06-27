"""Comprehensive tests for protocol definitions and contracts.

This module tests all protocol interfaces to ensure they define proper
contracts and can be implemented correctly by concrete classes.

Test categories:
- Protocol contract validation
- Runtime type checking behavior
- Implementation compliance testing
- Interface segregation verification
- Protocol composition and interaction
"""

from __future__ import annotations

import uuid
from datetime import UTC
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ldap_core_shared.types.protocols import (
    Bindable,
    Cacheable,
    Comparable,
    Connectable,
    Identifiable,
    Modifiable,
    Observable,
    Observer,
    Searchable,
    Serializable,
    Trackable,
    Validatable,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ldap_core_shared.types.aliases import (
        DN,
        Attributes,
        FilterExpression,
        OperationResult,
        SearchScope,
    )

# ===== PROTOCOL IMPLEMENTATION FIXTURES =====


class TestConnectable:
    """Test implementation of Connectable protocol."""

    def __init__(self, should_succeed: bool = True) -> None:
        """Initialize with success/failure behavior."""
        self._should_succeed = should_succeed
        self._connected = False

    async def connect(self, server_uri: str, **kwargs: Any) -> bool:
        """Test connect implementation."""
        if self._should_succeed:
            self._connected = True
            return True
        return False

    async def disconnect(self) -> bool:
        """Test disconnect implementation."""
        if self._connected:
            self._connected = False
            return True
        return False

    def is_connected(self) -> bool:
        """Test connection status check."""
        return self._connected


class TestBindable:
    """Test implementation of Bindable protocol."""

    def __init__(self, should_succeed: bool = True) -> None:
        """Initialize with success/failure behavior."""
        self._should_succeed = should_succeed
        self._bound = False

    async def bind(self, user_dn: DN, password: str) -> bool:
        """Test simple bind implementation."""
        if self._should_succeed and password != "wrong":
            self._bound = True
            return True
        return False

    async def bind_sasl(self, mechanism: str, **kwargs: Any) -> bool:
        """Test SASL bind implementation."""
        if self._should_succeed and mechanism in {"GSSAPI", "DIGEST-MD5"}:
            self._bound = True
            return True
        return False

    async def unbind(self) -> bool:
        """Test unbind implementation."""
        if self._bound:
            self._bound = False
            return True
        return False


class TestSearchable:
    """Test implementation of Searchable protocol."""

    def __init__(self, results: list[dict[str, Any]] | None = None) -> None:
        """Initialize with predefined results."""
        self._results = results or [
            {
                "dn": "cn=user1,dc=example,dc=com",
                "cn": ["user1"],
                "mail": ["user1@example.com"],
            },
            {
                "dn": "cn=user2,dc=example,dc=com",
                "cn": ["user2"],
                "mail": ["user2@example.com"],
            },
        ]

    async def search(
        self,
        base_dn: DN,
        search_filter: FilterExpression,
        scope: SearchScope = "subtree",
        attributes: list[str] | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Test search implementation."""
        for result in self._results:
            if attributes:
                # Filter attributes if specified
                filtered_result = {"dn": result["dn"]}
                for attr in attributes:
                    if attr in result:
                        filtered_result[attr] = result[attr]
                yield filtered_result
            else:
                yield result

    async def search_one(
        self,
        base_dn: DN,
        search_filter: FilterExpression,
        attributes: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Test search one implementation."""
        async for result in self.search(
            base_dn,
            search_filter,
            attributes=attributes,
            **kwargs,
        ):
            return result
        return None


class TestModifiable:
    """Test implementation of Modifiable protocol."""

    def __init__(self, should_succeed: bool = True) -> None:
        """Initialize with success/failure behavior."""
        self._should_succeed = should_succeed
        self._entries: dict[DN, Attributes] = {}

    async def add(self, dn: DN, attributes: Attributes) -> OperationResult:
        """Test add implementation."""
        if self._should_succeed and dn not in self._entries:
            self._entries[dn] = attributes
            return {"result_code": 0, "message": "Success", "dn": dn}
        return {"result_code": 68, "message": "Entry already exists", "dn": dn}

    async def modify(self, dn: DN, changes: dict[str, Any]) -> OperationResult:
        """Test modify implementation."""
        if self._should_succeed and dn in self._entries:
            self._entries[dn].update(changes)
            return {"result_code": 0, "message": "Success", "dn": dn}
        return {"result_code": 32, "message": "No such object", "dn": dn}

    async def delete(self, dn: DN) -> OperationResult:
        """Test delete implementation."""
        if self._should_succeed and dn in self._entries:
            del self._entries[dn]
            return {"result_code": 0, "message": "Success", "dn": dn}
        return {"result_code": 32, "message": "No such object", "dn": dn}


class TestValidatable:
    """Test implementation of Validatable protocol."""

    def __init__(self, is_valid: bool = True, errors: list[str] | None = None) -> None:
        """Initialize with validation state."""
        self._is_valid = is_valid
        self._errors = errors or []

    def validate(self) -> bool:
        """Test validation implementation."""
        return self._is_valid

    def get_validation_errors(self) -> list[str]:
        """Test validation errors implementation."""
        return self._errors.copy()


class TestSerializable:
    """Test implementation of Serializable protocol."""

    def __init__(self, data: dict[str, Any]) -> None:
        """Initialize with data."""
        self._data = data

    def to_dict(self) -> dict[str, Any]:
        """Test to_dict implementation."""
        return self._data.copy()

    def to_json(self) -> str:
        """Test to_json implementation."""
        import json

        return json.dumps(self._data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestSerializable:
        """Test from_dict implementation."""
        return cls(data)

    @classmethod
    def from_json(cls, json_str: str) -> TestSerializable:
        """Test from_json implementation."""
        import json

        data = json.loads(json_str)
        return cls(data)


class TestCacheable:
    """Test implementation of Cacheable protocol."""

    def __init__(self, key: str, ttl: int = 300, should_cache: bool = True) -> None:
        """Initialize with cache settings."""
        self._key = key
        self._ttl = ttl
        self._should_cache = should_cache

    def get_cache_key(self) -> str:
        """Test cache key generation."""
        return self._key

    def get_cache_ttl(self) -> int:
        """Test cache TTL implementation."""
        return self._ttl

    def should_cache(self) -> bool:
        """Test cache decision implementation."""
        return self._should_cache


class TestObserver:
    """Test implementation of Observer protocol."""

    def __init__(self) -> None:
        """Initialize observer."""
        self.received_events: list[tuple[str, dict[str, Any]]] = []

    async def on_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Test event handling implementation."""
        self.received_events.append((event_type, data.copy()))


class TestObservable:
    """Test implementation of Observable protocol."""

    def __init__(self) -> None:
        """Initialize observable."""
        self._observers: list[TestObserver] = []

    async def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Test event emission implementation."""
        for observer in self._observers:
            await observer.on_event(event_type, data)

    def add_observer(self, observer: TestObserver) -> None:
        """Test observer addition."""
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer: TestObserver) -> None:
        """Test observer removal."""
        if observer in self._observers:
            self._observers.remove(observer)


class TestIdentifiable:
    """Test implementation of Identifiable protocol."""

    def __init__(self, entity_id: uuid.UUID | None = None) -> None:
        """Initialize with ID."""
        self._id = entity_id or uuid.uuid4()

    def get_id(self) -> uuid.UUID:
        """Test ID retrieval."""
        return self._id

    def get_id_str(self) -> str:
        """Test ID string retrieval."""
        return str(self._id)


class TestTrackable:
    """Test implementation of Trackable protocol."""

    def __init__(self) -> None:
        """Initialize with timestamps."""
        from datetime import datetime

        now = datetime.now(UTC)
        self._created_at = now.isoformat()
        self._updated_at = now.isoformat()
        self._version = 1

    def get_created_at(self) -> str:
        """Test creation timestamp retrieval."""
        return self._created_at

    def get_updated_at(self) -> str:
        """Test update timestamp retrieval."""
        return self._updated_at

    def get_version(self) -> int:
        """Test version retrieval."""
        return self._version


class TestComparable:
    """Test implementation of Comparable protocol."""

    def __init__(self, value: float) -> None:
        """Initialize with comparable value."""
        self._value = value

    def __lt__(self, other: TestComparable) -> bool:
        """Test less than comparison."""
        return self._value < other._value

    def __le__(self, other: TestComparable) -> bool:
        """Test less than or equal comparison."""
        return self._value <= other._value

    def __gt__(self, other: TestComparable) -> bool:
        """Test greater than comparison."""
        return self._value > other._value

    def __ge__(self, other: TestComparable) -> bool:
        """Test greater than or equal comparison."""
        return self._value >= other._value


# ===== PROTOCOL CONTRACT TESTS =====


class TestConnectableProtocol:
    """Test suite for Connectable protocol."""

    @pytest.fixture
    def connectable(self) -> TestConnectable:
        """Provide Connectable implementation."""
        return TestConnectable()

    async def test_successful_connection(self, connectable: TestConnectable) -> None:
        """Test successful connection flow."""
        assert not connectable.is_connected()

        result = await connectable.connect("ldap://server.com")
        assert result is True
        assert connectable.is_connected()

    async def test_connection_failure(self) -> None:
        """Test connection failure handling."""
        connectable = TestConnectable(should_succeed=False)

        result = await connectable.connect("ldap://invalid.com")
        assert result is False
        assert not connectable.is_connected()

    async def test_disconnect(self, connectable: TestConnectable) -> None:
        """Test disconnection functionality."""
        await connectable.connect("ldap://server.com")
        assert connectable.is_connected()

        result = await connectable.disconnect()
        assert result is True
        assert not connectable.is_connected()

    async def test_disconnect_when_not_connected(
        self,
        connectable: TestConnectable,
    ) -> None:
        """Test disconnect when not connected."""
        result = await connectable.disconnect()
        assert result is False

    def test_runtime_protocol_check(self, connectable: TestConnectable) -> None:
        """Test runtime protocol checking."""
        assert isinstance(connectable, Connectable)

    @given(server_uri=st.text())
    async def test_connect_with_various_uris(
        self,
        connectable: TestConnectable,
        server_uri: str,
    ) -> None:
        """Property-based test for connection with various URIs."""
        result = await connectable.connect(server_uri)
        assert isinstance(result, bool)


class TestBindableProtocol:
    """Test suite for Bindable protocol."""

    @pytest.fixture
    def bindable(self) -> TestBindable:
        """Provide Bindable implementation."""
        return TestBindable()

    async def test_simple_bind_success(self, bindable: TestBindable) -> None:
        """Test successful simple bind."""
        result = await bindable.bind("cn=admin,dc=example,dc=com", "password")
        assert result is True

    async def test_simple_bind_failure(self, bindable: TestBindable) -> None:
        """Test failed simple bind."""
        result = await bindable.bind("cn=admin,dc=example,dc=com", "wrong")
        assert result is False

    async def test_sasl_bind_success(self, bindable: TestBindable) -> None:
        """Test successful SASL bind."""
        result = await bindable.bind_sasl("GSSAPI")
        assert result is True

        result = await bindable.bind_sasl("DIGEST-MD5", username="user")
        assert result is True

    async def test_sasl_bind_failure(self, bindable: TestBindable) -> None:
        """Test failed SASL bind with unsupported mechanism."""
        result = await bindable.bind_sasl("UNSUPPORTED")
        assert result is False

    async def test_unbind(self, bindable: TestBindable) -> None:
        """Test unbind functionality."""
        await bindable.bind("cn=admin,dc=example,dc=com", "password")
        result = await bindable.unbind()
        assert result is True

    def test_runtime_protocol_check(self, bindable: TestBindable) -> None:
        """Test runtime protocol checking."""
        assert isinstance(bindable, Bindable)


class TestSearchableProtocol:
    """Test suite for Searchable protocol."""

    @pytest.fixture
    def searchable(self) -> TestSearchable:
        """Provide Searchable implementation."""
        return TestSearchable()

    async def test_search_all_attributes(self, searchable: TestSearchable) -> None:
        """Test search returning all attributes."""
        results = [
            result
            async for result in searchable.search(
                "dc=example,dc=com",
                "(objectClass=*)",
                "subtree",
            )
        ]

        assert len(results) == 2
        assert "dn" in results[0]
        assert "cn" in results[0]
        assert "mail" in results[0]

    async def test_search_specific_attributes(self, searchable: TestSearchable) -> None:
        """Test search with attribute filtering."""
        results = [
            result
            async for result in searchable.search(
                "dc=example,dc=com",
                "(objectClass=*)",
                "subtree",
                ["cn"],
            )
        ]

        assert len(results) == 2
        assert "dn" in results[0]
        assert "cn" in results[0]
        assert "mail" not in results[0]

    async def test_search_one(self, searchable: TestSearchable) -> None:
        """Test search one functionality."""
        result = await searchable.search_one("dc=example,dc=com", "(cn=user1)")

        assert result is not None
        assert "dn" in result
        assert "cn" in result

    async def test_search_one_not_found(self) -> None:
        """Test search one with no results."""
        searchable = TestSearchable(results=[])
        result = await searchable.search_one("dc=example,dc=com", "(cn=nonexistent)")

        assert result is None

    def test_runtime_protocol_check(self, searchable: TestSearchable) -> None:
        """Test runtime protocol checking."""
        assert isinstance(searchable, Searchable)


class TestModifiableProtocol:
    """Test suite for Modifiable protocol."""

    @pytest.fixture
    def modifiable(self) -> TestModifiable:
        """Provide Modifiable implementation."""
        return TestModifiable()

    async def test_add_entry(self, modifiable: TestModifiable) -> None:
        """Test adding new entry."""
        dn = "cn=newuser,dc=example,dc=com"
        attributes = {"cn": ["newuser"], "mail": ["newuser@example.com"]}

        result = await modifiable.add(dn, attributes)
        assert result["result_code"] == 0
        assert result["message"] == "Success"
        assert result["dn"] == dn

    async def test_add_duplicate_entry(self, modifiable: TestModifiable) -> None:
        """Test adding duplicate entry fails."""
        dn = "cn=user,dc=example,dc=com"
        attributes = {"cn": ["user"]}

        # Add first time
        await modifiable.add(dn, attributes)

        # Add second time should fail
        result = await modifiable.add(dn, attributes)
        assert result["result_code"] == 68
        assert "already exists" in result["message"]

    async def test_modify_entry(self, modifiable: TestModifiable) -> None:
        """Test modifying existing entry."""
        dn = "cn=user,dc=example,dc=com"
        attributes = {"cn": ["user"]}
        changes = {"mail": ["user@example.com"]}

        # Add entry first
        await modifiable.add(dn, attributes)

        # Modify entry
        result = await modifiable.modify(dn, changes)
        assert result["result_code"] == 0
        assert result["message"] == "Success"

    async def test_modify_nonexistent_entry(self, modifiable: TestModifiable) -> None:
        """Test modifying non-existent entry fails."""
        dn = "cn=nonexistent,dc=example,dc=com"
        changes = {"mail": ["user@example.com"]}

        result = await modifiable.modify(dn, changes)
        assert result["result_code"] == 32
        assert "No such object" in result["message"]

    async def test_delete_entry(self, modifiable: TestModifiable) -> None:
        """Test deleting existing entry."""
        dn = "cn=user,dc=example,dc=com"
        attributes = {"cn": ["user"]}

        # Add entry first
        await modifiable.add(dn, attributes)

        # Delete entry
        result = await modifiable.delete(dn)
        assert result["result_code"] == 0
        assert result["message"] == "Success"

    async def test_delete_nonexistent_entry(self, modifiable: TestModifiable) -> None:
        """Test deleting non-existent entry fails."""
        dn = "cn=nonexistent,dc=example,dc=com"

        result = await modifiable.delete(dn)
        assert result["result_code"] == 32
        assert "No such object" in result["message"]

    def test_runtime_protocol_check(self, modifiable: TestModifiable) -> None:
        """Test runtime protocol checking."""
        assert isinstance(modifiable, Modifiable)


class TestValidatableProtocol:
    """Test suite for Validatable protocol."""

    def test_valid_object(self) -> None:
        """Test validation of valid object."""
        validatable = TestValidatable(is_valid=True)

        assert validatable.validate() is True
        assert len(validatable.get_validation_errors()) == 0

    def test_invalid_object(self) -> None:
        """Test validation of invalid object."""
        errors = ["Field is required", "Value out of range"]
        validatable = TestValidatable(is_valid=False, errors=errors)

        assert validatable.validate() is False
        assert validatable.get_validation_errors() == errors

    def test_validation_errors_immutable(self) -> None:
        """Test that validation errors are returned as copy."""
        errors = ["Error 1", "Error 2"]
        validatable = TestValidatable(is_valid=False, errors=errors)

        returned_errors = validatable.get_validation_errors()
        returned_errors.append("Modified error")

        # Original should be unchanged
        assert validatable.get_validation_errors() == errors

    def test_runtime_protocol_check(self) -> None:
        """Test runtime protocol checking."""
        validatable = TestValidatable()
        assert isinstance(validatable, Validatable)


class TestSerializableProtocol:
    """Test suite for Serializable protocol."""

    @pytest.fixture
    def sample_data(self) -> dict[str, Any]:
        """Provide sample data for testing."""
        return {"name": "Test", "value": 42, "active": True}

    def test_to_dict(self, sample_data: dict[str, Any]) -> None:
        """Test dictionary serialization."""
        serializable = TestSerializable(sample_data)
        result = serializable.to_dict()

        assert result == sample_data
        assert result is not sample_data  # Should be a copy

    def test_to_json(self, sample_data: dict[str, Any]) -> None:
        """Test JSON serialization."""
        serializable = TestSerializable(sample_data)
        json_str = serializable.to_json()

        import json

        parsed = json.loads(json_str)
        assert parsed == sample_data

    def test_from_dict(self, sample_data: dict[str, Any]) -> None:
        """Test creation from dictionary."""
        serializable = TestSerializable.from_dict(sample_data)
        assert serializable.to_dict() == sample_data

    def test_from_json(self, sample_data: dict[str, Any]) -> None:
        """Test creation from JSON."""
        import json

        json_str = json.dumps(sample_data)

        serializable = TestSerializable.from_json(json_str)
        assert serializable.to_dict() == sample_data

    def test_round_trip_serialization(self, sample_data: dict[str, Any]) -> None:
        """Test complete serialization round trip."""
        original = TestSerializable(sample_data)

        # Dict round trip
        dict_copy = TestSerializable.from_dict(original.to_dict())
        assert dict_copy.to_dict() == original.to_dict()

        # JSON round trip
        json_copy = TestSerializable.from_json(original.to_json())
        assert json_copy.to_dict() == original.to_dict()

    def test_runtime_protocol_check(self, sample_data: dict[str, Any]) -> None:
        """Test runtime protocol checking."""
        serializable = TestSerializable(sample_data)
        assert isinstance(serializable, Serializable)


class TestCacheableProtocol:
    """Test suite for Cacheable protocol."""

    def test_cache_key_generation(self) -> None:
        """Test cache key generation."""
        cacheable = TestCacheable("test_key")
        assert cacheable.get_cache_key() == "test_key"

    def test_cache_ttl(self) -> None:
        """Test cache TTL setting."""
        cacheable = TestCacheable("key", ttl=600)
        assert cacheable.get_cache_ttl() == 600

    def test_should_cache_true(self) -> None:
        """Test positive cache decision."""
        cacheable = TestCacheable("key", should_cache=True)
        assert cacheable.should_cache() is True

    def test_should_cache_false(self) -> None:
        """Test negative cache decision."""
        cacheable = TestCacheable("key", should_cache=False)
        assert cacheable.should_cache() is False

    def test_runtime_protocol_check(self) -> None:
        """Test runtime protocol checking."""
        cacheable = TestCacheable("key")
        assert isinstance(cacheable, Cacheable)


class TestObservableObserverProtocols:
    """Test suite for Observable and Observer protocols."""

    @pytest.fixture
    def observer(self) -> TestObserver:
        """Provide Observer implementation."""
        return TestObserver()

    @pytest.fixture
    def observable(self) -> TestObservable:
        """Provide Observable implementation."""
        return TestObservable()

    async def test_event_emission_and_handling(
        self,
        observable: TestObservable,
        observer: TestObserver,
    ) -> None:
        """Test event emission and handling."""
        observable.add_observer(observer)

        event_data = {"user_id": 123, "action": "login"}
        await observable.emit_event("user_login", event_data)

        assert len(observer.received_events) == 1
        event_type, data = observer.received_events[0]
        assert event_type == "user_login"
        assert data == event_data

    async def test_multiple_observers(self, observable: TestObservable) -> None:
        """Test multiple observers receiving events."""
        observer1 = TestObserver()
        observer2 = TestObserver()

        observable.add_observer(observer1)
        observable.add_observer(observer2)

        await observable.emit_event("test_event", {"data": "test"})

        assert len(observer1.received_events) == 1
        assert len(observer2.received_events) == 1

    def test_observer_addition_and_removal(
        self,
        observable: TestObservable,
        observer: TestObserver,
    ) -> None:
        """Test adding and removing observers."""
        # Add observer
        observable.add_observer(observer)
        assert observer in observable._observers

        # Add same observer again (should not duplicate)
        observable.add_observer(observer)
        assert observable._observers.count(observer) == 1

        # Remove observer
        observable.remove_observer(observer)
        assert observer not in observable._observers

    async def test_event_data_isolation(
        self,
        observable: TestObservable,
        observer: TestObserver,
    ) -> None:
        """Test that event data is properly isolated."""
        observable.add_observer(observer)

        original_data = {"count": 0}
        await observable.emit_event("test", original_data)

        # Modify original data
        original_data["count"] = 999

        # Observer should have received copy
        received_data = observer.received_events[0][1]
        assert received_data["count"] == 0

    def test_runtime_protocol_checks(
        self,
        observable: TestObservable,
        observer: TestObserver,
    ) -> None:
        """Test runtime protocol checking."""
        assert isinstance(observable, Observable)
        assert isinstance(observer, Observer)


class TestIdentifiableProtocol:
    """Test suite for Identifiable protocol."""

    def test_id_generation_and_retrieval(self) -> None:
        """Test ID generation and retrieval."""
        identifiable = TestIdentifiable()

        entity_id = identifiable.get_id()
        assert isinstance(entity_id, uuid.UUID)

        id_str = identifiable.get_id_str()
        assert isinstance(id_str, str)
        assert id_str == str(entity_id)

    def test_specific_id_assignment(self) -> None:
        """Test creation with specific ID."""
        specific_id = uuid.uuid4()
        identifiable = TestIdentifiable(specific_id)

        assert identifiable.get_id() == specific_id
        assert identifiable.get_id_str() == str(specific_id)

    def test_runtime_protocol_check(self) -> None:
        """Test runtime protocol checking."""
        identifiable = TestIdentifiable()
        assert isinstance(identifiable, Identifiable)


class TestTrackableProtocol:
    """Test suite for Trackable protocol."""

    def test_timestamp_retrieval(self) -> None:
        """Test timestamp retrieval."""
        trackable = TestTrackable()

        created_at = trackable.get_created_at()
        updated_at = trackable.get_updated_at()
        version = trackable.get_version()

        assert isinstance(created_at, str)
        assert isinstance(updated_at, str)
        assert isinstance(version, int)
        assert version == 1

    def test_iso_format_timestamps(self) -> None:
        """Test that timestamps are in ISO format."""
        trackable = TestTrackable()

        created_at = trackable.get_created_at()
        updated_at = trackable.get_updated_at()

        # Should be parseable as ISO format
        from datetime import datetime

        datetime.fromisoformat(created_at)
        datetime.fromisoformat(updated_at)

    def test_runtime_protocol_check(self) -> None:
        """Test runtime protocol checking."""
        trackable = TestTrackable()
        assert isinstance(trackable, Trackable)


class TestComparableProtocol:
    """Test suite for Comparable protocol."""

    def test_comparison_operations(self) -> None:
        """Test all comparison operations."""
        comp1 = TestComparable(10.0)
        comp2 = TestComparable(20.0)
        comp3 = TestComparable(10.0)

        # Less than
        assert comp1 < comp2
        assert not comp2 < comp1
        assert not comp1 < comp3

        # Less than or equal
        assert comp1 <= comp2
        assert comp1 <= comp3
        assert not comp2 <= comp1

        # Greater than
        assert comp2 > comp1
        assert not comp1 > comp2
        assert not comp1 > comp3

        # Greater than or equal
        assert comp2 >= comp1
        assert comp1 >= comp3
        assert not comp1 >= comp2

    def test_sorting_compatibility(self) -> None:
        """Test that comparable objects can be sorted."""
        comparables = [
            TestComparable(30.0),
            TestComparable(10.0),
            TestComparable(20.0),
        ]

        sorted_comparables = sorted(comparables)
        values = [c._value for c in sorted_comparables]
        assert values == [10.0, 20.0, 30.0]

    def test_runtime_protocol_check(self) -> None:
        """Test runtime protocol checking."""
        comparable = TestComparable(10.0)
        assert isinstance(comparable, Comparable)


# ===== INTEGRATION TESTS =====


class TestProtocolIntegration:
    """Integration tests for multiple protocols working together."""

    class MultiProtocolImplementation(
        TestIdentifiable,
        TestTrackable,
        TestValidatable,
        TestCacheable,
        TestSerializable,
    ):
        """Test class implementing multiple protocols."""

        def __init__(self) -> None:
            """Initialize all protocol implementations."""
            TestIdentifiable.__init__(self)
            TestTrackable.__init__(self)
            TestValidatable.__init__(self, is_valid=True)
            TestCacheable.__init__(self, f"entity_{self.get_id_str()}")

            # Serializable data
            self._data = {
                "id": self.get_id_str(),
                "created_at": self.get_created_at(),
                "version": self.get_version(),
            }
            TestSerializable.__init__(self, self._data)

    def test_multiple_protocol_implementation(self) -> None:
        """Test object implementing multiple protocols."""
        obj = self.MultiProtocolImplementation()

        # Test all protocol types
        assert isinstance(obj, Identifiable)
        assert isinstance(obj, Trackable)
        assert isinstance(obj, Validatable)
        assert isinstance(obj, Cacheable)
        assert isinstance(obj, Serializable)

        # Test functionality
        assert obj.validate() is True
        assert obj.should_cache() is True
        assert obj.get_cache_key().startswith("entity_")

        # Test serialization includes all data
        data = obj.to_dict()
        assert "id" in data
        assert "created_at" in data
        assert "version" in data


# ===== PROPERTY-BASED TESTS =====


class TestProtocolProperties:
    """Property-based tests for protocol contracts."""

    @given(
        server_uri=st.text(min_size=1),
        user_dn=st.text(min_size=1),
        password=st.text(min_size=1),
    )
    async def test_connection_bind_sequence(
        self,
        server_uri: str,
        user_dn: str,
        password: str,
    ) -> None:
        """Property test for connection and bind sequence."""

        class ConnectableBindable(TestConnectable, TestBindable):
            """Combined implementation for testing."""

            def __init__(self) -> None:
                TestConnectable.__init__(self)
                TestBindable.__init__(self)

        impl = ConnectableBindable()

        # Connection should work regardless of input
        connect_result = await impl.connect(server_uri)
        assert isinstance(connect_result, bool)

        if connect_result:
            # If connected, bind should work with valid credentials
            bind_result = await impl.bind(user_dn, password)
            assert isinstance(bind_result, bool)

    @given(
        cache_key=st.text(min_size=1),
        ttl=st.integers(min_value=0, max_value=86400),
    )
    def test_cacheable_properties(self, cache_key: str, ttl: int) -> None:
        """Property test for cacheable behavior."""
        cacheable = TestCacheable(cache_key, ttl)

        assert cacheable.get_cache_key() == cache_key
        assert cacheable.get_cache_ttl() == ttl
        assert isinstance(cacheable.should_cache(), bool)

    @given(
        values=st.lists(st.floats(allow_nan=False, allow_infinity=False), min_size=2),
    )
    def test_comparable_ordering(self, values: list[float]) -> None:
        """Property test for comparable ordering."""
        comparables = [TestComparable(v) for v in values]
        sorted_comparables = sorted(comparables)

        # Check that sorting preserves order
        for i in range(len(sorted_comparables) - 1):
            assert sorted_comparables[i] <= sorted_comparables[i + 1]
