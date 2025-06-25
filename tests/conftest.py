"""🔥🔥🔥🔥🔥 ULTRA DRY Test Configuration - ZERO DUPLICATION TOLERANCE.

This module provides shared fixtures, factories, and utilities that eliminate
ALL code duplication across the test suite. Following EXTREME DRY principles
with reusable components, property-based generators, and advanced patterns.

ZERO DUPLICATION RULES:
- ❌ No repeated entity creation
- ❌ No repeated mock implementations
- ❌ No repeated test data patterns
- ❌ No repeated assertion patterns
- ❌ No repeated setup/teardown code

REUSABILITY PATTERNS:
✅ Factory functions for all test objects
✅ Parametrized fixtures for variations
✅ Hypothesis strategies for property testing
✅ Shared assertion helpers
✅ Common mock implementations
✅ Test data generators
✅ Benchmark utilities
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypeVar

import pytest
from hypothesis import strategies as st

from ldap_core_shared.types.base import (
    BaseEntity,
    BaseService,
    BaseValueObject,
)
from ldap_core_shared.types.generics import Repository, Service

if TYPE_CHECKING:
    from collections.abc import Callable

    from ldap_core_shared.types.protocols import (
        Observer,
    )

T = TypeVar("T")


# =============================================================================
# 🔥 ENTITY FACTORIES - ZERO DUPLICATION
# =============================================================================


class TestUser(BaseEntity):
    """Standardized test user entity used across ALL tests."""

    username: str
    email: str
    age: int
    is_active: bool = True
    role: str = "user"

    def can_be_deleted(self) -> bool:
        """Business rule: admins and active users with important data cannot be deleted."""
        if self.role == "admin":
            return False
        return not (self.is_active and self.username.startswith("protected_"))


class TestProduct(BaseEntity):
    """Standardized test product entity."""

    name: str
    price: float
    category: str = "general"
    stock: int = 0
    is_available: bool = True

    def can_be_deleted(self) -> bool:
        """Business rule: products with stock cannot be deleted."""
        return self.stock == 0


class TestEmail(BaseValueObject):
    """Standardized test email value object."""

    address: str
    verified: bool = False
    domain: str = ""

    def model_post_init(self, __context: Any) -> None:
        """Extract domain from address."""
        if "@" in self.address:
            object.__setattr__(self, "domain", self.address.split("@")[1])

    def is_valid(self) -> bool:
        """Comprehensive email validation."""
        if not self.address or "@" not in self.address:
            return False
        parts = self.address.split("@")
        if len(parts) != 2:
            return False
        local, domain = parts
        return (
            len(local) > 0
            and len(domain) > 0
            and "." in domain
            and not local.startswith(".")
            and not local.endswith(".")
            and not domain.startswith(".")
            and not domain.endswith(".")
        )


# =============================================================================
# 🔥 ENTITY FACTORIES - PARAMETERIZED CREATION
# =============================================================================


@pytest.fixture
def user_factory():
    """Factory function for creating test users with variations."""

    def _create_user(
        username: str = "testuser",
        email: str | None = None,
        age: int = 25,
        is_active: bool = True,
        role: str = "user",
    ) -> TestUser:
        if email is None:
            email = f"{username}@example.com"

        return TestUser(
            username=username,
            email=email,
            age=age,
            is_active=is_active,
            role=role,
        )

    return _create_user


@pytest.fixture
def product_factory():
    """Factory function for creating test products with variations."""

    def _create_product(
        name: str = "Test Product",
        price: float = 99.99,
        category: str = "general",
        stock: int = 0,
        is_available: bool = True,
    ) -> TestProduct:
        return TestProduct(
            name=name,
            price=price,
            category=category,
            stock=stock,
            is_available=is_available,
        )

    return _create_product


@pytest.fixture
def email_factory():
    """Factory function for creating test emails with variations."""

    def _create_email(
        address: str = "test@example.com",
        verified: bool = False,
    ) -> TestEmail:
        return TestEmail(address=address, verified=verified)

    return _create_email


# =============================================================================
# 🔥 REPOSITORY AND SERVICE FIXTURES - REUSABLE PATTERNS
# =============================================================================


@pytest.fixture
def user_repository() -> Repository[TestUser]:
    """Standard user repository for all tests."""
    return Repository[TestUser]()


@pytest.fixture
def product_repository() -> Repository[TestProduct]:
    """Standard product repository for all tests."""
    return Repository[TestProduct]()


@pytest.fixture
def user_service(user_repository: Repository[TestUser]) -> Service[TestUser]:
    """Standard user service for all tests."""
    return Service[TestUser](user_repository)


@pytest.fixture
def product_service(
    product_repository: Repository[TestProduct],
) -> Service[TestProduct]:
    """Standard product service for all tests."""
    return Service[TestProduct](product_repository)


# =============================================================================
# 🔥 SAMPLE DATA FIXTURES - PREDEFINED COMMON DATASETS
# =============================================================================


@pytest.fixture
def sample_user(user_factory: Any) -> TestUser:
    """Standard sample user used across multiple tests."""
    return user_factory(username="john_doe", age=30, is_active=True)


@pytest.fixture
def admin_user(user_factory: Any) -> TestUser:
    """Standard admin user for authorization tests."""
    return user_factory(username="admin", role="admin", age=35)


@pytest.fixture
def inactive_user(user_factory: Any) -> TestUser:
    """Standard inactive user for state tests."""
    return user_factory(username="inactive_user", is_active=False, age=40)


@pytest.fixture
def protected_user(user_factory: Any) -> TestUser:
    """Standard protected user that cannot be deleted."""
    return user_factory(username="protected_vip", age=45)


@pytest.fixture
def sample_product(product_factory: Any) -> TestProduct:
    """Standard sample product."""
    return product_factory(name="Laptop", price=999.99, category="electronics")


@pytest.fixture
def out_of_stock_product(product_factory: Any) -> TestProduct:
    """Standard out of stock product."""
    return product_factory(name="Discontinued Item", stock=0, is_available=False)


@pytest.fixture
def in_stock_product(product_factory: Any) -> TestProduct:
    """Standard in stock product."""
    return product_factory(name="Popular Item", stock=50, price=49.99)


@pytest.fixture
def sample_email(email_factory: Any) -> TestEmail:
    """Standard sample email."""
    return email_factory(address="user@company.com", verified=True)


@pytest.fixture
def invalid_email(email_factory: Any) -> TestEmail:
    """Standard invalid email for validation tests."""
    return email_factory(address="invalid.email", verified=False)


# =============================================================================
# 🔥 BULK DATA FIXTURES - COLLECTIONS FOR STRESS TESTING
# =============================================================================


@pytest.fixture
def user_collection(user_factory: Any) -> list[TestUser]:
    """Collection of diverse users for bulk operations."""
    return [
        user_factory(username=f"user_{i}", age=18 + (i % 50), is_active=i % 4 != 0)
        for i in range(20)
    ]


@pytest.fixture
def product_collection(product_factory: Any) -> list[TestProduct]:
    """Collection of diverse products for bulk operations."""
    categories = ["electronics", "clothing", "books", "home"]
    return [
        product_factory(
            name=f"Product {i}",
            price=10.0 + (i * 5.0),
            category=categories[i % len(categories)],
            stock=i % 10,
        )
        for i in range(15)
    ]


# =============================================================================
# 🔥 MOCK IMPLEMENTATIONS - ZERO DUPLICATION PROTOCOL MOCKS
# =============================================================================


class UniversalMockConnection:
    """Universal mock that implements multiple LDAP protocols."""

    def __init__(self) -> None:
        self._connected = False
        self._bound = False
        self._server_uri = ""
        self._bind_dn = ""
        self._entries: dict[str, dict[str, Any]] = {}
        self._observers: list[Observer] = []

    # Connectable implementation
    async def connect(self, server_uri: str, **kwargs: Any) -> bool:
        self._server_uri = server_uri
        self._connected = True
        return True

    async def disconnect(self) -> bool:
        self._connected = False
        self._bound = False
        return True

    def is_connected(self) -> bool:
        return self._connected

    # Bindable implementation
    async def bind(self, user_dn: str, password: str) -> bool:
        if not self._connected:
            return False
        self._bind_dn = user_dn
        self._bound = True
        return True

    async def bind_sasl(self, mechanism: str, **kwargs: Any) -> bool:
        if not self._connected:
            return False
        self._bound = True
        return True

    async def unbind(self) -> bool:
        self._bound = False
        return True

    # Searchable implementation
    async def search(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
        **kwargs: Any,
    ):
        for dn, attrs in self._entries.items():
            if base_dn in dn or dn in base_dn:
                yield {"dn": dn, "attributes": attrs}

    async def search_one(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        async for entry in self.search(base_dn, search_filter, attributes=attributes):
            return entry
        return None

    # Modifiable implementation
    async def add(self, dn: str, attributes: dict[str, Any]) -> dict[str, Any]:
        if dn in self._entries:
            return {"result_code": 68, "message": "Entry already exists", "dn": dn}
        self._entries[dn] = attributes.copy()
        return {"result_code": 0, "message": "Success", "dn": dn}

    async def modify(self, dn: str, changes: dict[str, Any]) -> dict[str, Any]:
        if dn not in self._entries:
            return {"result_code": 32, "message": "No such object", "dn": dn}
        self._entries[dn].update(changes)
        return {"result_code": 0, "message": "Success", "dn": dn}

    async def delete(self, dn: str) -> dict[str, Any]:
        if dn not in self._entries:
            return {"result_code": 32, "message": "No such object", "dn": dn}
        del self._entries[dn]
        return {"result_code": 0, "message": "Success", "dn": dn}

    # Observable implementation
    async def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        for observer in self._observers:
            await observer.on_event(event_type, data)

    def add_observer(self, observer: Observer) -> None:
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer: Observer) -> None:
        if observer in self._observers:
            self._observers.remove(observer)

    # Helper methods for testing
    def add_test_entry(self, dn: str, attributes: dict[str, Any]) -> None:
        """Helper to add test entries directly."""
        self._entries[dn] = attributes.copy()

    def get_entry_count(self) -> int:
        """Helper to get number of entries."""
        return len(self._entries)

    def clear_entries(self) -> None:
        """Helper to clear all entries."""
        self._entries.clear()


@pytest.fixture
def mock_connection() -> UniversalMockConnection:
    """Universal mock connection implementing multiple protocols."""
    return UniversalMockConnection()


class MockObserver:
    """Reusable mock observer for event testing."""

    def __init__(self) -> None:
        self.received_events: list[tuple[str, dict[str, Any]]] = []

    async def on_event(self, event_type: str, data: dict[str, Any]) -> None:
        self.received_events.append((event_type, data.copy()))

    def get_event_count(self) -> int:
        return len(self.received_events)

    def get_events_by_type(self, event_type: str) -> list[dict[str, Any]]:
        return [data for etype, data in self.received_events if etype == event_type]

    def clear_events(self) -> None:
        self.received_events.clear()


@pytest.fixture
def mock_observer() -> MockObserver:
    """Reusable mock observer."""
    return MockObserver()


# =============================================================================
# 🔥 HYPOTHESIS STRATEGIES - PROPERTY-BASED TEST DATA
# =============================================================================

# Username strategy
username_strategy = st.text(
    alphabet=st.characters(
        whitelist_categories=["Lu", "Ll", "Nd"],
        whitelist_characters="_-",
    ),
    min_size=3,
    max_size=20,
).filter(lambda x: x[0].isalpha())

# Email strategy
email_strategy = st.builds(
    lambda local, domain, tld: f"{local}@{domain}.{tld}",
    local=st.text(
        alphabet=st.characters(whitelist_categories=["Lu", "Ll", "Nd"]),
        min_size=1,
        max_size=10,
    ),
    domain=st.text(
        alphabet=st.characters(whitelist_categories=["Lu", "Ll"]),
        min_size=2,
        max_size=10,
    ),
    tld=st.sampled_from(["com", "org", "net", "edu", "gov"]),
)

# Age strategy
age_strategy = st.integers(min_value=1, max_value=120)

# Price strategy
price_strategy = st.floats(
    min_value=0.01,
    max_value=9999.99,
    allow_nan=False,
    allow_infinity=False,
)

# Product category strategy
category_strategy = st.sampled_from(
    [
        "electronics",
        "clothing",
        "books",
        "home",
        "sports",
        "automotive",
        "beauty",
        "toys",
    ],
)

# Stock strategy
stock_strategy = st.integers(min_value=0, max_value=1000)


@pytest.fixture
def user_strategy():
    """Hypothesis strategy for generating test users."""
    return st.builds(
        TestUser,
        username=username_strategy,
        email=email_strategy,
        age=age_strategy,
        is_active=st.booleans(),
        role=st.sampled_from(["user", "admin", "moderator", "guest"]),
    )


@pytest.fixture
def product_strategy():
    """Hypothesis strategy for generating test products."""
    return st.builds(
        TestProduct,
        name=st.text(min_size=1, max_size=50),
        price=price_strategy,
        category=category_strategy,
        stock=stock_strategy,
        is_available=st.booleans(),
    )


@pytest.fixture
def email_strategy():
    """Hypothesis strategy for generating test emails."""
    return st.builds(
        TestEmail,
        address=email_strategy,
        verified=st.booleans(),
    )


# =============================================================================
# 🔥 ASSERTION HELPERS - REUSABLE VALIDATION PATTERNS
# =============================================================================


class AssertionHelpers:
    """Centralized assertion helpers to eliminate duplication."""

    @staticmethod
    def assert_valid_entity(entity: BaseEntity) -> None:
        """Assert entity has valid structure and audit fields."""
        assert isinstance(entity.id, uuid.UUID)
        assert isinstance(entity.created_at, datetime)
        assert isinstance(entity.updated_at, datetime)
        assert entity.created_at.tzinfo is not None
        assert entity.updated_at.tzinfo is not None
        assert entity.version >= 1
        assert entity.created_at <= entity.updated_at

    @staticmethod
    def assert_valid_value_object(value_obj: BaseValueObject) -> None:
        """Assert value object is properly structured."""
        # Value objects should be comparable by value
        same_obj = value_obj.__class__.model_validate(value_obj.model_dump())
        assert value_obj == same_obj

    @staticmethod
    async def assert_repository_crud_cycle(repo: Repository[T], entity: T) -> None:
        """Assert complete CRUD cycle works for repository."""
        # Create
        saved = await repo.save(entity)
        assert saved == entity

        # Read
        found = await repo.find_by_id(entity.id)
        assert found == entity

        # Update (mark updated)
        updated = entity.mark_updated()
        await repo.save(updated)
        found_updated = await repo.find_by_id(entity.id)
        assert found_updated.version == entity.version + 1

        # Delete
        deleted = await repo.delete(updated)
        assert deleted is True

        # Verify deletion
        not_found = await repo.find_by_id(entity.id)
        assert not_found is None

    @staticmethod
    async def assert_service_health(service: BaseService) -> None:
        """Assert service is healthy."""
        health = await service.health_check()
        assert health is True

    @staticmethod
    def assert_result_success(result: Any, expected_value: Any = None) -> None:
        """Assert Result is success with optional value check."""
        assert result.is_success()
        assert not result.is_error()
        if expected_value is not None:
            assert result.unwrap() == expected_value

    @staticmethod
    def assert_result_error(result: Any, expected_error: Any = None) -> None:
        """Assert Result is error with optional error check."""
        assert result.is_error()
        assert not result.is_success()
        if expected_error is not None:
            assert result.unwrap_error() == expected_error

    @staticmethod
    def assert_option_some(option: Any, expected_value: Any = None) -> None:
        """Assert Option is Some with optional value check."""
        assert option.is_some()
        assert not option.is_none()
        if expected_value is not None:
            assert option.unwrap() == expected_value

    @staticmethod
    def assert_option_none(option: Any) -> None:
        """Assert Option is None."""
        assert option.is_none()
        assert not option.is_some()


@pytest.fixture
def assert_helper() -> AssertionHelpers:
    """Centralized assertion helpers."""
    return AssertionHelpers


# =============================================================================
# 🔥 PERFORMANCE UTILITIES - BENCHMARKING WITHOUT DUPLICATION
# =============================================================================


class PerformanceUtils:
    """Centralized performance testing utilities."""

    @staticmethod
    def time_operation(operation: Callable[[], Any]) -> tuple[Any, float]:
        """Time an operation and return (result, duration)."""
        import time

        start = time.time()
        result = operation()
        duration = time.time() - start
        return result, duration

    @staticmethod
    async def time_async_operation(operation: Callable[[], Any]) -> tuple[Any, float]:
        """Time an async operation and return (result, duration)."""
        import time

        start = time.time()
        result = await operation()
        duration = time.time() - start
        return result, duration

    @staticmethod
    def assert_performance(
        duration: float,
        max_duration: float,
        operation_name: str = "operation",
    ) -> None:
        """Assert operation completed within performance threshold."""
        assert (
            duration <= max_duration
        ), f"{operation_name} took {duration:.4f}s, expected <= {max_duration:.4f}s"

    @staticmethod
    def measure_throughput(count: int, duration: float) -> float:
        """Calculate operations per second."""
        return count / duration if duration > 0 else float("inf")


@pytest.fixture
def perf_utils() -> PerformanceUtils:
    """Performance testing utilities."""
    return PerformanceUtils


# =============================================================================
# 🔥 TEST DATA GENERATORS - STANDARDIZED PATTERNS
# =============================================================================


class TestDataGenerator:
    """Centralized test data generation to eliminate duplication."""

    @staticmethod
    def generate_user_batch(count: int, factory_func: Callable) -> list[TestUser]:
        """Generate batch of users with systematic variations."""
        return [
            factory_func(
                username=f"batch_user_{i}",
                age=18 + (i % 60),
                is_active=i % 3 != 0,
                role="admin" if i % 10 == 0 else "user",
            )
            for i in range(count)
        ]

    @staticmethod
    def generate_product_batch(count: int, factory_func: Callable) -> list[TestProduct]:
        """Generate batch of products with systematic variations."""
        categories = ["electronics", "clothing", "books", "home"]
        return [
            factory_func(
                name=f"Product {i}",
                price=round(10.0 + (i * 5.0), 2),
                category=categories[i % len(categories)],
                stock=i % 20,
                is_available=i % 5 != 0,
            )
            for i in range(count)
        ]

    @staticmethod
    def generate_ldap_dns(count: int, base_dn: str = "dc=test,dc=com") -> list[str]:
        """Generate systematic LDAP DNs for testing."""
        return [f"cn=entry{i},ou=people,{base_dn}" for i in range(count)]

    @staticmethod
    def generate_test_attributes(entry_id: int) -> dict[str, list[str]]:
        """Generate systematic LDAP attributes."""
        return {
            "objectClass": ["person", "organizationalPerson"],
            "cn": [f"entry{entry_id}"],
            "sn": [f"surname{entry_id}"],
            "mail": [f"entry{entry_id}@test.com"],
            "description": [f"Test entry number {entry_id}"],
        }


@pytest.fixture
def data_generator() -> TestDataGenerator:
    """Centralized test data generator."""
    return TestDataGenerator


# =============================================================================
# 🔥 CLEANUP UTILITIES - CONSISTENT TEARDOWN
# =============================================================================


@pytest.fixture(autouse=True)
def cleanup_test_state() -> None:
    """Auto cleanup to ensure test isolation."""
    # Setup - nothing needed
    return
    # Teardown - could add cleanup logic here if needed


# =============================================================================
# 🔥 PARAMETERIZED FIXTURES - ELIMINATING SIMILAR TEST PATTERNS
# =============================================================================


@pytest.fixture(
    params=[
        ("valid_user", {"username": "valid", "email": "valid@test.com", "age": 25}),
        ("edge_age_user", {"username": "young", "email": "young@test.com", "age": 1}),
        ("old_user", {"username": "senior", "email": "senior@test.com", "age": 120}),
    ],
)
def parameterized_user(request: Any, user_factory: Any) -> Any:
    """Parameterized user fixture for testing variations."""
    name, params = request.param
    return user_factory(**params)


@pytest.fixture(
    params=[
        ("cheap_product", {"name": "Cheap Item", "price": 0.01}),
        ("expensive_product", {"name": "Luxury Item", "price": 9999.99}),
        ("free_product", {"name": "Free Sample", "price": 0.00}),
    ],
)
def parameterized_product(request: Any, product_factory: Any) -> Any:
    """Parameterized product fixture for testing variations."""
    name, params = request.param
    return product_factory(**params)


# =============================================================================
# 🔥 INTEGRATION TEST FIXTURES - COMPLEX SCENARIOS
# =============================================================================


@pytest.fixture
def populated_user_repository(user_repository: Any, user_collection: Any) -> Any:
    """Repository pre-populated with test users."""
    import asyncio

    async def _populate() -> None:
        for user in user_collection:
            await user_repository.save(user)

    asyncio.run(_populate())
    return user_repository


@pytest.fixture
def populated_product_repository(
    product_repository: Any, product_collection: Any
) -> Any:
    """Repository pre-populated with test products."""
    import asyncio

    async def _populate() -> None:
        for product in product_collection:
            await product_repository.save(product)

    asyncio.run(_populate())
    return product_repository
