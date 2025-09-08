"""Example of using flext_tests library for functional testing without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import asyncio

import pytest
from flext_core import FlextResult
from flext_tests import (
    AdminUserFactory,
    AsyncTestUtils,
    FlextMatchers,
    PerformanceProfiler,
    UserFactory,
)

from flext_ldap import get_flext_ldap_api
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.exceptions import FlextLDAPExceptions


class TestFlextTestsIntegration:
    """Demonstrate proper usage of flext_tests library for LDAP functional testing."""

    async def test_async_test_utils_with_ldap_operations(self) -> None:
        """Test AsyncTestUtils for concurrent LDAP operations."""
        api = get_flext_ldap_api()

        # Test concurrent session generation using AsyncTestUtils
        async def generate_session() -> str:
            return api._generate_session_id()

        # Use AsyncTestUtils.run_concurrent for parallel testing
        session_results = await AsyncTestUtils.run_concurrent(
            [
                generate_session(),
                generate_session(),
                generate_session(),
            ]
        )

        # Verify all sessions are unique
        session_ids = [result for result in session_results if result]
        assert len(set(session_ids)) == len(session_ids), (
            "All session IDs should be unique"
        )

        # Use AsyncTestUtils.run_with_timeout for timeout testing
        with pytest.raises(asyncio.TimeoutError):
            await AsyncTestUtils.run_with_timeout(
                AsyncTestUtils.simulate_delay(2.0), timeout_seconds=0.1
            )

    async def test_flext_matchers_for_result_validation(self) -> None:
        """Test FlextMatchers for FlextResult validation without mocks."""
        get_flext_ldap_api()

        # Test successful result validation using real FlextResult
        success_result = FlextResult.ok("test_success_value")

        # Use FlextMatchers for result assertions
        FlextMatchers.assert_result_success(success_result)
        assert FlextMatchers.is_successful_result(success_result)

        # Test failure result validation
        failure_result = FlextResult.fail("test_error")

        FlextMatchers.assert_result_failure(failure_result)
        assert FlextMatchers.is_failed_result(failure_result)

        # Test JSON structure validation
        user_data = {
            "dn": "cn=test,dc=example,dc=com",
            "uid": "testuser",
            "cn": "Test User",
        }

        FlextMatchers.assert_json_structure(
            user_data, {"dn": str, "uid": str, "cn": str}
        )

    def test_user_factory_for_ldap_entities(self) -> None:
        """Test UserFactory integration with LDAP entities."""
        # Generate test users using UserFactory
        test_users = UserFactory.build_batch(5)

        for user in test_users:
            # Verify user has required attributes
            assert hasattr(user, "name")
            assert hasattr(user, "email")
            assert hasattr(user, "id")

            # Convert to LDAP CreateUserRequest
            create_request = FlextLDAPEntities.CreateUserRequest(
                dn=f"cn={user.name.replace(' ', '.')},ou=users,dc=example,dc=com",
                uid=user.name.replace(" ", ".").lower(),
                cn=user.name,
                mail=user.email,
            )

            # Validate business rules
            validation_result = create_request.validate_business_rules()
            FlextMatchers.assert_result_success(validation_result)

    async def test_performance_profiling_for_ldap_operations(self) -> None:
        """Test PerformanceProfiler for LDAP operation performance."""
        api = get_flext_ldap_api()

        # Profile session creation performance
        def session_operation() -> str:
            return api._generate_session_id()

        # Use PerformanceProfiler.profile_memory
        memory_result = PerformanceProfiler.profile_memory(session_operation)
        assert memory_result is not None

        # Skip performance test for now - requires benchmark fixture
        # FlextMatchers.assert_performance_within_limit would need benchmark fixture
        assert True  # Placeholder for performance testing

    def test_REDACTED_LDAP_BIND_PASSWORD_user_factory_integration(self) -> None:
        """Test AdminUserFactory for privileged user scenarios."""
        # Create REDACTED_LDAP_BIND_PASSWORD users for testing
        REDACTED_LDAP_BIND_PASSWORD_users = AdminUserFactory.build_batch(3)

        for REDACTED_LDAP_BIND_PASSWORD in REDACTED_LDAP_BIND_PASSWORD_users:
            # Verify REDACTED_LDAP_BIND_PASSWORD has required attributes
            assert hasattr(REDACTED_LDAP_BIND_PASSWORD, "name")
            assert hasattr(REDACTED_LDAP_BIND_PASSWORD, "email")

            # Create REDACTED_LDAP_BIND_PASSWORD LDAP request
            REDACTED_LDAP_BIND_PASSWORD_request = FlextLDAPEntities.CreateUserRequest(
                dn=f"cn={REDACTED_LDAP_BIND_PASSWORD.name.replace(' ', '.')},ou=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
                uid=REDACTED_LDAP_BIND_PASSWORD.name.replace(" ", ".").lower(),
                cn=REDACTED_LDAP_BIND_PASSWORD.name,
                mail=REDACTED_LDAP_BIND_PASSWORD.email,
            )

            # Validate REDACTED_LDAP_BIND_PASSWORD user request
            validation_result = REDACTED_LDAP_BIND_PASSWORD_request.validate_business_rules()
            FlextMatchers.assert_result_success(validation_result)

    async def test_async_concurrent_ldap_operations(self) -> None:
        """Test concurrent LDAP operations using AsyncTestUtils."""
        api = get_flext_ldap_api()

        # Create multiple users concurrently
        users = UserFactory.build_batch(3)

        async def create_user_session(user: object) -> str:
            """Create session for user creation."""
            session_id = api._generate_session_id()
            return {
                "session_id": session_id,
                "user": user,
                "timestamp": asyncio.get_event_loop().time(),
            }

        # Run concurrent user session creation
        concurrent_tasks = [create_user_session(user) for user in users]
        results = await AsyncTestUtils.run_concurrent_tasks(concurrent_tasks)

        # Validate all operations completed successfully
        assert len(results) == 3
        for result in results:
            assert "session_id" in result
            assert "user" in result
            assert "timestamp" in result

        # Verify sessions are unique
        session_ids = [result["session_id"] for result in results]
        assert len(set(session_ids)) == len(session_ids)

    def test_type_guard_validation_with_flext_matchers(self) -> None:
        """Test type guard validation using FlextMatchers."""
        # Test LDAP DN validation
        valid_dn = "cn=test,ou=users,dc=example,dc=com"
        invalid_dn = "invalid_dn_format"

        # Use FlextMatchers.assert_regex_match for DN validation
        dn_pattern = r"^[a-zA-Z]+=[^,]+(?:,[a-zA-Z]+=[^,]+)*$"
        FlextMatchers.assert_regex_match(valid_dn, dn_pattern)

        with pytest.raises(AssertionError):
            FlextMatchers.assert_regex_match(invalid_dn, dn_pattern)

    def test_exception_validation_with_real_scenarios(self) -> None:
        """Test exception handling in real scenarios without mocks."""
        # Test FlextLDAPExceptions factory methods
        conn_params = FlextLDAPExceptions.ConnectionParams(
            server_uri="ldap://localhost:389", error="Connection timeout"
        )
        connection_error = FlextLDAPExceptions.Factory.connection_failed(conn_params)

        assert isinstance(connection_error, Exception)
        assert "ldap://localhost:389" in str(connection_error)
        assert "Connection timeout" in str(connection_error)

        # Test validation error creation
        validation_error = FlextLDAPExceptions.Factory.validation_failed(
            field_name="dn", error="Invalid DN format"
        )

        assert isinstance(validation_error, Exception)
        assert "Invalid DN format" in str(validation_error)
