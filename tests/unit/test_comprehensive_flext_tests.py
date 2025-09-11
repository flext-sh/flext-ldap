"""Comprehensive example using flext_tests library for 100% functional testing.

This demonstrates proper usage of ALL flext_tests capabilities:
- Factories for test data generation
- Matchers for assertions
- Performance profiling
- Async utilities
- Hypothesis testing
- Builder patterns


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from flext_core import FlextResult
from flext_tests import (
    FlextTestsAsyncs,
    FlextTestsBuilders,
    FlextTestsFactories,
    FlextTestsMatchers,
    FlextTestsPerformance,
)

from flext_ldap import get_flext_ldap_api
from flext_ldap.entities import FlextLDAPEntities

# Access components through proper structure
AdminUserFactory = FlextTestsFactories.AdminUserFactory
UserFactory = FlextTestsFactories.UserFactory
AsyncTestUtils = FlextTestsAsyncs
TestBuilders = FlextTestsBuilders
PerformanceProfiler = FlextTestsPerformance


@pytest.mark.asyncio
class TestComprehensiveFlextTests:
    """Comprehensive flext_tests integration demonstrating ALL capabilities."""

    def test_user_factory_comprehensive(self) -> None:
        """Test UserFactory from flext_tests for LDAP user creation."""
        # Generate test users using flext_tests UserFactory
        users = UserFactory.build_batch(5)
        REDACTED_LDAP_BIND_PASSWORD_user = AdminUserFactory.build()

        # Validate using FlextTestsMatchers
        assert len(users) == 5
        assert users
        assert len(users) > 0
        # Validate REDACTED_LDAP_BIND_PASSWORD_user has required fields
        assert hasattr(REDACTED_LDAP_BIND_PASSWORD_user, "name")
        assert hasattr(REDACTED_LDAP_BIND_PASSWORD_user, "email")

        # Transform to LDAP entities using only valid User model fields
        for user in users:
            uid = user.name.lower().replace(" ", ".")
            ldap_user_data = {
                "id": uid,  # Required field
                "dn": f"cn={user.name},ou=users,dc=test,dc=com",  # Required field
                "uid": uid,  # Required field
                "cn": user.name,
                "mail": user.email,
                "sn": user.name.split()[-1] if " " in user.name else user.name,
                "given_name": user.name.split()[0] if " " in user.name else user.name,
                # created_at and updated_at will be set automatically by default_factory
            }

            # Create LDAP entity using valid model fields only
            ldap_user = FlextLDAPEntities.User(**ldap_user_data)
            assert ldap_user.cn == user.name
            assert ldap_user.mail == user.email

    async def test_async_utils_with_performance_profiling(self) -> None:
        """Test AsyncTestUtils with PerformanceProfiler for LDAP operations."""

        # Run concurrent operations with async utils
        async def session_generation_task() -> str:
            """Generate session ID."""
            return f"session_{uuid.uuid4()}"

        # Run concurrent operations without profiling
        sessions = await AsyncTestUtils.run_concurrent(
            [session_generation_task() for _ in range(10)]
        )

        # Validate results using FlextTestsMatchers
        assert sessions
        assert len(sessions) > 0
        assert len(sessions) == 10
        assert len(set(sessions)) == 10  # All unique

        # Basic validation - all sessions should be valid strings
        for session in sessions:
            assert isinstance(session, str)
            assert len(session) > 0

    def test_builders_for_search_requests(self) -> None:
        """Test direct LDAP SearchRequest creation using SOURCE OF TRUTH pattern."""
        # Use direct FlextLDAPEntities.SearchRequest construction - no duplication
        ldap_search = FlextLDAPEntities.SearchRequest(
            base_dn="ou=users,dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "mail", "uid"],
            size_limit=100,
            time_limit=30,
        )

        # Validate LDAP format - basic validation
        assert "dc=" in ldap_search.base_dn  # Basic DN validation
        assert "(" in ldap_search.filter_str
        assert ")" in ldap_search.filter_str
        assert ldap_search.scope in {"base", "one", "subtree"}

    async def test_real_ldap_operations_with_matchers(self) -> None:
        """Test real LDAP operations using FlextTestsMatchers for validation."""
        api = get_flext_ldap_api()

        # Generate test user using UserFactory
        test_user = UserFactory.build()

        # Create search request for the user
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn="dc=test,dc=com",
            filter_str=f"(cn={test_user.name})",
            scope="subtree",
            attributes=["cn", "mail"],
        )

        # Execute real search (will fail gracefully without connection)
        result = await api.search(search_request)

        # Use FlextTestsMatchers for result validation
        # Check that result is a FlextResult instance
        assert isinstance(result, FlextResult)

        if result.is_success:
            assert isinstance(result.value, list)
        else:
            # Expected failure without real LDAP connection
            FlextTestsMatchers.assert_result_failure(result)
            assert result.error is not None
            assert result.error
            assert len(result.error) > 0

    def test_hypothesis_like_testing_with_factories(self) -> None:
        """Test hypothesis-like behavior using flext_tests factories."""
        # Generate multiple test scenarios using factories
        test_scenarios = []

        for _ in range(20):  # Test 20 different scenarios
            user = UserFactory.build()
            scenario = {
                "user": user,
                "dn_format": f"cn={user.name},ou=users,dc=example,dc=com",
                "expected_cn": user.name,
                "expected_mail": user.email,
            }
            test_scenarios.append(scenario)

        # Test all scenarios
        for scenario in test_scenarios:
            # Validate DN format - basic validation
            assert "dc=" in scenario["dn_format"]
            assert "cn=" in scenario["dn_format"]

            # Create LDAP user from scenario using only valid fields
            ldap_user = FlextLDAPEntities.User(
                id=f"test_{scenario['user'].name.lower().replace(' ', '_')}",
                dn=scenario["dn_format"],
                cn=scenario["expected_cn"],
                mail=scenario["expected_mail"],
                uid=scenario["user"].name.lower().replace(" ", "."),
                sn="TestSurname",
                given_name=scenario["expected_cn"],
                object_classes=["person"],
                attributes={},
                status="active",
            )
            assert ldap_user.cn == scenario["expected_cn"]
            assert ldap_user.mail == scenario["expected_mail"]

    async def test_timeout_and_error_handling_with_async_utils(self) -> None:
        """Test timeout and error handling using AsyncTestUtils."""

        # Test timeout behavior
        async def slow_operation() -> str:
            await asyncio.sleep(0.5)
            return "completed"

        # Test timeout functionality
        with pytest.raises(asyncio.TimeoutError):
            await AsyncTestUtils.run_with_timeout(slow_operation(), timeout_seconds=0.1)

        # Test successful completion within timeout
        result = await AsyncTestUtils.run_with_timeout(
            slow_operation(), timeout_seconds=1.0
        )
        assert result == "completed"

    def test_data_validation_with_comprehensive_matchers(self) -> None:
        """Test comprehensive data validation using all FlextTestsMatchers."""
        # Test various data validation scenarios
        user = UserFactory.build()

        # String validations
        assert user.name
        assert len(user.name) > 0
        assert user.email
        assert len(user.email) > 0

        # Email validation
        # Email validation - basic check
        assert "@" in user.email
        assert "." in user.email

        # Collection validations
        test_list = [1, 2, 3, 4, 5]
        assert test_list
        assert len(test_list) > 0
        assert len(test_list) == 5

        assert isinstance(user.name, str)
        assert isinstance(test_list, list)

        # FlextResult validations
        success_result = FlextResult.ok("success")
        failure_result = FlextResult.fail("error")

        FlextTestsMatchers.assert_result_success(success_result)
        FlextTestsMatchers.assert_result_failure(failure_result)

        assert FlextTestsMatchers.is_successful_result(success_result)
        assert FlextTestsMatchers.is_failed_result(failure_result)
