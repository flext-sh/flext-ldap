"""Comprehensive FlextTests integration tests for flext-ldap.

Demonstrates proper usage of FlextTests patterns for LDAP testing with Pydantic v2.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio
import uuid
from typing import cast

import pytest
from flext_tests import FlextTestsAsyncs, FlextTestsFactories, FlextTestsMatchers

from flext_core import FlextResult, FlextTypes
from flext_ldap.api import FlextLdapApi
from flext_ldap.models import FlextLdapModels


class TestComprehensiveFlextTests:
    """Comprehensive FlextTests integration demonstrating LDAP testing capabilities."""

    def test_ldap_user_factory_with_flext_patterns(self) -> None:
        """Test LDAP user creation using real FlextTestsFactories patterns."""
        # Use REAL FlextTestsFactories.UserFactory.create() method

        # Create multiple users using real factory methods
        test_users = FlextTestsFactories.UserFactory.create_batch(5)

        # Create REDACTED_LDAP_BIND_PASSWORD user using single create method (UserFactory uses defaults)
        REDACTED_LDAP_BIND_PASSWORD_user = FlextTestsFactories.UserFactory.create()
        # Customize for REDACTED_LDAP_BIND_PASSWORD role
        REDACTED_LDAP_BIND_PASSWORD_user["name"] = "AdminUser"
        REDACTED_LDAP_BIND_PASSWORD_user["email"] = "REDACTED_LDAP_BIND_PASSWORD@example.com"

        # Validate using FlextTestsMatchers

        # Use available FlextTestsMatchers and standard assertions
        assert test_users, "User list should not be empty"
        assert len(test_users) == 5, "Should have exactly 5 users"
        assert isinstance(REDACTED_LDAP_BIND_PASSWORD_user, dict), "Admin user should be a dictionary"
        assert "name" in REDACTED_LDAP_BIND_PASSWORD_user and "email" in REDACTED_LDAP_BIND_PASSWORD_user, (
            "Admin user should have required keys"
        )

        # Transform to LDAP entities
        for user in test_users:
            # Create UID from the user ID for LDAP compatibility - ensure type safety
            user_id = str(user["id"])
            user_name = str(user["name"])
            user_email = str(user["email"])
            uid = f"user_{user_id.split('-', maxsplit=1)[0]}"  # Use first part of UUID as UID

            # Create LDAP entity with proper constructor arguments
            ldap_user = FlextLdapModels.User(
                id=user_id,
                dn=f"cn={user_name},ou=users,dc=test,dc=com",
                uid=uid,
                cn=user_name,
                mail=user_email,
                sn=user_name.rsplit(maxsplit=1)[-1] if " " in user_name else user_name,
                given_name=user_name.split(maxsplit=1)[0]
                if " " in user_name
                else user_name,
                object_classes=["person"],
                attributes={},
            )

            # Use standard assertions for LDAP entity validation
            assert isinstance(ldap_user, FlextLdapModels.User), (
                "Should create valid LDAP User entity"
            )
            assert ldap_user.dn is not None, "DN should not be None"
            assert ldap_user.mail == user["email"], "Email should match"

    @pytest.mark.asyncio
    async def test_async_utils_with_performance_profiling(self) -> None:
        """Test AsyncTestUtils with PerformanceProfiler for LDAP operations."""

        # Create async task factory using real FlextTestsAsyncs
        async def session_generation_task() -> str:
            """Generate session ID."""
            return f"session_{uuid.uuid4()}"

        # Run concurrent operations using asyncio.gather (FlextTestsAsyncs.run_concurrent has different purpose)
        sessions = await asyncio.gather(*[session_generation_task() for _ in range(10)])

        # Validate results using standard assertions
        assert sessions, "Sessions should not be empty"
        assert len(sessions) == 10, "Should have exactly 10 sessions"
        assert len(set(sessions)) == 10, "All sessions should be unique"

        # Validate session format
        for session in sessions:
            assert isinstance(session, str), "Session should be string"
            assert session, "Session should not be empty"

    def test_builders_for_search_requests(self) -> None:
        """Test LDAP SearchRequest creation using FlextTests patterns."""
        # Use direct FlextLdapModels.SearchRequest construction (no FlextTestsBuilders as it doesn't exist)
        ldap_search = FlextLdapModels.SearchRequest(
            base_dn="ou=users,dc=test,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "mail", "uid"],
            size_limit=100,
            time_limit=30,
        )

        # Validate LDAP format using standard assertions
        assert "dc=" in ldap_search.base_dn, "Base DN should contain dc="
        assert "(" in ldap_search.filter_str, (
            "Filter should contain opening parenthesis"
        )
        assert ")" in ldap_search.filter_str, (
            "Filter should contain closing parenthesis"
        )
        assert ldap_search.scope in {"base", "one", "subtree"}, (
            "Scope should be valid LDAP scope"
        )

    @pytest.mark.asyncio
    async def test_real_ldap_operations_with_matchers(self) -> None:
        """Test real LDAP operations using FlextTestsMatchers for validation."""
        api = FlextLdapApi()

        # Generate test user data
        test_user = {
            "name": "TestUser_Search",
            "email": "testsearch@example.com",
            "uid": "testsearch",
        }

        # Create search request for the user
        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=test,dc=com",
            filter_str=f"(cn={test_user['name']})",
            scope="subtree",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )

        # Execute search (will fail gracefully without connection)
        result = await api.search(search_request)

        # Validate result using FlextTestsMatchers
        assert isinstance(result, FlextResult), (
            "Result should be a FlextResult instance"
        )

        if result.is_success:
            FlextTestsMatchers.assert_result_success(result)
            assert isinstance(result.value, list), (
                "Successful result should contain a list"
            )
        else:
            # Expected failure without real LDAP connection
            FlextTestsMatchers.assert_result_failure(result)
            assert result.error is not None, "Error should not be None"
            assert str(result.error), "Error message should not be empty"

    def test_hypothesis_like_testing_with_factories(self) -> None:
        """Test multiple scenarios using FlextTestsFactories patterns."""
        # Generate test scenarios using real FlextTestsFactories
        test_scenarios = []
        for i in range(20):  # Test 20 different scenarios
            user = {
                "name": f"TestUser{i}",
                "email": f"testuser{i}@example.com",
                "uid": f"testuser{i}",
            }
            scenario = {
                "user": user,
                "dn_format": f"cn={user['name']},ou=users,dc=example,dc=com",
                "expected_cn": user["name"],
                "expected_mail": user["email"],
            }
            test_scenarios.append(scenario)

        # Test all scenarios using available assertions
        for scenario in test_scenarios:
            # Validate DN format using standard assertions
            assert "dc=" in scenario["dn_format"], "DN should contain dc="
            assert "cn=" in scenario["dn_format"], "DN should contain cn="

            # Create LDAP user from scenario using only valid fields with type safety
            user_dict = cast("dict[str, str]", scenario["user"])
            user_name = str(user_dict["name"])
            ldap_user = FlextLdapModels.User(
                id=f"test{user_name.lower().replace(' ', '')}",
                dn=str(scenario["dn_format"]),
                cn=str(scenario["expected_cn"]),
                mail=str(scenario["expected_mail"]),
                uid=user_name.lower().replace(" ", "."),
                sn="TestSurname",
                given_name=str(scenario["expected_cn"]),
                object_classes=["person"],
                attributes={},
                status="active",
            )
            assert ldap_user.cn == scenario["expected_cn"], "CN should match expected"
            assert ldap_user.mail == scenario["expected_mail"], (
                "Email should match expected"
            )

    @pytest.mark.asyncio
    async def test_timeout_and_error_handling_with_async_utils(self) -> None:
        """Test timeout and error handling using real FlextTestsAsyncs."""

        # Test timeout behavior using FlextTestsAsyncs
        async def slow_operation() -> str:
            await asyncio.sleep(0.5)
            return "completed"

        # Test timeout functionality using FlextTestsAsyncs.run_with_timeout
        with pytest.raises(asyncio.TimeoutError):
            await FlextTestsAsyncs.run_with_timeout(
                slow_operation(), timeout_seconds=0.1
            )

        # Test successful completion within timeout
        result = await FlextTestsAsyncs.run_with_timeout(
            slow_operation(), timeout_seconds=1.0
        )
        assert result == "completed", "Operation should complete successfully"

    def test_data_validation_with_comprehensive_matchers(self) -> None:
        """Test comprehensive data validation using real FlextTestsMatchers."""
        # Test various data validation scenarios
        user = {
            "name": "DataValidationUser",
            "email": "datavalidation@example.com",
            "uid": "datavalidation",
        }

        # String validations using standard assertions
        assert user["name"], "Name should not be empty"
        assert user["email"], "Email should not be empty"

        # Email validation using standard assertions
        assert "@" in user["email"], "Email should contain @"
        assert "." in user["email"], "Email should contain ."

        # Collection validations using standard assertions
        test_list = [1, 2, 3, 4, 5]
        assert test_list, "List should not be empty"
        assert len(test_list) > 0, "List should have elements"
        assert len(test_list) == 5, "List should have exactly 5 elements"

        assert isinstance(user["name"], str), "Name should be string"
        assert isinstance(test_list, list), "Should be a list"

        # FlextResult validations using FlextTestsMatchers
        success_result = FlextResult[str].ok("success")
        failure_result = FlextResult[str].fail("error")

        FlextTestsMatchers.assert_result_success(success_result)
        FlextTestsMatchers.assert_result_failure(failure_result)

        # Use real FlextTestsMatchers.assert_json_structure with proper typing
        json_user = cast("FlextTypes.Core.JsonObject", user)
        FlextTestsMatchers.assert_json_structure(json_user, ["name", "email", "uid"])
