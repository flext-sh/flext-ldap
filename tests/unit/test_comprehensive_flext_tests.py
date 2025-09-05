"""Comprehensive example using flext_tests library for 100% functional testing.

This demonstrates proper usage of ALL flext_tests capabilities:
- Factories for test data generation
- Matchers for assertions
- Performance profiling
- Async utilities
- Hypothesis testing
- Builder patterns
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from flext_core import FlextResult
from flext_tests import (
    AdminUserFactory,
    AsyncTestUtils,
    FlextMatchers,
    PerformanceProfiler,
    TestBuilders,
    UserFactory,
)

from flext_ldap import FlextLDAPApi, get_flext_ldap_api
from flext_ldap.entities import FlextLDAPEntities


@pytest.mark.asyncio
class TestComprehensiveFlextTests:
    """Comprehensive flext_tests integration demonstrating ALL capabilities."""

    def test_user_factory_comprehensive(self) -> None:
        """Test UserFactory from flext_tests for LDAP user creation."""
        # Generate test users using flext_tests UserFactory
        users = UserFactory.build_batch(5)
        REDACTED_LDAP_BIND_PASSWORD_user = AdminUserFactory.build()
        
        # Validate using FlextMatchers
        assert len(users) == 5
        FlextMatchers.assert_collection_not_empty(users)
        FlextMatchers.assert_has_required_fields(REDACTED_LDAP_BIND_PASSWORD_user, ['name', 'email'])
        
        # Transform to LDAP entities
        for user in users:
            ldap_user_data = {
                'dn': f"cn={user.name},ou=users,dc=test,dc=com",
                'cn': user.name,
                'mail': user.email,
                'objectClass': ['person', 'organizationalPerson'],
                'uid': user.name.lower().replace(' ', '.'),
                'sn': user.name.split()[-1] if ' ' in user.name else user.name,
                'given_name': user.name.split()[0] if ' ' in user.name else user.name,
                'active': True,
                'groups': [],
                'created_at': None,
                'last_login': None,
                'custom_attributes': {},
                'attributes': {}
            }
            
            # Create LDAP entity using real data
            ldap_user = FlextLDAPEntities.User(**ldap_user_data)
            assert ldap_user.cn == user.name
            assert ldap_user.mail == user.email

    async def test_async_utils_with_performance_profiling(self) -> None:
        """Test AsyncTestUtils with PerformanceProfiler for LDAP operations."""
        api = get_flext_ldap_api()
        
        # Performance profiling using flext_tests
        profiler = PerformanceProfiler()
        
        async def session_generation_task() -> str:
            """Generate session ID with performance tracking."""
            with profiler.track_operation('session_generation'):
                return api._generate_session_id()
        
        # Run concurrent operations with performance tracking
        with profiler.track_operation('concurrent_sessions'):
            sessions = await AsyncTestUtils.run_concurrent([
                session_generation_task() for _ in range(10)
            ])
        
        # Validate results using FlextMatchers
        FlextMatchers.assert_collection_not_empty(sessions)
        assert len(sessions) == 10
        assert len(set(sessions)) == 10  # All unique
        
        # Performance assertions
        session_stats = profiler.get_operation_stats('session_generation')
        FlextMatchers.assert_performance_within_bounds(
            session_stats['avg_time'], 0.0, 1.0  # Should be very fast
        )

    def test_builders_for_search_requests(self) -> None:
        """Test TestBuilders for creating complex LDAP search requests."""
        # Use flext_tests TestBuilders for complex object creation
        builder = TestBuilders.FlexibleBuilder()
        
        # Build search request using builder pattern
        search_request = (builder
            .with_attribute('base_dn', 'ou=users,dc=test,dc=com')
            .with_attribute('filter_str', '(objectClass=person)')
            .with_attribute('scope', 'subtree')
            .with_attribute('attributes', ['cn', 'mail', 'uid'])
            .with_attribute('size_limit', 100)
            .with_attribute('time_limit', 30)
            .build()
        )
        
        # Transform to LDAP SearchRequest
        ldap_search = FlextLDAPEntities.SearchRequest(
            base_dn=search_request['base_dn'],
            filter_str=search_request['filter_str'],
            scope=search_request['scope'],
            attributes=search_request['attributes'],
            size_limit=search_request['size_limit'],
            time_limit=search_request['time_limit']
        )
        
        # Validate using FlextMatchers
        FlextMatchers.assert_valid_ldap_dn(ldap_search.base_dn)
        FlextMatchers.assert_valid_ldap_filter(ldap_search.filter_str)
        assert ldap_search.scope in ['base', 'one', 'subtree']

    async def test_real_ldap_operations_with_matchers(self) -> None:
        """Test real LDAP operations using FlextMatchers for validation."""
        api = get_flext_ldap_api()
        
        # Generate test user using UserFactory
        test_user = UserFactory.build()
        
        # Create search request for the user
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn='dc=test,dc=com',
            filter_str=f'(cn={test_user.name})',
            scope='subtree',
            attributes=['cn', 'mail']
        )
        
        # Execute real search (will fail gracefully without connection)
        result = await api.search(search_request)
        
        # Use FlextMatchers for result validation
        FlextMatchers.assert_is_flext_result(result)
        
        if result.is_success:
            FlextMatchers.assert_collection_type(result.value, list)
        else:
            # Expected failure without real LDAP connection
            FlextMatchers.assert_result_failure(result)
            assert result.error is not None
            FlextMatchers.assert_string_not_empty(result.error)

    def test_hypothesis_like_testing_with_factories(self) -> None:
        """Test hypothesis-like behavior using flext_tests factories."""
        # Generate multiple test scenarios using factories
        test_scenarios = []
        
        for _ in range(20):  # Test 20 different scenarios
            user = UserFactory.build()
            scenario = {
                'user': user,
                'dn_format': f"cn={user.name},ou=users,dc=example,dc=com",
                'expected_cn': user.name,
                'expected_mail': user.email
            }
            test_scenarios.append(scenario)
        
        # Test all scenarios
        for scenario in test_scenarios:
            # Validate DN format
            FlextMatchers.assert_valid_ldap_dn(scenario['dn_format'])
            
            # Create LDAP user from scenario
            user_data = {
                'dn': scenario['dn_format'],
                'cn': scenario['expected_cn'],
                'mail': scenario['expected_mail'],
                'objectClass': ['person'],
                'uid': scenario['user'].name.lower().replace(' ', '.'),
                'sn': 'TestSurname',
                'given_name': scenario['expected_cn'],
                'active': True,
                'groups': [],
                'created_at': None,
                'last_login': None,
                'custom_attributes': {},
                'attributes': {}
            }
            
            # This should not fail for any valid user
            ldap_user = FlextLDAPEntities.User(**user_data)
            assert ldap_user.cn == scenario['expected_cn']
            assert ldap_user.mail == scenario['expected_mail']

    async def test_timeout_and_error_handling_with_async_utils(self) -> None:
        """Test timeout and error handling using AsyncTestUtils."""
        # Test timeout behavior
        async def slow_operation() -> str:
            await asyncio.sleep(0.5)
            return "completed"
        
        # Test timeout functionality
        with pytest.raises(asyncio.TimeoutError):
            await AsyncTestUtils.run_with_timeout(
                slow_operation(), timeout_seconds=0.1
            )
        
        # Test successful completion within timeout
        result = await AsyncTestUtils.run_with_timeout(
            slow_operation(), timeout_seconds=1.0
        )
        assert result == "completed"

    def test_data_validation_with_comprehensive_matchers(self) -> None:
        """Test comprehensive data validation using all FlextMatchers."""
        # Test various data validation scenarios
        user = UserFactory.build()
        
        # String validations
        FlextMatchers.assert_string_not_empty(user.name)
        FlextMatchers.assert_string_not_empty(user.email)
        
        # Email validation
        FlextMatchers.assert_valid_email(user.email)
        
        # Collection validations
        test_list = [1, 2, 3, 4, 5]
        FlextMatchers.assert_collection_not_empty(test_list)
        FlextMatchers.assert_collection_size(test_list, 5)
        
        # Type validations
        FlextMatchers.assert_instance_of(user.name, str)
        FlextMatchers.assert_instance_of(test_list, list)
        
        # FlextResult validations
        success_result = FlextResult.ok("success")
        failure_result = FlextResult.fail("error")
        
        FlextMatchers.assert_result_success(success_result)
        FlextMatchers.assert_result_failure(failure_result)
        
        assert FlextMatchers.is_successful_result(success_result)
        assert FlextMatchers.is_failed_result(failure_result)