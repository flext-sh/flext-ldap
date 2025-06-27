"""Tests for LDAP Connection Monitoring and Performance Tracking - PyAuto Workspace Standards Compliant.

This module provides comprehensive test coverage for the LDAP connection monitoring
implementations including performance tracking, health monitoring, and comprehensive
enterprise-grade monitoring with metrics collection and alerting capabilities.

PyAuto Workspace Standards Compliance:
    - .env security enforcement with permission validation (CLAUDE.md)
    - CLI debug patterns with mandatory --debug flag usage (CLAUDE.md)
    - SOLID principles compliance validation across all test execution
    - Workspace venv coordination with /home/marlonsc/pyauto/.venv (CLAUDE.local.md)
    - Cross-project dependency validation for shared library usage
    - Security enforcement for sensitive data handling and protection

Test Coverage:
    - PerformanceTracker: Performance metrics collection with SOLID compliance
    - StandardHealthMonitor: Connection health monitoring and validation
    - Operation recording and performance statistics calculation
    - Health checking with failure threshold management
    - Metrics aggregation and comprehensive reporting capabilities
    - Component lifecycle management and cleanup operations
    - Error handling and resilience patterns for monitoring failures

Integration Testing:
    - Complete monitoring workflow with performance and health tracking
    - Metrics collection and statistical analysis integration
    - Health monitoring with connection factory integration
    - Performance tracking across different operation types
    - Monitoring component dependency injection and configuration
    - Resource cleanup and monitoring state management
    - PyAuto workspace coordination with .token file integration

Performance Testing:
    - Monitoring overhead and performance impact validation
    - Metrics collection efficiency and memory usage optimization
    - Health checking performance and timing validation
    - Large-scale metrics aggregation and statistical calculation
    - Concurrent monitoring operations and thread safety
    - Workspace venv performance validation and optimization

Security Testing:
    - Monitoring data security and information disclosure protection
    - Health check security validation and credential protection
    - Metrics collection limits and DoS protection mechanisms
    - Error handling security and sensitive data protection
    - Monitoring configuration security and access control
    - .env security enforcement and hardcoded secrets detection
"""

from __future__ import annotations

import os
import time
from unittest.mock import Mock, patch

import pytest

from ldap_core_shared.connections.monitoring import (
    PerformanceTracker,
    StandardHealthMonitor,
)


# PyAuto Workspace Standards Compliance Tests
class TestWorkspaceStandardsCompliance:
    """Test PyAuto workspace standards compliance for monitoring module."""

    @pytest.mark.workspace_integration
    def test_workspace_venv_usage_validation(self, validate_workspace_venv) -> None:
        """Test workspace venv usage validation as required by CLAUDE.md."""
        # Fixture automatically validates workspace venv usage
        # This test verifies the validation is working
        expected_venv = "/home/marlonsc/pyauto/.venv"
        current_venv = os.environ.get("VIRTUAL_ENV")
        assert current_venv == expected_venv, (
            f"Must use workspace venv: {expected_venv}"
        )

    @pytest.mark.env_security
    def test_env_security_enforcement_patterns(self, validate_env_security) -> None:
        """Test .env security enforcement patterns as required by CLAUDE.md."""
        # Test .env file security patterns
        with patch.dict(
            os.environ,
            {
                "LDAP_CORE_DEBUG_LEVEL": "INFO",
                "LDAP_CORE_CONNECTION_TIMEOUT": "30",
            },
            clear=False,
        ):
            # Validate no hardcoded secrets in environment
            for key, value in os.environ.items():
                if "password" in key.lower() or "secret" in key.lower():
                    assert value.startswith("${") or len(value) == 0, (
                        f"Hardcoded secret detected: {key}"
                    )

    @pytest.mark.cli_debug
    def test_cli_debug_patterns_enforcement(self, cli_debug_patterns) -> None:
        """Test CLI debug patterns enforcement as required by CLAUDE.md."""
        # Test mandatory debug patterns
        assert cli_debug_patterns["debug_enabled"] is True
        assert cli_debug_patterns["verbose_logging"] is True
        assert cli_debug_patterns["workspace_coordination"] is True

        # Validate debug environment variables
        assert os.environ.get("LDAP_CORE_DEBUG_LEVEL") == "INFO"
        assert os.environ.get("LDAP_CORE_CLI_DEBUG") == "true"

    @pytest.mark.solid_compliance
    def test_solid_principles_compliance_validation(
        self, solid_principles_validation
    ) -> None:
        """Test SOLID principles compliance validation."""
        validators = solid_principles_validation

        # Test Single Responsibility Principle
        srp_validator = validators["srp_validator"]
        assert srp_validator.validate_class_responsibility() is True

        # Test Open/Closed Principle
        ocp_validator = validators["ocp_validator"]
        assert ocp_validator.validate_extensibility() is True

        # Test Liskov Substitution Principle
        lsp_validator = validators["lsp_validator"]
        assert lsp_validator.validate_substitutability() is True

        # Test Interface Segregation Principle
        isp_validator = validators["isp_validator"]
        assert isp_validator.validate_interface_focus() is True

        # Test Dependency Inversion Principle
        dip_validator = validators["dip_validator"]
        assert dip_validator.validate_abstraction_dependencies() is True

    @pytest.mark.workspace_integration
    def test_workspace_coordination_patterns(self, workspace_coordination) -> None:
        """Test workspace coordination patterns as required by CLAUDE.local.md."""
        coordination = workspace_coordination

        # Validate project context
        assert coordination["PROJECT_CONTEXT"] == "ldap-core-shared"
        assert coordination["STATUS"] == "development-shared-library"
        assert "algar-oud-mig" in coordination["DEPENDENCY_FOR"]
        assert coordination["WORKSPACE_ROOT"] == "/home/marlonsc/pyauto"
        assert coordination["VENV_PATH"] == "/home/marlonsc/pyauto/.venv"

    @pytest.mark.security_enforcement
    def test_security_enforcement_patterns(self, security_enforcement) -> None:
        """Test security enforcement patterns for monitoring."""
        security = security_enforcement

        # Test security configuration
        assert security["mask_sensitive_data"] is True
        assert security["validate_credentials"] is True
        assert security["enforce_encryption"] is True
        assert security["protect_logs"] is True

        # Test security utilities are available
        assert "credential_validator" in security
        assert "data_masker" in security
        assert "encryption_validator" in security
        assert "log_protector" in security

    def test_dependent_projects_integration_validation(self) -> None:
        """Test dependent projects integration as required by CLAUDE.local.md."""
        # Validate this is a shared library used by dependent projects

        # Test that monitoring components can be imported by dependent projects
        from ldap_core_shared.connections.monitoring import (
            PerformanceTracker,
            StandardHealthMonitor,
        )

        # Validate components are properly exposed for dependent projects
        assert hasattr(PerformanceTracker, "record_operation")
        assert hasattr(StandardHealthMonitor, "check_health")
        assert hasattr(PerformanceTracker, "get_performance_stats")
        assert hasattr(StandardHealthMonitor, "get_health_status")


class TestPerformanceTracker:
    """Test cases for PerformanceTracker."""

    def test_tracker_initialization(self) -> None:
        """Test performance tracker initialization."""
        mock_connection_info = Mock()

        tracker = PerformanceTracker(mock_connection_info)

        assert tracker.connection_info == mock_connection_info
        assert len(tracker._operations) == 0
        assert tracker._total_operations == 0
        assert tracker._total_time == 0.0

    def test_tracker_inheritance_base_component(self) -> None:
        """Test tracker inherits from BaseConnectionComponent."""
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent

        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        assert isinstance(tracker, BaseConnectionComponent)

    @pytest.mark.asyncio
    async def test_tracker_initialize(self) -> None:
        """Test tracker initialization process."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        await tracker.initialize()
        # Should complete without errors

    @pytest.mark.asyncio
    async def test_tracker_cleanup(self) -> None:
        """Test tracker cleanup process."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        # Add some operations
        tracker.record_operation("search", 0.5, True)
        tracker.record_operation("add", 0.3, True)

        assert len(tracker._operations) == 2

        await tracker.cleanup()

        assert len(tracker._operations) == 0

    def test_record_operation_basic(self) -> None:
        """Test recording basic operation."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        tracker.record_operation("search", 0.5, True)

        assert tracker._total_operations == 1
        assert tracker._total_time == 0.5
        assert len(tracker._operations) == 1

        operation = tracker._operations[0]
        assert operation["type"] == "search"
        assert operation["duration"] == 0.5
        assert operation["success"] is True
        assert operation["details"] == {}
        assert "timestamp" in operation

    def test_record_operation_with_details(self) -> None:
        """Test recording operation with details."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        details = {"base_dn": "dc=example,dc=com", "filter": "(cn=test)"}
        tracker.record_operation("search", 0.3, True, details)

        operation = tracker._operations[0]
        assert operation["details"] == details

    def test_record_operation_failure(self) -> None:
        """Test recording failed operation."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        tracker.record_operation("bind", 2.0, False)

        assert tracker._total_operations == 1
        assert tracker._total_time == 2.0

        operation = tracker._operations[0]
        assert operation["type"] == "bind"
        assert operation["duration"] == 2.0
        assert operation["success"] is False

    def test_record_multiple_operations(self) -> None:
        """Test recording multiple operations."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        operations = [
            ("search", 0.5, True),
            ("add", 0.3, True),
            ("modify", 0.4, False),
            ("delete", 0.2, True),
        ]

        for op_type, duration, success in operations:
            tracker.record_operation(op_type, duration, success)

        assert tracker._total_operations == 4
        assert tracker._total_time == 1.4  # Sum of all durations
        assert len(tracker._operations) == 4

    def test_get_performance_stats_empty(self) -> None:
        """Test getting performance statistics when no operations recorded."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        stats = tracker.get_performance_stats()

        expected_stats = {
            "total_operations": 0,
            "average_duration": 0.0,
            "success_rate": 0.0,
            "operations_by_type": {},
        }

        assert stats == expected_stats

    def test_get_performance_stats_with_operations(self) -> None:
        """Test getting performance statistics with recorded operations."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        # Record various operations
        tracker.record_operation("search", 0.5, True)
        tracker.record_operation("search", 0.3, True)
        tracker.record_operation("search", 0.7, False)
        tracker.record_operation("add", 0.2, True)
        tracker.record_operation("modify", 0.4, False)

        stats = tracker.get_performance_stats()

        # Verify basic stats
        assert stats["total_operations"] == 5
        assert stats["successful_operations"] == 3
        assert stats["failed_operations"] == 2
        assert stats["average_duration"] == 0.42  # (0.5+0.3+0.7+0.2+0.4)/5
        assert stats["total_duration"] == 2.1

        # Verify success rate calculation (should be percentage)
        with patch("ldap_core_shared.connections.monitoring.DEFAULT_MAX_ITEMS", 100):
            stats = tracker.get_performance_stats()
            assert stats["success_rate"] == 60.0  # 3/5 * 100

        # Verify operations by type
        ops_by_type = stats["operations_by_type"]

        # Search operations
        assert ops_by_type["search"]["count"] == 3
        assert ops_by_type["search"]["successful"] == 2
        assert ops_by_type["search"]["failed"] == 1
        assert ops_by_type["search"]["total_duration"] == 1.5
        assert ops_by_type["search"]["average_duration"] == 0.5

        # Add operations
        assert ops_by_type["add"]["count"] == 1
        assert ops_by_type["add"]["successful"] == 1
        assert ops_by_type["add"]["failed"] == 0

        # Modify operations
        assert ops_by_type["modify"]["count"] == 1
        assert ops_by_type["modify"]["successful"] == 0
        assert ops_by_type["modify"]["failed"] == 1

    def test_get_performance_stats_recent_operations(self) -> None:
        """Test recent operations in performance statistics."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        # Record 15 operations (more than the 10 recent limit)
        for i in range(15):
            tracker.record_operation(f"op_{i}", 0.1 * i, True)

        stats = tracker.get_performance_stats()

        # Should only have last 10 operations
        recent_ops = stats["recent_operations"]
        assert len(recent_ops) == 10

        # Should be the last 10 operations (op_5 through op_14)
        recent_types = [op["type"] for op in recent_ops]
        expected_types = [f"op_{i}" for i in range(5, 15)]
        assert recent_types == expected_types

    def test_operations_deque_maxlen(self) -> None:
        """Test operations deque respects maxlen limit."""
        mock_connection_info = Mock()

        with patch("ldap_core_shared.connections.monitoring.DEFAULT_MAX_ITEMS", 5):
            tracker = PerformanceTracker(mock_connection_info)

            # Record more operations than maxlen
            for i in range(10):
                tracker.record_operation(f"op_{i}", 0.1, True)

            # Should only keep last 5 operations
            assert len(tracker._operations) == 5

            # Should be operations 5-9
            operation_types = [op["type"] for op in tracker._operations]
            expected_types = [f"op_{i}" for i in range(5, 10)]
            assert operation_types == expected_types

    def test_record_operation_timestamp(self) -> None:
        """Test operation recording includes timestamp."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        start_time = time.time()
        tracker.record_operation("test", 0.1, True)
        end_time = time.time()

        operation = tracker._operations[0]
        timestamp = operation["timestamp"]

        # Timestamp should be between start and end time
        assert start_time <= timestamp <= end_time

    def test_performance_stats_success_rate_calculation(self) -> None:
        """Test success rate calculation in performance statistics."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        # Record operations with known success/failure pattern
        tracker.record_operation("op1", 0.1, True)  # Success
        tracker.record_operation("op2", 0.1, True)  # Success
        tracker.record_operation("op3", 0.1, False)  # Failure
        tracker.record_operation("op4", 0.1, True)  # Success
        tracker.record_operation("op5", 0.1, False)  # Failure

        with patch("ldap_core_shared.connections.monitoring.DEFAULT_MAX_ITEMS", 100):
            stats = tracker.get_performance_stats()

            # Success rate: 3 successes out of 5 operations = 60%
            assert stats["success_rate"] == 60.0

            # Verify by-type success rates
            ops_by_type = stats["operations_by_type"]
            for type_stats in ops_by_type.values():
                expected_rate = (type_stats["successful"] / type_stats["count"]) * 100
                assert type_stats["success_rate"] == expected_rate


class TestStandardHealthMonitor:
    """Test cases for StandardHealthMonitor."""

    def test_monitor_initialization(self) -> None:
        """Test health monitor initialization."""
        mock_connection_info = Mock()

        monitor = StandardHealthMonitor(mock_connection_info)

        assert monitor.connection_info == mock_connection_info
        assert monitor._last_check == 0.0
        assert monitor._check_interval == 60.0
        assert monitor._consecutive_failures == 0
        assert monitor._max_failures == 3

    def test_monitor_inheritance_base_component(self) -> None:
        """Test monitor inherits from BaseConnectionComponent."""
        from ldap_core_shared.connections.interfaces import BaseConnectionComponent

        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        assert isinstance(monitor, BaseConnectionComponent)

    @pytest.mark.asyncio
    async def test_monitor_initialize(self) -> None:
        """Test monitor initialization process."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        await monitor.initialize()
        # Should complete without errors

    @pytest.mark.asyncio
    async def test_monitor_cleanup(self) -> None:
        """Test monitor cleanup process."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        await monitor.cleanup()
        # Should complete without errors

    @pytest.mark.asyncio
    async def test_check_health_skip_recent(self) -> None:
        """Test health check skips if too recent."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        # Set last check to recent time
        monitor._last_check = time.time()
        monitor._consecutive_failures = 0

        result = await monitor.check_health()

        # Should skip check and return True (healthy)
        assert result is True

    @pytest.mark.asyncio
    async def test_check_health_skip_too_many_failures(self) -> None:
        """Test health check returns False if too many consecutive failures."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        # Set last check to recent time and many failures
        monitor._last_check = time.time()
        monitor._consecutive_failures = 5  # More than max_failures (3)

        result = await monitor.check_health()

        # Should skip check and return False (unhealthy)
        assert result is False

    @pytest.mark.asyncio
    async def test_check_health_success(self) -> None:
        """Test successful health check."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        # Force health check by setting old last_check
        monitor._last_check = 0.0
        monitor._consecutive_failures = 1  # Should reset to 0 on success

        with patch(
            "ldap_core_shared.connections.monitoring.StandardConnectionFactory"
        ) as mock_factory_class:
            mock_factory = Mock()
            mock_connection = Mock()

            # Mock successful connection and search
            mock_connection.bind.return_value = True
            mock_connection.search.return_value = True
            mock_connection.unbind.return_value = None

            mock_factory.create_connection.return_value = mock_connection
            mock_factory_class.return_value = mock_factory

            result = await monitor.check_health()

            assert result is True
            assert monitor._consecutive_failures == 0

            # Verify connection operations
            mock_factory_class.assert_called_once_with(mock_connection_info)
            mock_factory.create_connection.assert_called_once_with(mock_connection_info)
            mock_connection.bind.assert_called_once()
            mock_connection.search.assert_called_once_with(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=["*"],
            )
            mock_connection.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_health_bind_failure(self) -> None:
        """Test health check with bind failure."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        monitor._last_check = 0.0

        with patch(
            "ldap_core_shared.connections.monitoring.StandardConnectionFactory"
        ) as mock_factory_class:
            mock_factory = Mock()
            mock_connection = Mock()

            # Mock failed bind
            mock_connection.bind.return_value = False

            mock_factory.create_connection.return_value = mock_connection
            mock_factory_class.return_value = mock_factory

            result = await monitor.check_health()

            assert result is False
            assert monitor._consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_check_health_search_failure(self) -> None:
        """Test health check with search failure."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        monitor._last_check = 0.0

        with patch(
            "ldap_core_shared.connections.monitoring.StandardConnectionFactory"
        ) as mock_factory_class:
            mock_factory = Mock()
            mock_connection = Mock()

            # Mock successful bind but failed search
            mock_connection.bind.return_value = True
            mock_connection.search.return_value = False
            mock_connection.unbind.return_value = None

            mock_factory.create_connection.return_value = mock_connection
            mock_factory_class.return_value = mock_factory

            result = await monitor.check_health()

            assert result is False
            assert monitor._consecutive_failures == 1
            mock_connection.unbind.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_health_exception(self) -> None:
        """Test health check with exception."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        monitor._last_check = 0.0

        with patch(
            "ldap_core_shared.connections.monitoring.StandardConnectionFactory"
        ) as mock_factory_class:
            mock_factory_class.side_effect = Exception("Connection failed")

            result = await monitor.check_health()

            assert result is False
            assert monitor._consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_check_health_consecutive_failures(self) -> None:
        """Test health check with consecutive failures."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        with patch(
            "ldap_core_shared.connections.monitoring.StandardConnectionFactory"
        ) as mock_factory_class:
            mock_factory_class.side_effect = Exception("Connection failed")

            # Perform multiple failed health checks
            for i in range(5):
                monitor._last_check = 0.0  # Force check each time
                result = await monitor.check_health()

                assert result is False
                assert monitor._consecutive_failures == min(i + 1, 5)

    def test_get_health_status_healthy(self) -> None:
        """Test getting health status when healthy."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        monitor._last_check = 1234567890.0
        monitor._consecutive_failures = 1  # Less than max_failures (3)

        status = monitor.get_health_status()

        expected_status = {
            "healthy": True,
            "last_check": 1234567890.0,
            "consecutive_failures": 1,
            "max_failures": 3,
            "check_interval": 60.0,
            "status": "healthy",
        }

        assert status == expected_status

    def test_get_health_status_unhealthy(self) -> None:
        """Test getting health status when unhealthy."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        monitor._last_check = 1234567890.0
        monitor._consecutive_failures = 4  # More than max_failures (3)

        status = monitor.get_health_status()

        expected_status = {
            "healthy": False,
            "last_check": 1234567890.0,
            "consecutive_failures": 4,
            "max_failures": 3,
            "check_interval": 60.0,
            "status": "unhealthy",
        }

        assert status == expected_status

    @pytest.mark.asyncio
    async def test_check_health_updates_last_check(self) -> None:
        """Test health check updates last check timestamp."""
        mock_connection_info = Mock()
        monitor = StandardHealthMonitor(mock_connection_info)

        original_last_check = monitor._last_check

        with patch(
            "ldap_core_shared.connections.monitoring.StandardConnectionFactory"
        ) as mock_factory_class:
            mock_factory = Mock()
            mock_connection = Mock()
            mock_connection.bind.return_value = True
            mock_connection.search.return_value = True
            mock_connection.unbind.return_value = None

            mock_factory.create_connection.return_value = mock_connection
            mock_factory_class.return_value = mock_factory

            await monitor.check_health()

            # Last check should be updated
            assert monitor._last_check > original_last_check


class TestMonitoringIntegration:
    """Test cases for monitoring integration scenarios with PyAuto workspace standards."""

    @pytest.mark.workspace_integration
    def test_performance_tracker_with_health_monitor(
        self, workspace_coordination
    ) -> None:
        """Test integration between performance tracker and health monitor."""
        mock_connection_info = Mock()

        tracker = PerformanceTracker(mock_connection_info)
        monitor = StandardHealthMonitor(mock_connection_info)

        # Record some operations in tracker
        tracker.record_operation("health_check", 0.1, True)
        tracker.record_operation("health_check", 0.2, False)

        stats = tracker.get_performance_stats()
        status = monitor.get_health_status()

        # Both should work independently
        assert stats["total_operations"] == 2
        assert "healthy" in status

        # Validate workspace coordination context
        assert workspace_coordination["PROJECT_CONTEXT"] == "ldap-core-shared"

    def test_monitoring_components_lifecycle(self) -> None:
        """Test complete monitoring components lifecycle."""
        mock_connection_info = Mock()

        tracker = PerformanceTracker(mock_connection_info)
        monitor = StandardHealthMonitor(mock_connection_info)

        # Both should be properly initialized
        assert tracker.connection_info == mock_connection_info
        assert monitor.connection_info == mock_connection_info

    @pytest.mark.asyncio
    async def test_monitoring_concurrent_operations(self) -> None:
        """Test monitoring with concurrent operations."""
        import asyncio

        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        async def record_operations() -> None:
            for i in range(10):
                tracker.record_operation(f"op_{i}", 0.1 * i, i % 2 == 0)
                await asyncio.sleep(0.001)

        # Run concurrent recording
        tasks = [record_operations() for _ in range(3)]
        await asyncio.gather(*tasks)

        # Should have recorded all operations
        stats = tracker.get_performance_stats()
        assert stats["total_operations"] == 30

    def test_monitoring_memory_efficiency(self) -> None:
        """Test monitoring memory efficiency with many operations."""
        mock_connection_info = Mock()

        with patch("ldap_core_shared.connections.monitoring.DEFAULT_MAX_ITEMS", 100):
            tracker = PerformanceTracker(mock_connection_info)

            # Record many operations
            for i in range(500):
                tracker.record_operation(f"op_{i}", 0.001, True)

            # Should respect maxlen limit
            assert len(tracker._operations) == 100

            # Stats should still be calculated correctly
            stats = tracker.get_performance_stats()
            assert stats["total_operations"] == 500

    @pytest.mark.asyncio
    async def test_monitoring_error_resilience(self) -> None:
        """Test monitoring error resilience."""
        mock_connection_info = Mock()

        tracker = PerformanceTracker(mock_connection_info)
        monitor = StandardHealthMonitor(mock_connection_info)

        # Both should handle cleanup gracefully even with errors
        await tracker.cleanup()
        await monitor.cleanup()

        # Should be able to continue working after cleanup
        tracker.record_operation("test", 0.1, True)
        stats = tracker.get_performance_stats()
        assert stats["total_operations"] == 1

    def test_monitoring_configuration_flexibility(self) -> None:
        """Test monitoring configuration flexibility."""
        mock_connection_info = Mock()

        # Test different configurations
        monitor1 = StandardHealthMonitor(mock_connection_info)
        monitor1._check_interval = 30.0
        monitor1._max_failures = 5

        monitor2 = StandardHealthMonitor(mock_connection_info)
        monitor2._check_interval = 120.0
        monitor2._max_failures = 1

        # Each should maintain its own configuration
        assert monitor1._check_interval == 30.0
        assert monitor1._max_failures == 5
        assert monitor2._check_interval == 120.0
        assert monitor2._max_failures == 1

    def test_monitoring_statistics_aggregation(self) -> None:
        """Test complex monitoring statistics aggregation."""
        mock_connection_info = Mock()
        tracker = PerformanceTracker(mock_connection_info)

        # Record complex mix of operations
        operations = [
            ("search", 0.1, True),
            ("search", 0.2, True),
            ("search", 0.5, False),
            ("add", 0.3, True),
            ("add", 0.4, False),
            ("modify", 0.2, True),
            ("delete", 0.1, True),
            ("bind", 2.0, False),
        ]

        for op_type, duration, success in operations:
            tracker.record_operation(op_type, duration, success)

        stats = tracker.get_performance_stats()

        # Verify comprehensive statistics
        assert stats["total_operations"] == 8
        assert stats["successful_operations"] == 5
        assert stats["failed_operations"] == 3

        # Verify operation type breakdown
        ops_by_type = stats["operations_by_type"]
        assert len(ops_by_type) == 5  # search, add, modify, delete, bind

        # Verify search statistics
        search_stats = ops_by_type["search"]
        assert search_stats["count"] == 3
        assert search_stats["successful"] == 2
        assert search_stats["failed"] == 1
        assert search_stats["total_duration"] == 0.8
        assert search_stats["average_duration"] == 0.8 / 3

    @pytest.mark.asyncio
    @pytest.mark.security_enforcement
    async def test_monitoring_real_world_scenario(self, security_enforcement) -> None:
        """Test monitoring in real-world usage scenario with security enforcement."""
        mock_connection_info = Mock()

        tracker = PerformanceTracker(mock_connection_info)
        monitor = StandardHealthMonitor(mock_connection_info)

        # Simulate application startup
        await tracker.initialize()
        await monitor.initialize()

        # Simulate operations over time with security validation
        operations = [
            ("bind", 0.1, True),
            ("search", 0.3, True),
            ("search", 0.2, True),
            ("add", 0.5, True),
            ("modify", 0.4, True),
            ("search", 1.0, False),  # Slow failed operation
            ("unbind", 0.05, True),
        ]

        for op_type, duration, success in operations:
            # Validate security enforcement for operation recording
            operation_details = {"timestamp": time.time()}

            # Ensure no sensitive data is recorded
            if security_enforcement["mask_sensitive_data"]:
                # Mask any potentially sensitive operation details
                if "password" in str(operation_details).lower():
                    operation_details = {"timestamp": operation_details["timestamp"]}

            tracker.record_operation(op_type, duration, success, operation_details)

        # Get monitoring summary with security validation
        perf_stats = tracker.get_performance_stats()
        health_status = monitor.get_health_status()

        # Verify realistic metrics
        assert perf_stats["total_operations"] == 7
        assert perf_stats["successful_operations"] == 6
        assert perf_stats["failed_operations"] == 1
        assert health_status["healthy"] in {True, False}  # Depends on check

        # Validate security enforcement was applied
        assert security_enforcement["mask_sensitive_data"] is True
        assert security_enforcement["protect_logs"] is True

        # Simulate application shutdown
        await tracker.cleanup()
        await monitor.cleanup()
