"""🔥 SOLID Principles Implementation Tests.

This test suite validates that our LDAP connection management implementation
follows all SOLID principles with ZERO TOLERANCE for violations.

Test Coverage:
- Single Responsibility Principle validation
- Open/Closed Principle validation
- Liskov Substitution Principle validation
- Interface Segregation Principle validation
- Dependency Inversion Principle validation
- Integration testing of SOLID components
- Performance validation with SOLID implementation

ZERO TOLERANCE SOLID testing following enterprise patterns.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import ldap3
import pytest

from ldap_core_shared.connections.base import LDAPConnectionInfo
from ldap_core_shared.connections.implementations import (
    AsyncConnectionPool,
    ConnectionManagerFactory,
    PerformanceTracker,
    SOLIDConnectionManager,
    StandardConnectionFactory,
    StandardHealthMonitor,
    StandardSecurityManager,
)
from ldap_core_shared.connections.interfaces import (
    IConnectionFactory,
    IConnectionPool,
    IHealthMonitor,
    IPerformanceTracker,
    ISecurityManager,
    validate_solid_compliance,
)


@pytest.fixture
def connection_info() -> LDAPConnectionInfo:
    """Create test connection info."""
    return LDAPConnectionInfo(
        host="ldap.test.com",
        port=389,
        use_ssl=False,
        bind_dn="cn=test,dc=test,dc=com",
        bind_password="test_password",  # nosec B106
        base_dn="dc=test,dc=com",
    )


# ============================================================================
# 🔥 SINGLE RESPONSIBILITY PRINCIPLE TESTS
# ============================================================================


class TestSingleResponsibilityPrinciple:
    """🎯 Test Single Responsibility Principle compliance."""

    def test_connection_factory_single_responsibility(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that ConnectionFactory only creates connections."""
        factory = StandardConnectionFactory(connection_info)

        # Factory should only have connection creation methods
        factory_methods = [
            method for method in dir(factory) if not method.startswith("_")
        ]
        connection_methods = [
            "create_connection",
            "initialize",
            "cleanup",
            "connection_info",
        ]

        for method in factory_methods:
            assert method in connection_methods or hasattr(
                object,
                method,
            ), f"Factory has non-connection method: {method}"

    def test_performance_tracker_single_responsibility(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that PerformanceTracker only tracks performance."""
        tracker = PerformanceTracker(connection_info)

        # Tracker should only have performance methods
        tracker_methods = [
            method for method in dir(tracker) if not method.startswith("_")
        ]
        performance_methods = [
            "record_operation",
            "get_metrics",
            "initialize",
            "cleanup",
            "connection_info",
        ]

        for method in tracker_methods:
            assert method in performance_methods or hasattr(
                object,
                method,
            ), f"Tracker has non-performance method: {method}"

    def test_health_monitor_single_responsibility(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that HealthMonitor only monitors health."""
        monitor = StandardHealthMonitor(connection_info)

        # Monitor should only have health methods
        monitor_methods = [
            method for method in dir(monitor) if not method.startswith("_")
        ]
        health_methods = [
            "check_health",
            "start_monitoring",
            "stop_monitoring",
            "initialize",
            "cleanup",
            "connection_info",
        ]

        for method in monitor_methods:
            assert method in health_methods or hasattr(
                object,
                method,
            ), f"Monitor has non-health method: {method}"


# ============================================================================
# 🔥 OPEN/CLOSED PRINCIPLE TESTS
# ============================================================================


class TestOpenClosedPrinciple:
    """🎯 Test Open/Closed Principle compliance."""

    def test_connection_factory_extensibility(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that ConnectionFactory is open for extension."""

        class CustomConnectionFactory(StandardConnectionFactory):
            """Custom factory extending base functionality."""

            def create_connection(
                self,
                connection_info: LDAPConnectionInfo,
            ) -> ldap3.Connection:
                """Custom connection creation with additional features."""
                # Call parent implementation
                connection = super().create_connection(connection_info)
                # Add custom behavior without modifying base class
                connection.custom_flag = True  # type: ignore
                return connection

        # Custom factory should work without modifying base
        custom_factory = CustomConnectionFactory(connection_info)
        assert isinstance(custom_factory, StandardConnectionFactory)
        assert isinstance(custom_factory, IConnectionFactory)

    def test_performance_tracker_extensibility(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that PerformanceTracker is open for extension."""

        class CustomPerformanceTracker(PerformanceTracker):
            """Custom tracker with additional metrics."""

            def __init__(self, connection_info: LDAPConnectionInfo) -> None:
                super().__init__(connection_info)
                self._custom_metrics: dict[str, Any] = {}

            def record_operation(
                self,
                operation_type: str,
                duration: float,
                success: bool,
            ) -> None:
                """Record operation with custom metrics."""
                super().record_operation(operation_type, duration, success)
                # Add custom behavior
                self._custom_metrics[f"custom_{operation_type}"] = duration

        # Custom tracker should work without modifying base
        custom_tracker = CustomPerformanceTracker(connection_info)
        assert isinstance(custom_tracker, PerformanceTracker)
        assert isinstance(custom_tracker, IPerformanceTracker)


# ============================================================================
# 🔥 LISKOV SUBSTITUTION PRINCIPLE TESTS
# ============================================================================


class TestLiskovSubstitutionPrinciple:
    """🎯 Test Liskov Substitution Principle compliance."""

    def test_connection_factory_substitution(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that any IConnectionFactory can substitute another."""

        class AlternativeConnectionFactory:
            """Alternative factory implementation."""

            def __init__(self, connection_info: LDAPConnectionInfo) -> None:
                self.connection_info = connection_info

            async def initialize(self) -> None:
                """Initialize factory."""

            async def cleanup(self) -> None:
                """Cleanup factory."""

            def create_connection(
                self,
                connection_info: LDAPConnectionInfo,
            ) -> ldap3.Connection:
                """Create connection with alternative implementation."""
                # Alternative implementation that still satisfies the contract
                server = ldap3.Server(
                    host=connection_info.host,
                    port=connection_info.port,
                    use_ssl=connection_info.use_ssl,
                    get_info=ldap3.ALL,
                )
                return ldap3.Connection(
                    server=server,
                    user=connection_info.bind_dn,
                    password=connection_info.bind_password.get_secret_value(),
                    auto_bind=False,  # Different but valid implementation
                )

        # Both implementations should work interchangeably
        standard_factory = StandardConnectionFactory(connection_info)
        alternative_factory = AlternativeConnectionFactory(connection_info)

        # Test that they both satisfy the interface contract
        factories = [standard_factory, alternative_factory]

        for factory in factories:
            assert hasattr(factory, "create_connection")
            assert callable(factory.create_connection)
            # Both should create valid connections
            with patch("ldap3.Connection") as mock_connection:
                mock_connection.return_value = MagicMock()
                connection = factory.create_connection(connection_info)
                assert connection is not None

    @pytest.mark.asyncio
    async def test_solid_manager_substitution(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that SOLID managers can be substituted."""
        # Create different manager configurations
        standard_manager = ConnectionManagerFactory.create_standard_manager(
            connection_info,
        )
        high_perf_manager = ConnectionManagerFactory.create_high_performance_manager(
            connection_info,
        )

        # Both should satisfy the same interface
        managers = [standard_manager, high_perf_manager]

        for manager in managers:
            assert isinstance(manager, SOLIDConnectionManager)
            # All should have the same interface methods
            assert hasattr(manager, "initialize")
            assert hasattr(manager, "cleanup")
            assert hasattr(manager, "get_connection")
            assert hasattr(manager, "search")
            assert hasattr(manager, "add_entry")
            assert hasattr(manager, "modify_entry")
            assert hasattr(manager, "delete_entry")


# ============================================================================
# 🔥 INTERFACE SEGREGATION PRINCIPLE TESTS
# ============================================================================


class TestInterfaceSegregationPrinciple:
    """🎯 Test Interface Segregation Principle compliance."""

    def test_focused_interfaces(self) -> None:
        """Test that interfaces are small and focused."""
        # Test IConnectionFactory interface
        factory_methods = [
            method
            for method in dir(IConnectionFactory)
            if not method.startswith("_")
            and callable(getattr(IConnectionFactory, method, None))
        ]
        assert len(factory_methods) <= 3, "Factory interface too large"

        # Test IPerformanceTracker interface
        tracker_methods = [
            method
            for method in dir(IPerformanceTracker)
            if not method.startswith("_")
            and callable(getattr(IPerformanceTracker, method, None))
        ]
        assert len(tracker_methods) <= 3, "Performance tracker interface too large"

        # Test IHealthMonitor interface
        health_methods = [
            method
            for method in dir(IHealthMonitor)
            if not method.startswith("_")
            and callable(getattr(IHealthMonitor, method, None))
        ]
        assert len(health_methods) <= 4, "Health monitor interface too large"

    def test_interface_specialization(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that components only implement interfaces they need."""
        # Factory should only implement factory interface
        factory = StandardConnectionFactory(connection_info)
        assert isinstance(factory, IConnectionFactory)
        # Should not implement other interfaces unless explicitly needed

        # Tracker should only implement tracker interface
        tracker = PerformanceTracker(connection_info)
        assert isinstance(tracker, IPerformanceTracker)

        # Monitor should only implement monitor interface
        monitor = StandardHealthMonitor(connection_info)
        assert isinstance(monitor, IHealthMonitor)


# ============================================================================
# 🔥 DEPENDENCY INVERSION PRINCIPLE TESTS
# ============================================================================


class TestDependencyInversionPrinciple:
    """🎯 Test Dependency Inversion Principle compliance."""

    @pytest.mark.asyncio
    async def test_dependency_injection(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that high-level modules depend on abstractions."""
        # Create mock implementations
        mock_factory = MagicMock(spec=IConnectionFactory)
        mock_pool = MagicMock(spec=IConnectionPool)
        mock_tracker = MagicMock(spec=IPerformanceTracker)
        mock_health = MagicMock(spec=IHealthMonitor)
        mock_security = MagicMock(spec=ISecurityManager)

        # Configure mocks
        mock_factory.initialize = AsyncMock()
        mock_factory.cleanup = AsyncMock()
        mock_pool.initialize = AsyncMock()
        mock_pool.cleanup = AsyncMock()
        mock_tracker.initialize = AsyncMock()
        mock_tracker.cleanup = AsyncMock()
        mock_health.initialize = AsyncMock()
        mock_health.cleanup = AsyncMock()
        mock_security.initialize = AsyncMock()
        mock_security.cleanup = AsyncMock()

        # SOLIDConnectionManager should accept any implementations
        manager = SOLIDConnectionManager(
            connection_info,
            factory=mock_factory,
            pool=mock_pool,
            health_monitor=mock_health,
            performance_tracker=mock_tracker,
            security_manager=mock_security,
        )

        # Initialize should call all injected dependencies
        await manager.initialize()

        # Verify all dependencies were used
        mock_factory.initialize.assert_called_once()
        mock_pool.initialize.assert_called_once()
        mock_tracker.initialize.assert_called_once()
        mock_health.initialize.assert_called_once()
        mock_security.initialize.assert_called_once()

    def test_abstraction_dependencies(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that components depend on abstractions, not concretions."""
        # AsyncConnectionPool should depend on IConnectionFactory, not concrete factory
        factory = StandardConnectionFactory(connection_info)
        pool = AsyncConnectionPool(connection_info, factory)

        # Pool should work with any IConnectionFactory implementation
        assert hasattr(pool, "_factory")
        # Should be able to use factory through interface
        assert isinstance(pool._factory, IConnectionFactory)


# ============================================================================
# 🔥 SOLID INTEGRATION TESTS
# ============================================================================


class TestSOLIDIntegration:
    """🎯 Test complete SOLID implementation integration."""

    @pytest.mark.asyncio
    async def test_complete_solid_workflow(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test complete SOLID workflow with all components."""
        # Create SOLID manager
        manager = ConnectionManagerFactory.create_standard_manager(connection_info)

        # Mock ldap3 components
        with patch("ldap3.Server"), patch("ldap3.Connection") as mock_connection:
            # Configure mocks
            mock_connection_instance = MagicMock()
            mock_connection_instance.bind.return_value = True
            mock_connection_instance.bound = True
            mock_connection_instance.add.return_value = True
            mock_connection_instance.modify.return_value = True
            mock_connection_instance.delete.return_value = True
            mock_connection_instance.search.return_value = True
            mock_connection_instance.entries = []

            mock_connection.return_value = mock_connection_instance

            # Test complete lifecycle
            async with manager:
                # Test all CRUD operations work through SOLID composition
                await manager.add_entry("cn=test,dc=test,dc=com", {"cn": "test"})
                await manager.modify_entry(
                    "cn=test,dc=test,dc=com",
                    {"description": "updated"},
                )

                # Test search
                [
                    result
                    async for result in manager.search(
                        "dc=test,dc=com", "(objectClass=*)"
                    )
                ]

                await manager.delete_entry("cn=test,dc=test,dc=com")

                # Test health check
                health_status = await manager.health_check()
                assert isinstance(health_status, bool)

                # Test metrics
                metrics = manager.get_performance_metrics()
                assert isinstance(metrics, dict)
                assert "operations_count" in metrics

    def test_solid_compliance_validation(self) -> None:
        """Test SOLID compliance validation."""
        # Test compliance validation for key classes
        classes_to_test = [
            StandardConnectionFactory,
            AsyncConnectionPool,
            PerformanceTracker,
            StandardHealthMonitor,
            StandardSecurityManager,
            SOLIDConnectionManager,
        ]

        for cls in classes_to_test:
            compliance = validate_solid_compliance(cls)

            # All should pass basic compliance checks
            assert isinstance(compliance, dict)
            assert "single_responsibility" in compliance
            assert "open_closed" in compliance
            assert "liskov_substitution" in compliance
            assert "interface_segregation" in compliance
            assert "dependency_inversion" in compliance

            # For this implementation, all should be True
            for principle, compliant in compliance.items():
                assert compliant, f"{cls.__name__} violates {principle}"


# ============================================================================
# 🔥 PERFORMANCE VALIDATION WITH SOLID
# ============================================================================


class TestSOLIDPerformance:
    """🎯 Test that SOLID implementation maintains performance."""

    @pytest.mark.asyncio
    async def test_solid_vs_legacy_performance(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that SOLID implementation doesn't sacrifice performance."""
        # Create SOLID manager
        solid_manager = ConnectionManagerFactory.create_high_performance_manager(
            connection_info,
        )

        with patch("ldap3.Server"), patch("ldap3.Connection") as mock_connection:
            # Configure fast mock
            mock_connection_instance = MagicMock()
            mock_connection_instance.bind.return_value = True
            mock_connection_instance.bound = True
            mock_connection_instance.search.return_value = True
            mock_connection_instance.entries = [
                MagicMock(
                    entry_dn=f"cn=user{i},dc=test,dc=com",
                    entry_attributes_as_dict={"cn": [f"user{i}"]},
                )
                for i in range(100)
            ]
            mock_connection.return_value = mock_connection_instance

            # Test search performance
            start_time = time.time()

            async with solid_manager:
                total_entries = 0
                async for _ in solid_manager.search(
                    "dc=test,dc=com",
                    "(objectClass=*)",
                ):
                    total_entries += 1

            elapsed_time = time.time() - start_time
            throughput = (
                total_entries / elapsed_time if elapsed_time > 0 else float("inf")
            )

            # Should maintain high performance (>1000 entries/second even with SOLID overhead)
            assert throughput > 1000, (
                f"SOLID throughput {throughput:.0f} entries/s too low"
            )
            assert total_entries == 100, "Should process all entries"

    @pytest.mark.asyncio
    async def test_connection_acquisition_performance(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test connection acquisition performance with SOLID."""
        manager = ConnectionManagerFactory.create_high_performance_manager(
            connection_info,
        )

        with patch("ldap3.Server"), patch("ldap3.Connection") as mock_connection:
            # Configure fast mock
            mock_connection_instance = MagicMock()
            mock_connection_instance.bind.return_value = True
            mock_connection_instance.bound = True
            mock_connection.return_value = mock_connection_instance

            async with manager:
                # Test multiple rapid connection acquisitions
                start_time = time.time()

                for _ in range(10):
                    async with manager.get_connection():
                        pass  # Just acquire and release

                elapsed_time = time.time() - start_time
                avg_acquisition_time = elapsed_time / 10

                # Should be fast (<50ms per acquisition including SOLID overhead)
                assert avg_acquisition_time < 0.05, (
                    f"Acquisition time {avg_acquisition_time:.3f}s too slow"
                )


# ============================================================================
# 🔥 SOLID ERROR HANDLING TESTS
# ============================================================================


class TestSOLIDErrorHandling:
    """🎯 Test error handling in SOLID implementation."""

    @pytest.mark.asyncio
    async def test_component_failure_isolation(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> None:
        """Test that component failures are properly isolated."""
        # Create manager with mock components that can fail
        mock_factory = MagicMock(spec=IConnectionFactory)
        mock_factory.initialize = AsyncMock(side_effect=Exception("Factory failed"))
        mock_factory.cleanup = AsyncMock()

        mock_tracker = MagicMock(spec=IPerformanceTracker)
        mock_tracker.initialize = AsyncMock()
        mock_tracker.cleanup = AsyncMock()

        manager = SOLIDConnectionManager(
            connection_info,
            factory=mock_factory,
            performance_tracker=mock_tracker,
        )

        # Initialization should fail gracefully
        with pytest.raises(Exception, match="Factory failed"):
            await manager.initialize()

        # Other components should still be cleanable
        await manager.cleanup()
        mock_tracker.cleanup.assert_called_once()


if __name__ == "__main__":
    # Run SOLID compliance tests
    pytest.main(
        [
            __file__,
            "-v",
            "--tb=short",
            "-k",
            "solid",
        ],
    )
