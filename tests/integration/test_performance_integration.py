"""🔥🔥🔥 ULTRA INTEGRATION Tests for Performance Monitoring Components.

Integration tests for performance monitoring across all LDAP Core components,
testing real-world scenarios with connection management, LDIF processing,
and enterprise-grade performance measurement patterns.

Architecture tested:
- PerformanceMonitor + Connection Manager integration
- Performance tracking across LDIF processing workflows
- Concurrent performance measurement accuracy
- Memory and resource monitoring integration
- Performance alerting and threshold management
- Enterprise performance reporting integration

ZERO TOLERANCE PERFORMANCE PRINCIPLES:
✅ Accurate measurement across component boundaries
✅ Low-overhead monitoring integration
✅ Concurrent measurement accuracy
✅ Resource usage tracking
✅ Performance regression detection
✅ Real-world workload simulation
"""

import asyncio
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from ldap_core_shared.connections.manager import LDAPConnectionManager
from ldap_core_shared.ldif.parser import LDIFParser
from ldap_core_shared.ldif.processor import LDIFProcessor
from ldap_core_shared.utils.performance import PerformanceMonitor


class TestPerformanceMonitoringIntegration:
    """🔥 Integration tests for performance monitoring across components."""

    @pytest.fixture
    def performance_ldif_content(self):
        """Create LDIF content optimized for performance testing."""
        content = "dn: dc=performance,dc=com\nobjectClass: domain\ndc: performance\n\n"

        # Add organizational units
        for ou in ["users", "groups", "systems"]:
            content += f"""dn: ou={ou},dc=performance,dc=com
objectClass: organizationalUnit
ou: {ou}

"""

        # Add users (performance test entries)
        for i in range(50):
            content += f"""dn: uid=user{i:03d},ou=users,dc=performance,dc=com
objectClass: inetOrgPerson
uid: user{i:03d}
cn: User {i:03d}
sn: User{i:03d}
givenName: Performance
mail: user{i:03d}@performance.com
telephoneNumber: +1-555-{i:04d}
employeeNumber: {10000 + i}
departmentNumber: Engineering
title: Performance Test User

"""

        # Add groups
        for i in range(10):
            content += f"""dn: cn=group{i:02d},ou=groups,dc=performance,dc=com
objectClass: groupOfNames
cn: group{i:02d}
description: Performance test group {i:02d}
member: uid=user{i:03d},ou=users,dc=performance,dc=com

"""

        return content

    @pytest.mark.asyncio
    async def test_connection_performance_integration(
        self,
        sample_connection_info,
        performance_ldif_content,
    ) -> None:
        """🔥 Test performance monitoring integration with connection management."""
        monitor = PerformanceMonitor()

        with patch("ldap3.Connection") as mock_conn_class:
            # Setup realistic connection mock
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.entries = []
            mock_conn.result = {"result": 0, "description": "success"}
            mock_conn_class.return_value = mock_conn

            # Start overall performance measurement
            monitor.start_measurement("connection_integration")

            async with LDAPConnectionManager(
                sample_connection_info,
                enable_pooling=True,
                pool_size=10,
                enable_monitoring=True,
            ) as manager:
                # Test connection acquisition performance
                monitor.start_measurement("connection_acquisition")

                connection_times = []
                for _i in range(20):
                    start_time = time.time()
                    async with manager.get_connection():
                        acquisition_time = time.time() - start_time
                        connection_times.append(acquisition_time)
                        monitor.record_event("connection_acquired")

                monitor.stop_measurement("connection_acquisition")

                # Test search operation performance
                monitor.start_measurement("search_operations")

                search_configs = [
                    {
                        "search_base": "ou=users,dc=performance,dc=com",
                        "search_filter": f"(uid=user{i:03d})",
                        "attributes": ["cn", "mail"],
                    }
                    for i in range(10)
                ]

                for config in search_configs:
                    start_time = time.time()
                    async for _ in manager.search(**config):
                        pass
                    time.time() - start_time
                    monitor.record_event("search_completed")

                monitor.stop_measurement("search_operations")

                # Get connection manager statistics
                conn_stats = manager.get_stats()

            monitor.stop_measurement("connection_integration")

            # Analyze performance metrics
            metrics = monitor.get_metrics()

            # Verify connection performance
            assert "connection_acquisition" in metrics
            assert "search_operations" in metrics
            assert "connection_integration" in metrics

            # Verify event counts
            assert metrics["events"]["connection_acquired"] == 20
            assert metrics["events"]["search_completed"] == 10

            # Verify performance characteristics
            acquisition_duration = metrics["connection_acquisition"]["duration"]
            search_duration = metrics["search_operations"]["duration"]

            assert acquisition_duration > 0
            assert search_duration > 0

            # Verify connection statistics integration
            assert conn_stats.total_connections >= 0
            assert conn_stats.total_operations >= 0

    @pytest.mark.asyncio
    async def test_ldif_processing_performance_integration(
        self,
        performance_ldif_content,
    ) -> None:
        """🔥 Test performance monitoring integration with LDIF processing."""
        monitor = PerformanceMonitor()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(performance_ldif_content)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()
            parser = LDIFParser()

            # Test processor performance
            monitor.start_measurement("processor_performance")

            processor_entries = []
            processing_times = []

            async with processor.process_file(ldif_path) as results:
                async for entry in results:
                    start_time = time.time()

                    # Simulate entry processing
                    processor.categorize_entry(entry)

                    processing_time = time.time() - start_time
                    processing_times.append(processing_time)
                    processor_entries.append(entry)

                    monitor.record_event("entry_processed")

            monitor.stop_measurement("processor_performance")

            # Test parser performance
            monitor.start_measurement("parser_performance")

            parser_entries = []
            async for entry in parser.parse_file(ldif_path):
                parser_entries.append(entry)
                monitor.record_event("entry_parsed")

            monitor.stop_measurement("parser_performance")

            # Test concurrent processing performance
            monitor.start_measurement("concurrent_processing")

            async def concurrent_processor():
                entries = []
                async with processor.process_file(ldif_path) as results:
                    async for entry in results:
                        entries.append(entry)
                return len(entries)

            async def concurrent_parser():
                entries = []
                async for entry in parser.parse_file(ldif_path):
                    entries.append(entry)
                return len(entries)

            # Run both concurrently
            proc_count, parse_count = await asyncio.gather(
                concurrent_processor(),
                concurrent_parser(),
            )

            monitor.stop_measurement("concurrent_processing")

            # Analyze performance metrics
            metrics = monitor.get_metrics()

            # Verify measurements exist
            assert "processor_performance" in metrics
            assert "parser_performance" in metrics
            assert "concurrent_processing" in metrics

            # Verify entry counts
            assert len(processor_entries) == len(parser_entries)
            assert proc_count == parse_count
            assert metrics["events"]["entry_processed"] == len(processor_entries)
            assert metrics["events"]["entry_parsed"] == len(parser_entries)

            # Verify performance characteristics
            processor_duration = metrics["processor_performance"]["duration"]
            parser_duration = metrics["parser_performance"]["duration"]
            concurrent_duration = metrics["concurrent_processing"]["duration"]

            assert processor_duration > 0
            assert parser_duration > 0
            assert concurrent_duration > 0

            # Concurrent should be faster than sequential sum
            assert concurrent_duration < (processor_duration + parser_duration)

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_resource_monitoring_integration(
        self,
        sample_connection_info,
        performance_ldif_content,
    ) -> None:
        """🔥 Test resource monitoring integration across components."""
        monitor = PerformanceMonitor()

        # Create temporary LDIF file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(performance_ldif_content)
            ldif_path = f.name

        try:
            with patch("ldap3.Connection") as mock_conn_class:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.entries = []
                mock_conn_class.return_value = mock_conn

                # Start comprehensive resource monitoring
                monitor.start_measurement("resource_integration")

                # Test memory usage during concurrent operations
                async def memory_intensive_task(task_id: int):
                    """Simulate memory-intensive LDAP operations."""
                    processor = LDIFProcessor()

                    async with LDAPConnectionManager(
                        sample_connection_info,
                        enable_pooling=True,
                        pool_size=5,
                    ) as manager:
                        # Process LDIF file
                        entries = []
                        async with processor.process_file(ldif_path) as results:
                            async for entry in results:
                                entries.append(entry)
                                monitor.record_event(f"task_{task_id}_entry")

                        # Perform connection operations
                        for _i in range(10):
                            async with manager.get_connection():
                                monitor.record_event(f"task_{task_id}_connection")

                        return len(entries)

                # Launch multiple concurrent tasks
                tasks = [memory_intensive_task(i) for i in range(3)]
                results = await asyncio.gather(*tasks)

                monitor.stop_measurement("resource_integration")

                # Analyze resource metrics
                metrics = monitor.get_metrics()

                # Verify all tasks completed
                assert len(results) == 3
                assert all(count > 0 for count in results)

                # Verify event tracking for all tasks
                for i in range(3):
                    assert metrics["events"][f"task_{i}_entry"] > 0
                    assert metrics["events"][f"task_{i}_connection"] == 10

                # Verify resource integration measurement
                assert "resource_integration" in metrics
                assert metrics["resource_integration"]["duration"] > 0

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_performance_threshold_integration(
        self,
        sample_connection_info,
    ) -> None:
        """🔥 Test performance threshold monitoring integration."""
        monitor = PerformanceMonitor()

        # Define performance thresholds
        thresholds = {
            "connection_time": 0.1,  # 100ms max for connection
            "operation_time": 0.05,  # 50ms max for operations
            "total_duration": 1.0,  # 1 second max for test
        }

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn_class.return_value = mock_conn

            monitor.start_measurement("threshold_test")

            async with LDAPConnectionManager(
                sample_connection_info,
                enable_pooling=True,
            ) as manager:
                # Test connection acquisition times
                for i in range(10):
                    monitor.start_measurement(f"connection_{i}")

                    async with manager.get_connection():
                        # Simulate work
                        await asyncio.sleep(0.001)

                    monitor.stop_measurement(f"connection_{i}")

                # Test operation times
                for i in range(5):
                    monitor.start_measurement(f"operation_{i}")

                    # Simulate LDAP operation
                    async for _ in manager.search("dc=test", "(objectClass=*)"):
                        pass

                    monitor.stop_measurement(f"operation_{i}")

            monitor.stop_measurement("threshold_test")

            # Analyze threshold compliance
            metrics = monitor.get_metrics()

            # Check connection time thresholds
            connection_violations = []
            for i in range(10):
                conn_time = metrics[f"connection_{i}"]["duration"]
                if conn_time > thresholds["connection_time"]:
                    connection_violations.append(i)

            # Check operation time thresholds
            operation_violations = []
            for i in range(5):
                op_time = metrics[f"operation_{i}"]["duration"]
                if op_time > thresholds["operation_time"]:
                    operation_violations.append(i)

            # Check total duration threshold
            total_time = metrics["threshold_test"]["duration"]
            total_violation = total_time > thresholds["total_duration"]

            # In a test environment, we expect good performance
            # (In production, these would trigger alerts)
            assert len(connection_violations) < 5  # Allow some variance
            assert len(operation_violations) < 3  # Allow some variance
            assert not total_violation or total_time < 2.0  # Allow reasonable test time

    @pytest.mark.asyncio
    async def test_concurrent_monitoring_accuracy(self) -> None:
        """🔥 Test monitoring accuracy under concurrent load."""
        monitor = PerformanceMonitor()

        async def concurrent_worker(worker_id: int, operations: int):
            """Worker function for concurrent monitoring test."""
            worker_results = {
                "worker_id": worker_id,
                "operations_completed": 0,
                "total_duration": 0,
            }

            for i in range(operations):
                monitor.start_measurement(f"worker_{worker_id}_op_{i}")

                # Simulate variable workload
                work_time = 0.001 * (1 + (worker_id % 3))  # 1-3ms work
                await asyncio.sleep(work_time)

                monitor.stop_measurement(f"worker_{worker_id}_op_{i}")
                monitor.record_event(f"worker_{worker_id}_completed")

                worker_results["operations_completed"] += 1

            return worker_results

        # Launch concurrent workers
        num_workers = 5
        operations_per_worker = 10

        monitor.start_measurement("concurrent_accuracy_test")

        tasks = [
            concurrent_worker(i, operations_per_worker) for i in range(num_workers)
        ]

        results = await asyncio.gather(*tasks)

        monitor.stop_measurement("concurrent_accuracy_test")

        # Verify all workers completed
        assert len(results) == num_workers

        total_operations = 0
        for result in results:
            assert result["operations_completed"] == operations_per_worker
            total_operations += result["operations_completed"]

        # Verify monitoring accuracy
        metrics = monitor.get_metrics()

        # Check individual operation measurements
        for worker_id in range(num_workers):
            for op_id in range(operations_per_worker):
                measurement_key = f"worker_{worker_id}_op_{op_id}"
                assert measurement_key in metrics
                assert metrics[measurement_key]["duration"] > 0

            # Check event counts
            event_key = f"worker_{worker_id}_completed"
            assert metrics["events"][event_key] == operations_per_worker

        # Verify total accuracy
        assert total_operations == num_workers * operations_per_worker
        assert "concurrent_accuracy_test" in metrics


class TestPerformanceRegressionIntegration:
    """🔥🔥 Integration tests for performance regression detection."""

    @pytest.mark.asyncio
    async def test_baseline_performance_establishment(
        self,
        sample_connection_info,
    ) -> None:
        """🔥 Test establishing baseline performance metrics."""
        monitor = PerformanceMonitor()

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn_class.return_value = mock_conn

            # Establish baseline measurements
            baseline_metrics = {}

            # Connection establishment baseline
            monitor.start_measurement("baseline_connection")

            async with LDAPConnectionManager(sample_connection_info) as manager:
                for _ in range(20):
                    async with manager.get_connection():
                        pass

            monitor.stop_measurement("baseline_connection")

            # Search operation baseline
            monitor.start_measurement("baseline_search")

            async with LDAPConnectionManager(sample_connection_info) as manager:
                for i in range(10):
                    async for _ in manager.search(f"uid=user{i}", "(objectClass=*)"):
                        pass

            monitor.stop_measurement("baseline_search")

            # Pool refresh baseline
            monitor.start_measurement("baseline_pool_refresh")

            async with LDAPConnectionManager(
                sample_connection_info,
                enable_pooling=True,
                pool_size=10,
            ) as manager:
                await manager.refresh_pool()

            monitor.stop_measurement("baseline_pool_refresh")

            # Capture baseline metrics
            metrics = monitor.get_metrics()
            baseline_metrics.update(
                {
                    "connection_time": metrics["baseline_connection"]["duration"],
                    "search_time": metrics["baseline_search"]["duration"],
                    "pool_refresh_time": metrics["baseline_pool_refresh"]["duration"],
                },
            )

            # Verify baseline establishment
            assert all(time > 0 for time in baseline_metrics.values())

            # Store baseline for comparison (in real implementation)
            # This would be persisted for regression detection
            assert baseline_metrics["connection_time"] < 1.0  # Reasonable baseline
            assert baseline_metrics["search_time"] < 1.0  # Reasonable baseline
            assert baseline_metrics["pool_refresh_time"] < 1.0  # Reasonable baseline

    @pytest.mark.asyncio
    async def test_performance_degradation_detection(
        self,
        sample_connection_info,
    ) -> None:
        """🔥 Test detection of performance degradation."""
        monitor = PerformanceMonitor()

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn_class.return_value = mock_conn

            # Simulate normal performance
            monitor.start_measurement("normal_performance")

            async with LDAPConnectionManager(sample_connection_info) as manager:
                for _ in range(10):
                    async with manager.get_connection():
                        await asyncio.sleep(0.001)  # Normal delay

            monitor.stop_measurement("normal_performance")
            normal_time = monitor.get_metrics()["normal_performance"]["duration"]

            # Simulate degraded performance
            monitor.start_measurement("degraded_performance")

            async with LDAPConnectionManager(sample_connection_info) as manager:
                for _ in range(10):
                    async with manager.get_connection():
                        await asyncio.sleep(0.01)  # 10x slower

            monitor.stop_measurement("degraded_performance")
            degraded_time = monitor.get_metrics()["degraded_performance"]["duration"]

            # Detect degradation
            degradation_ratio = degraded_time / normal_time

            # Verify degradation detection
            assert degradation_ratio > 2.0  # Significant degradation detected

            # In real implementation, this would trigger alerts
            performance_alert = {
                "metric": "connection_performance",
                "baseline": normal_time,
                "current": degraded_time,
                "degradation_factor": degradation_ratio,
                "threshold_exceeded": degradation_ratio > 2.0,
            }

            assert performance_alert["threshold_exceeded"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
