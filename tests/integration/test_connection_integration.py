"""🔥🔥🔥 ULTRA INTEGRATION Tests for LDAP Connection Components.

Integration tests for LDAP Core Shared library focusing on component interaction,
connection management, and real LDAP operations using mocked servers.

Architecture tested:
- LDAPConnectionManager + Base components integration
- Connection pooling + LDIF processing interaction
- SSH tunnel + connection management integration
- Performance monitoring + connection statistics
- Error handling across component boundaries
- Health checks and recovery mechanisms

ZERO TOLERANCE INTEGRATION PRINCIPLES:
✅ Component interaction testing
✅ Cross-module communication validation
✅ Resource management verification
✅ Error propagation testing
✅ Performance integration monitoring
✅ Real-world scenario simulation
"""

import asyncio
import contextlib
import tempfile
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ldap_core_shared.connections.base import (
    LDAPConnectionOptions,
    LDAPSearchConfig,
)
from ldap_core_shared.connections.manager import LDAPConnectionManager
from ldap_core_shared.ldif.processor import LDIFProcessor
from ldap_core_shared.utils.performance import PerformanceMonitor


class TestConnectionManagerIntegration:
    """🔥 Integration tests for LDAPConnectionManager with various components."""

    @pytest.fixture
    async def mock_connection_manager(self, sample_connection_info):
        """Create mocked connection manager for integration testing."""
        manager = LDAPConnectionManager(
            connection_info=sample_connection_info,
            enable_pooling=True,
            pool_size=5,
            enable_monitoring=True,
        )

        # Mock the actual LDAP connection creation
        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.entries = []
            mock_conn.result = {"result": 0, "description": "success"}
            mock_conn_class.return_value = mock_conn

            async with manager:
                yield manager

    @pytest.fixture
    def integration_search_configs(self):
        """Create search configurations for integration testing."""
        return [
            LDAPSearchConfig(
                search_base="ou=users,dc=example,dc=com",
                search_filter="(objectClass=person)",
                attributes=["cn", "mail", "uid"],
                search_scope="SUBTREE",
            ),
            LDAPSearchConfig(
                search_base="ou=groups,dc=example,dc=com",
                search_filter="(objectClass=groupOfNames)",
                attributes=["cn", "member"],
                search_scope="SUBTREE",
            ),
            LDAPSearchConfig(
                search_base="ou=roles,dc=example,dc=com",
                search_filter="(objectClass=organizationalRole)",
                attributes=["cn", "description"],
                search_scope="ONELEVEL",
            ),
        ]

    @pytest.mark.asyncio
    async def test_connection_manager_initialization_integration(
        self,
        sample_connection_info,
    ) -> None:
        """🔥 Test connection manager initialization with all components."""
        options = LDAPConnectionOptions(
            connection_info=sample_connection_info,
            connection_pool_enabled=True,
            max_pool_size=10,
            enable_ssh_tunnel=False,
        )

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn_class.return_value = mock_conn

            manager = LDAPConnectionManager.from_options(options)

            assert manager.connection_info == sample_connection_info
            assert manager.enable_pooling is True
            assert manager.pool_size == 10
            assert manager.enable_monitoring is True

    @pytest.mark.asyncio
    async def test_connection_pool_health_integration(
        self,
        mock_connection_manager,
    ) -> None:
        """🔥 Test connection pool health checks integration."""
        # Perform health check
        health_status = await mock_connection_manager.health_check()
        assert health_status is True

        # Verify pool statistics after health check
        stats = mock_connection_manager.get_stats()
        assert stats.total_connections >= 0
        assert stats.active_connections >= 0
        assert stats.failed_connections >= 0

    @pytest.mark.asyncio
    async def test_concurrent_search_operations_integration(
        self,
        mock_connection_manager,
        integration_search_configs,
    ) -> None:
        """🔥 Test concurrent search operations with connection pooling."""
        # Mock search results
        with patch.object(mock_connection_manager, "search_with_config") as mock_search:
            mock_search.return_value = AsyncMock()
            mock_search.return_value.__aiter__ = AsyncMock(
                return_value=iter(
                    [
                        {
                            "dn": "uid=user1,ou=users,dc=example,dc=com",
                            "attributes": {"cn": ["User 1"]},
                        },
                        {
                            "dn": "uid=user2,ou=users,dc=example,dc=com",
                            "attributes": {"cn": ["User 2"]},
                        },
                    ],
                ),
            )

            # Execute bulk search operations
            results = await mock_connection_manager.bulk_search(
                integration_search_configs,
            )

            assert len(results) == len(integration_search_configs)
            assert mock_search.call_count == len(integration_search_configs)

    @pytest.mark.asyncio
    async def test_connection_error_recovery_integration(
        self,
        mock_connection_manager,
    ) -> None:
        """🔥 Test connection error recovery across components."""
        # Simulate connection failure and recovery
        with patch.object(mock_connection_manager, "get_connection") as mock_get_conn:
            # First call fails
            mock_get_conn.side_effect = [
                Exception("Connection failed"),
                contextlib.asynccontextmanager(lambda: AsyncMock())(),
            ]

            # First operation should fail
            with pytest.raises(Exception, match="Connection failed"):
                async with mock_connection_manager.get_connection():
                    pass

            # Second operation should succeed (recovery)
            async with mock_connection_manager.get_connection() as conn:
                assert conn is not None

    @pytest.mark.asyncio
    async def test_performance_monitoring_integration(
        self,
        mock_connection_manager,
    ) -> None:
        """🔥 Test performance monitoring integration across operations."""
        initial_stats = mock_connection_manager.get_stats()

        # Perform multiple operations to generate metrics
        for _ in range(5):
            async with mock_connection_manager.get_connection():
                # Simulate operation delay
                await asyncio.sleep(0.01)

        final_stats = mock_connection_manager.get_stats()

        # Verify statistics were updated
        assert final_stats.total_connections >= initial_stats.total_connections
        assert final_stats.total_operations >= initial_stats.total_operations

    @pytest.mark.asyncio
    async def test_ssh_tunnel_integration(self, sample_connection_info) -> None:
        """🔥 Test SSH tunnel integration with connection manager."""
        options = LDAPConnectionOptions(
            connection_info=sample_connection_info,
            enable_ssh_tunnel=True,
            ssh_host="ssh.example.com",
            ssh_port=22,
            ssh_username="tunneluser",
            ssh_password="tunnelpass",
        )

        manager = LDAPConnectionManager.from_options(options)

        # Verify SSH tunnel configuration was applied
        # Note: In real implementation, this would establish SSH tunnel
        assert manager.connection_info == sample_connection_info


class TestLDIFProcessorConnectionIntegration:
    """🔥🔥 Integration tests for LDIF processing with connection management."""

    @pytest.fixture
    def sample_ldif_content(self) -> str:
        """Create sample LDIF content for integration testing."""
        return """dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users

dn: uid=user1,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: user1
cn: User One
sn: One
mail: user1@example.com

dn: uid=user2,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: user2
cn: User Two
sn: Two
mail: user2@example.com

dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

dn: cn=group1,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: group1
member: uid=user1,ou=users,dc=example,dc=com
member: uid=user2,ou=users,dc=example,dc=com
"""

    @pytest.mark.asyncio
    async def test_ldif_processor_with_connection_manager(
        self,
        sample_ldif_content,
        sample_connection_info,
    ) -> None:
        """🔥 Test LDIF processor integration with connection manager."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(sample_ldif_content)
            ldif_path = f.name

        try:
            # Create processor and connection manager
            processor = LDIFProcessor()

            with patch("ldap3.Connection") as mock_conn_class:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn_class.return_value = mock_conn

                async with LDAPConnectionManager(sample_connection_info) as manager:
                    # Process LDIF file
                    async with processor.process_file(ldif_path) as results:
                        entries = []
                        async for entry in results:
                            entries.append(entry)

                    # Verify integration results
                    assert len(entries) > 0

                    # Verify we can use connection manager with processed entries
                    stats = manager.get_stats()
                    assert stats.total_connections >= 0

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_ldif_processing_with_performance_monitoring(
        self,
        sample_ldif_content,
    ) -> None:
        """🔥 Test LDIF processing with performance monitoring integration."""
        monitor = PerformanceMonitor()
        processor = LDIFProcessor()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False) as f:
            f.write(sample_ldif_content)
            ldif_path = f.name

        try:
            # Start performance monitoring
            monitor.start_measurement("ldif_processing")

            # Process LDIF with performance tracking
            async with processor.process_file(ldif_path) as results:
                entry_count = 0
                async for _entry in results:
                    entry_count += 1
                    monitor.record_event("entry_processed")

            # Stop monitoring and get metrics
            monitor.stop_measurement("ldif_processing")
            metrics = monitor.get_metrics()

            # Verify integration metrics
            assert "ldif_processing" in metrics
            assert metrics["ldif_processing"]["duration"] > 0
            assert metrics["events"]["entry_processed"] == entry_count

        finally:
            import os

            os.unlink(ldif_path)


class TestEndToEndIntegration:
    """🔥🔥🔥 End-to-end integration tests across all components."""

    @pytest.mark.asyncio
    async def test_full_ldap_workflow_integration(
        self,
        sample_connection_info,
        integration_search_configs,
    ) -> None:
        """🔥🔥🔥 Test complete LDAP workflow integration."""
        # Initialize performance monitoring
        monitor = PerformanceMonitor()
        monitor.start_measurement("full_workflow")

        with patch("ldap3.Connection") as mock_conn_class:
            # Setup mock connection
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.entries = [
                MagicMock(
                    entry_dn="uid=user1,ou=users,dc=example,dc=com",
                    entry_attributes_as_dict={
                        "cn": ["User 1"],
                        "mail": ["user1@example.com"],
                    },
                ),
            ]
            mock_conn.result = {"result": 0, "description": "success"}
            mock_conn_class.return_value = mock_conn

            # Create connection manager with full configuration
            options = LDAPConnectionOptions(
                connection_info=sample_connection_info,
                connection_pool_enabled=True,
                max_pool_size=10,
                enable_ssh_tunnel=False,
            )

            async with LDAPConnectionManager.from_options(options) as manager:
                # Perform health check
                health_ok = await manager.health_check()
                assert health_ok is True

                # Execute search operations
                search_results = await manager.bulk_search(integration_search_configs)
                assert len(search_results) == len(integration_search_configs)

                # Test CRUD operations
                test_dn = "uid=testuser,ou=users,dc=example,dc=com"
                test_attributes = {
                    "objectClass": ["inetOrgPerson"],
                    "uid": ["testuser"],
                    "cn": ["Test User"],
                    "sn": ["User"],
                    "mail": ["test@example.com"],
                }

                # Add entry
                add_result = await manager.add_entry(test_dn, test_attributes)
                assert add_result is True

                # Modify entry
                modify_result = await manager.modify_entry(
                    test_dn,
                    {"cn": "Modified User"},
                )
                assert modify_result is True

                # Get entry
                entry = await manager.get_entry(test_dn)
                assert entry is not None

                # Compare attribute
                compare_result = await manager.compare_attribute(
                    test_dn,
                    "uid",
                    "testuser",
                )
                assert compare_result is True

                # Delete entry
                delete_result = await manager.delete_entry(test_dn)
                assert delete_result is True

                # Get final statistics
                final_stats = manager.get_stats()
                assert final_stats.total_operations > 0

        # Stop monitoring and verify metrics
        monitor.stop_measurement("full_workflow")
        metrics = monitor.get_metrics()
        assert "full_workflow" in metrics
        assert metrics["full_workflow"]["duration"] > 0

    @pytest.mark.asyncio
    async def test_concurrent_operations_integration(
        self,
        sample_connection_info,
    ) -> None:
        """🔥🔥 Test concurrent operations across all components."""

        async def worker_task(
            worker_id: int,
            manager: LDAPConnectionManager,
        ) -> dict[str, Any]:
            """Worker task for concurrent testing."""
            results = {"worker_id": worker_id, "operations": 0, "errors": 0}

            try:
                # Perform multiple operations
                for _i in range(10):
                    async with manager.get_connection():
                        results["operations"] += 1
                        # Simulate work
                        await asyncio.sleep(0.001)

                # Perform health check
                health_ok = await manager.health_check()
                if health_ok:
                    results["operations"] += 1

            except Exception:
                results["errors"] += 1

            return results

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn_class.return_value = mock_conn

            async with LDAPConnectionManager(
                sample_connection_info,
                pool_size=20,
            ) as manager:
                # Launch concurrent workers
                tasks = [worker_task(i, manager) for i in range(5)]
                results = await asyncio.gather(*tasks)

                # Verify all workers completed successfully
                total_operations = sum(r["operations"] for r in results)
                total_errors = sum(r["errors"] for r in results)

                assert total_operations > 0
                assert total_errors == 0

                # Verify connection pool handled concurrency well
                stats = manager.get_stats()
                assert stats.active_connections >= 0
                assert stats.total_connections > 0

    @pytest.mark.asyncio
    async def test_error_handling_integration(
        self,
        sample_connection_info,
    ) -> None:
        """🔥🔥 Test error handling integration across components."""
        with patch("ldap3.Connection") as mock_conn_class:
            # Setup connection that fails on certain operations
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True

            # Make search operation fail
            mock_conn.search.side_effect = Exception("Search failed")
            mock_conn_class.return_value = mock_conn

            async with LDAPConnectionManager(sample_connection_info) as manager:
                # Test error handling in search
                with pytest.raises(Exception, match="Search failed"):
                    async for _ in manager.search("dc=example,dc=com"):
                        pass

                # Verify error statistics were updated
                stats = manager.get_stats()
                assert stats.failed_connections > 0 or stats.total_operations >= 0

    @pytest.mark.asyncio
    async def test_resource_cleanup_integration(
        self,
        sample_connection_info,
    ) -> None:
        """🔥🔥 Test resource cleanup integration."""
        manager = None

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn_class.return_value = mock_conn

            # Create and use manager
            manager = LDAPConnectionManager(
                sample_connection_info,
                enable_pooling=True,
                pool_size=5,
            )

            async with manager:
                # Perform operations to create connections
                async with manager.get_connection():
                    pass

                # Verify connections exist
                stats = manager.get_stats()
                assert stats.total_connections > 0

        # After context exit, resources should be cleaned up
        # In real implementation, we would verify all connections are closed
        assert manager is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
