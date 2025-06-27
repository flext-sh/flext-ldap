"""Tests for Vectorized Bulk Operations Processor.

This module provides comprehensive test coverage for the vectorized bulk
processor including performance optimization, parallel processing, and
enterprise-grade bulk operations with validation.

Test Coverage:
    - VectorizedBulkProcessor: High-performance bulk operations
    - VectorizedProcessingStats: Performance statistics tracking
    - Vectorized validation functions (Numba JIT compiled)
    - Parallel batch processing with optimal sizing
    - Memory-efficient DataFrame operations
    - Error handling and failure rate adaptation

Performance Testing:
    - Large-scale bulk operations (10K+ entries)
    - Memory usage optimization validation
    - Parallel processing efficiency
    - Vectorized operation speed benchmarks

Security Testing:
    - Input validation and sanitization
    - Memory exhaustion protection
    - Failure rate threshold enforcement
    - Resource consumption limits
"""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any
from unittest.mock import Mock

import pytest

# Test if vectorized dependencies are available
try:
    import numpy as np
    import pandas as pd

    VECTORIZED_AVAILABLE = True
except ImportError:
    VECTORIZED_AVAILABLE = False
    np = None
    pd = None

from ldap_core_shared.core.operations import (
    BulkOperationResult,
    LDAPBulkOperationError,
    OperationResult,
)
from ldap_core_shared.vectorized.bulk_processor import (
    BYTES_PER_KB,
    HTTP_INTERNAL_ERROR,
    VectorizedBulkProcessor,
    VectorizedProcessingStats,
    _calculate_batch_sizes,
    _validate_dns_vectorized,
    create_vectorized_processor,
)


class MockEnterpriseTransaction:
    """Mock enterprise transaction for testing."""

    def __init__(self) -> None:
        self.context = Mock()
        self.context.transaction_id = "test-transaction-123"
        self.context.operations_log = []
        self.context.backups = []
        self.context.add_checkpoint = Mock()
        self.is_committed = False
        self._add_results = []

    def add_entry(self, dn: str, attributes: dict[str, Any]) -> OperationResult:
        """Mock add entry operation."""
        # Simulate some entries failing for testing
        if "fail" in dn.lower():
            return OperationResult(success=False, message="Simulated failure")
        return OperationResult(success=True, message="Entry added successfully")


class TestVectorizedProcessingStats:
    """Test cases for VectorizedProcessingStats."""

    def test_stats_initialization(self) -> None:
        """Test statistics initialization with default values."""
        stats = VectorizedProcessingStats()

        assert stats.total_entries == 0
        assert stats.successful_entries == 0
        assert stats.failed_entries == 0
        assert stats.validation_time == 0.0
        assert stats.processing_time == 0.0
        assert stats.batch_processing_time == 0.0
        assert stats.parallel_tasks == 0
        assert stats.memory_peak_mb == 0.0
        assert stats.entries_per_second == 0.0

    def test_success_rate_calculation(self) -> None:
        """Test success rate calculation."""
        stats = VectorizedProcessingStats()

        # Test with zero entries
        assert stats.success_rate == 100.0

        # Test with all successful
        stats.total_entries = 100
        stats.successful_entries = 100
        assert stats.success_rate == 100.0

        # Test with partial success
        stats.successful_entries = 80
        assert stats.success_rate == 80.0

        # Test with all failures
        stats.successful_entries = 0
        assert stats.success_rate == 0.0

    def test_stats_serialization(self) -> None:
        """Test statistics can be converted to dict."""
        stats = VectorizedProcessingStats(
            total_entries=1000,
            successful_entries=950,
            failed_entries=50,
            validation_time=0.5,
            processing_time=2.0,
        )

        stats_dict = asdict(stats)
        assert isinstance(stats_dict, dict)
        assert stats_dict["total_entries"] == 1000
        assert stats_dict["successful_entries"] == 950
        assert stats_dict["success_rate"] == 95.0


@pytest.mark.skipif(
    not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
)
class TestVectorizedFunctions:
    """Test cases for vectorized utility functions."""

    def test_validate_dns_vectorized_valid_dns(self) -> None:
        """Test vectorized DN validation with valid DNs."""
        dns_array = np.array(
            [
                "cn=test,dc=example,dc=com",
                "uid=user,ou=people,dc=example,dc=com",
                "cn=REDACTED_LDAP_BIND_PASSWORD,ou=REDACTED_LDAP_BIND_PASSWORDs,dc=example,dc=com",
            ]
        )

        results = _validate_dns_vectorized(dns_array)

        assert isinstance(results, np.ndarray)
        assert results.dtype == np.bool_
        assert len(results) == 3
        assert all(results)  # All should be valid

    def test_validate_dns_vectorized_invalid_dns(self) -> None:
        """Test vectorized DN validation with invalid DNs."""
        dns_array = np.array(
            [
                "",  # Empty DN
                "invalid",  # No equals sign
                "cn",  # Too short
                "valid=test,dc=example,dc=com",  # Valid one
            ]
        )

        results = _validate_dns_vectorized(dns_array)

        assert len(results) == 4
        assert not results[0]  # Empty
        assert not results[1]  # No equals
        assert not results[2]  # Too short
        assert results[3]  # Valid

    def test_validate_dns_vectorized_edge_cases(self) -> None:
        """Test vectorized DN validation with edge cases."""
        dns_array = np.array(
            [
                "a=b",  # Minimal valid DN
                "cn=test with spaces,dc=example,dc=com",  # Spaces
                "cn=test,with,commas=value,dc=example,dc=com",  # Multiple commas
            ]
        )

        results = _validate_dns_vectorized(dns_array)

        assert all(results)  # All should be valid

    def test_calculate_batch_sizes_single_batch(self) -> None:
        """Test batch size calculation for small datasets."""
        total_entries = 500
        max_memory_mb = 10.0

        batch_sizes = _calculate_batch_sizes(total_entries, max_memory_mb)

        # Should fit in one batch
        assert len(batch_sizes) == 1
        assert batch_sizes[0] == total_entries

    def test_calculate_batch_sizes_multiple_batches(self) -> None:
        """Test batch size calculation for large datasets."""
        total_entries = 20000
        max_memory_mb = 5.0  # Small memory limit

        batch_sizes = _calculate_batch_sizes(total_entries, max_memory_mb)

        # Should create multiple batches
        assert len(batch_sizes) > 1
        assert sum(batch_sizes) == total_entries

        # Check individual batch sizes are reasonable
        max_entries_per_batch = int((max_memory_mb * BYTES_PER_KB) / 1.0)
        for batch_size in batch_sizes[:-1]:  # All except last
            assert batch_size == max_entries_per_batch

    def test_calculate_batch_sizes_remainder(self) -> None:
        """Test batch size calculation with remainder."""
        total_entries = 2500
        max_memory_mb = 2.0  # Will create multiple batches with remainder

        batch_sizes = _calculate_batch_sizes(total_entries, max_memory_mb)

        assert sum(batch_sizes) == total_entries

        # Last batch should have the remainder
        max_entries_per_batch = int((max_memory_mb * BYTES_PER_KB) / 1.0)
        expected_remainder = total_entries % max_entries_per_batch
        if expected_remainder > 0:
            assert batch_sizes[-1] == expected_remainder


class TestVectorizedBulkProcessor:
    """Test cases for VectorizedBulkProcessor."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.mock_transaction = MockEnterpriseTransaction()
        self.processor = VectorizedBulkProcessor(
            transaction=self.mock_transaction,
            max_memory_mb=64.0,
            max_parallel_tasks=4,
            adaptive_batching=True,
        )

    def test_processor_initialization(self) -> None:
        """Test processor initialization with parameters."""
        assert self.processor.transaction is self.mock_transaction
        assert self.processor.max_memory_mb == 64.0
        assert self.processor.max_parallel_tasks == 4
        assert self.processor.adaptive_batching is True
        assert isinstance(self.processor.stats, VectorizedProcessingStats)

    def test_processor_initialization_defaults(self) -> None:
        """Test processor initialization with default parameters."""
        processor = VectorizedBulkProcessor(transaction=self.mock_transaction)

        assert processor.max_memory_mb == 512.0
        assert processor.max_parallel_tasks == 8
        assert processor.adaptive_batching is True

    @pytest.mark.asyncio
    async def test_process_entries_empty_list(self) -> None:
        """Test processing with empty entries list."""
        with pytest.raises(ValueError, match="Entries list cannot be empty"):
            await self.processor.process_entries_vectorized([])

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_process_entries_basic(self) -> None:
        """Test basic entry processing."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
            {"dn": "cn=test3,dc=example,dc=com", "attributes": {"cn": "test3"}},
        ]

        result = await self.processor.process_entries_vectorized(entries)

        assert isinstance(result, BulkOperationResult)
        assert result.total_entries == 3
        assert result.successful_entries == 3
        assert result.failed_entries == 0
        assert result.operation_type == "vectorized_bulk_add"
        assert result.transaction_id == "test-transaction-123"

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_process_entries_with_failures(self) -> None:
        """Test processing with some entry failures."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {
                "dn": "cn=fail,dc=example,dc=com",
                "attributes": {"cn": "fail"},
            },  # Will fail
            {"dn": "cn=test3,dc=example,dc=com", "attributes": {"cn": "test3"}},
        ]

        result = await self.processor.process_entries_vectorized(entries)

        assert result.total_entries == 3
        assert result.successful_entries == 2
        assert result.failed_entries == 1
        assert self.processor.stats.success_rate == pytest.approx(66.67, rel=1e-2)

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_create_dataframe_async(self) -> None:
        """Test async DataFrame creation."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
        ]

        df = await self.processor._create_dataframe_async(entries)

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 2
        assert "dn" in df.columns
        assert "attributes" in df.columns
        assert "_index" in df.columns
        assert "_processed" in df.columns
        assert "_success" in df.columns
        assert "_error" in df.columns

        # Check dtypes
        assert df["dn"].dtype.name == "string"
        assert df["_processed"].dtype == bool
        assert df["_success"].dtype == bool

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_validate_entries_vectorized_valid(self) -> None:
        """Test vectorized validation with valid entries."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
        ]

        df = await self.processor._create_dataframe_async(entries)

        # Should not raise exception for valid entries
        await self.processor._validate_entries_vectorized(df)

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_validate_entries_missing_columns(self) -> None:
        """Test validation with missing required columns."""
        # Create DataFrame without required columns
        df = pd.DataFrame([{"invalid": "data"}])

        with pytest.raises(ValueError, match="Missing required columns"):
            await self.processor._validate_entries_vectorized(df)

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_process_single_batch(self) -> None:
        """Test processing of a single batch."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
        ]

        df = await self.processor._create_dataframe_async(entries)

        progress_calls = []

        def progress_callback(current, total, dn) -> None:
            progress_calls.append((current, total, dn))

        result_df = await self.processor._process_single_batch(
            df,
            0,
            progress_callback,
        )

        assert isinstance(result_df, pd.DataFrame)
        assert len(result_df) == 2
        assert all(result_df["_processed"])
        assert all(result_df["_success"])
        assert len(progress_calls) == 2  # Called for each entry

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_check_failure_rate_adaptive_normal(self) -> None:
        """Test adaptive failure rate checking with normal rate."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
        ]

        df = await self.processor._create_dataframe_async(entries)
        df.loc[0, "_success"] = True
        df.loc[1, "_success"] = True

        # Should not raise exception for low failure rate
        await self.processor._check_failure_rate_adaptive(df, 1)

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_check_failure_rate_adaptive_high(self) -> None:
        """Test adaptive failure rate checking with high failure rate."""
        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": "test2"}},
        ]

        df = await self.processor._create_dataframe_async(entries)
        df.loc[0, "_success"] = False  # High failure rate
        df.loc[1, "_success"] = False

        with pytest.raises(LDAPBulkOperationError, match="High failure rate detected"):
            await self.processor._check_failure_rate_adaptive(df, 1)

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_create_bulk_result(self) -> None:
        """Test bulk result creation with statistics."""
        # Set up some statistics
        self.processor.stats.total_entries = 100
        self.processor.stats.successful_entries = 95
        self.processor.stats.failed_entries = 5
        self.processor.stats.validation_time = 0.1
        self.processor.stats.processing_time = 2.0
        self.processor.stats.parallel_tasks = 4
        self.processor._start_time = time.time() - 2.5

        result = await self.processor._create_bulk_result()

        assert isinstance(result, BulkOperationResult)
        assert result.total_entries == 100
        assert result.successful_entries == 95
        assert result.failed_entries == 5
        assert result.operation_type == "vectorized_bulk_add"
        assert result.operation_duration > 0
        assert result.transaction_id == "test-transaction-123"

    @pytest.mark.asyncio
    async def test_process_entries_exception_handling(self) -> None:
        """Test exception handling in processing."""
        # Mock transaction to raise exception
        self.mock_transaction.add_entry = Mock(side_effect=Exception("Test error"))

        entries = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": "test1"}},
        ]

        with pytest.raises(
            LDAPBulkOperationError, match="Vectorized processing failed"
        ):
            await self.processor.process_entries_vectorized(entries)


class TestFactoryFunction:
    """Test cases for factory functions."""

    @pytest.mark.asyncio
    async def test_create_vectorized_processor(self) -> None:
        """Test factory function for creating processor."""
        mock_transaction = MockEnterpriseTransaction()

        processor = await create_vectorized_processor(
            transaction=mock_transaction,
            max_memory_mb=256.0,
            max_parallel_tasks=6,
        )

        assert isinstance(processor, VectorizedBulkProcessor)
        assert processor.transaction is mock_transaction
        assert processor.max_memory_mb == 256.0
        assert processor.max_parallel_tasks == 6

    @pytest.mark.asyncio
    async def test_create_vectorized_processor_defaults(self) -> None:
        """Test factory function with default parameters."""
        mock_transaction = MockEnterpriseTransaction()

        processor = await create_vectorized_processor(transaction=mock_transaction)

        assert isinstance(processor, VectorizedBulkProcessor)
        assert processor.max_memory_mb == 512.0
        assert processor.max_parallel_tasks == 8


class TestPerformanceOptimization:
    """Performance-focused test cases."""

    def setup_method(self) -> None:
        """Set up performance test fixtures."""
        self.mock_transaction = MockEnterpriseTransaction()

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_large_dataset_processing(self) -> None:
        """Test processing of large datasets for performance validation."""
        # Create large dataset
        entries = [
            {
                "dn": f"cn=user{i},ou=people,dc=example,dc=com",
                "attributes": {"cn": f"user{i}", "uid": f"user{i}"},
            }
            for i in range(1000)  # 1K entries for testing
        ]

        processor = VectorizedBulkProcessor(
            transaction=self.mock_transaction,
            max_memory_mb=128.0,
            max_parallel_tasks=4,
        )

        start_time = time.time()
        result = await processor.process_entries_vectorized(entries)
        duration = time.time() - start_time

        assert result.total_entries == 1000
        assert result.successful_entries == 1000
        assert duration < 10.0  # Should complete within 10 seconds
        assert processor.stats.entries_per_second > 50  # Reasonable throughput

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    def test_memory_efficiency(self) -> None:
        """Test memory-efficient batch size calculation."""
        # Test various memory constraints
        test_cases = [
            (10000, 1.0),  # Small memory
            (10000, 10.0),  # Medium memory
            (10000, 100.0),  # Large memory
        ]

        for total_entries, max_memory_mb in test_cases:
            batch_sizes = _calculate_batch_sizes(total_entries, max_memory_mb)

            # Verify memory constraint is respected
            max_entries_per_batch = int((max_memory_mb * BYTES_PER_KB) / 1.0)
            for batch_size in batch_sizes[:-1]:  # All except potentially last
                assert batch_size <= max_entries_per_batch

            # Verify all entries are covered
            assert sum(batch_sizes) == total_entries

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    def test_vectorized_validation_performance(self) -> None:
        """Test performance of vectorized validation."""
        # Create large DN array
        dns_array = np.array(
            [f"cn=user{i},ou=people,dc=example,dc=com" for i in range(10000)]
        )

        start_time = time.time()
        results = _validate_dns_vectorized(dns_array)
        duration = time.time() - start_time

        assert len(results) == 10000
        assert all(results)  # All should be valid
        assert duration < 1.0  # Should be very fast with JIT compilation


class TestSecurityValidation:
    """Security-focused test cases."""

    def setup_method(self) -> None:
        """Set up security test fixtures."""
        self.mock_transaction = MockEnterpriseTransaction()
        self.processor = VectorizedBulkProcessor(
            transaction=self.mock_transaction,
            max_memory_mb=64.0,
            max_parallel_tasks=2,
        )

    @pytest.mark.asyncio
    async def test_input_validation_malformed_entries(self) -> None:
        """Test input validation with malformed entries."""
        malformed_entries = [
            {},  # Empty entry
            {"dn": ""},  # Empty DN
            {"attributes": {}},  # Missing DN
            {"dn": "cn=test", "attributes": None},  # Null attributes
        ]

        # Should handle malformed entries gracefully
        with pytest.raises((ValueError, LDAPBulkOperationError)):
            await self.processor.process_entries_vectorized(malformed_entries)

    def test_memory_exhaustion_protection(self) -> None:
        """Test protection against memory exhaustion attacks."""
        # Test with extremely large memory request
        huge_memory_mb = 10000.0  # 10GB
        total_entries = 1000000  # 1M entries

        # Should create reasonable batch sizes even with large memory
        batch_sizes = _calculate_batch_sizes(total_entries, huge_memory_mb)

        # Verify batches are reasonable
        assert len(batch_sizes) >= 1
        assert sum(batch_sizes) == total_entries

        # No single batch should be unreasonably large
        max_reasonable_batch = 100000  # 100K entries max
        for batch_size in batch_sizes:
            assert batch_size <= max_reasonable_batch

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    @pytest.mark.asyncio
    async def test_failure_rate_threshold_enforcement(self) -> None:
        """Test failure rate threshold enforcement for security."""
        # Create entries with high failure rate
        entries = [
            {"dn": f"cn=fail{i},dc=example,dc=com", "attributes": {"cn": f"fail{i}"}}
            for i in range(10)  # All will fail due to "fail" in DN
        ]

        # Enable adaptive batching to trigger failure rate check
        self.processor.adaptive_batching = True

        with pytest.raises(LDAPBulkOperationError, match="High failure rate detected"):
            await self.processor.process_entries_vectorized(entries)

    def test_resource_limits_validation(self) -> None:
        """Test resource limits validation."""
        # Test reasonable limits
        processor = VectorizedBulkProcessor(
            transaction=self.mock_transaction,
            max_memory_mb=1024.0,  # 1GB
            max_parallel_tasks=16,  # 16 tasks
        )

        assert processor.max_memory_mb == 1024.0
        assert processor.max_parallel_tasks == 16

        # Test with very large limits (should be accepted but may be capped internally)
        processor = VectorizedBulkProcessor(
            transaction=self.mock_transaction,
            max_memory_mb=100000.0,  # 100GB
            max_parallel_tasks=1000,  # 1000 tasks
        )

        # Should not crash, but implementation may cap these values
        assert processor.max_memory_mb >= 0
        assert processor.max_parallel_tasks >= 0


class TestEdgeCases:
    """Edge case test scenarios."""

    def setup_method(self) -> None:
        """Set up edge case test fixtures."""
        self.mock_transaction = MockEnterpriseTransaction()

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    def test_single_entry_processing(self) -> None:
        """Test processing with single entry."""
        VectorizedBulkProcessor(transaction=self.mock_transaction)

        # Should handle single entry efficiently
        batch_sizes = _calculate_batch_sizes(1, 64.0)
        assert len(batch_sizes) == 1
        assert batch_sizes[0] == 1

    def test_zero_memory_limit(self) -> None:
        """Test handling of zero memory limit."""
        # Should handle gracefully (use minimum batch size)
        batch_sizes = _calculate_batch_sizes(100, 0.0)

        # Should still create valid batches
        assert len(batch_sizes) >= 1
        assert sum(batch_sizes) == 100

    @pytest.mark.skipif(
        not VECTORIZED_AVAILABLE, reason="Vectorized dependencies not available"
    )
    def test_empty_dn_array_validation(self) -> None:
        """Test validation with empty DN array."""
        dns_array = np.array([])
        results = _validate_dns_vectorized(dns_array)

        assert len(results) == 0
        assert results.dtype == np.bool_

    def test_constants_validation(self) -> None:
        """Test that constants have expected values."""
        assert BYTES_PER_KB == 1024
        assert HTTP_INTERNAL_ERROR == 500

    @pytest.mark.asyncio
    async def test_processor_with_disabled_adaptive_batching(self) -> None:
        """Test processor with adaptive batching disabled."""
        processor = VectorizedBulkProcessor(
            transaction=self.mock_transaction,
            adaptive_batching=False,
        )

        assert processor.adaptive_batching is False

        # Should not check failure rates when disabled

        # Create mock DataFrame to test the method directly
        if VECTORIZED_AVAILABLE:
            df = pd.DataFrame([{"_success": False}])
            # Should not raise exception when adaptive batching is disabled
            await processor._check_failure_rate_adaptive(df, 0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
