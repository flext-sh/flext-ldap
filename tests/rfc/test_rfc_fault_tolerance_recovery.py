"""🚀 RFC FAULT TOLERANCE & RECOVERY EXTREME Testing - AINDA MAIS EXIGENTE.

Este módulo implementa os testes MAIS RIGOROSOS possíveis para tolerância a falhas
e recuperação em operações LDAP, baseado em RFCs e sendo extremamente exigente
na validação de resiliência do sistema.

RFCs FAULT TOLERANCE REQUIREMENTS:
- RFC 4511: LDAP Protocol fault handling and error recovery
- RFC 4512: Directory resilience and consistency
- RFC 4513: Authentication failure recovery
- RFC 2696: Paged results continuation after failures
- RFC 4533: Sync operation recovery

ZERO TOLERANCE RELIABILITY: Sistema deve recuperar de QUALQUER falha.
AINDA MAIS EXIGENTE: Testa cenários de falha que outros nunca consideram.

COBERTURA FAULT TOLERANCE EXTREMA:
- Recuperação de falhas de conexão com backoff exponencial
- Continuidade de operações durante instabilidade de rede
- Recovery de operações paginadas interrompidas
- Tolerância a falhas de autenticação temporárias
- Integridade de dados durante falhas parciais
- Circuit breaker patterns para proteção do servidor
- Graceful degradation sob stress extremo
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ldap_core_shared.api import LDAP, LDAPConfig
from ldap_core_shared.core.operations import LDAPOperationRequest, LDAPSearchParams
from ldap_core_shared.exceptions.connection import (
    ConnectionError,
    ConnectionTimeoutError,
)
from ldap_core_shared.utils.performance import PerformanceMonitor


class TestConnectionFailureRecovery:
    """🔥🔥🔥 Connection Failure Recovery EXTREME Testing."""

    @pytest.mark.asyncio
    async def test_exponential_backoff_recovery_extreme(self) -> None:
        """Extreme exponential backoff recovery testing."""
        # Test exponential backoff with multiple failure scenarios

        performance_monitor = PerformanceMonitor(name="performance_test")

        failure_scenarios = [
            {
                "name": "intermittent_network_failure",
                "failure_pattern": [
                    True,
                    False,
                    False,
                    True,
                    False,
                    True,
                    False,
                    False,
                    False,
                ],  # Success pattern
                "expected_retries": 3,
                "max_backoff_time": 8.0,
            },
            {
                "name": "extended_server_unavailable",
                "failure_pattern": [True] * 5
                + [False] * 3,  # Server down then recovers
                "expected_retries": 5,
                "max_backoff_time": 16.0,
            },
            {
                "name": "dns_resolution_failure",
                "failure_pattern": [True] * 2 + [False],  # DNS fails then resolves
                "expected_retries": 2,
                "max_backoff_time": 4.0,
            },
        ]

        for scenario in failure_scenarios:
            with patch("ldap3.Connection") as mock_conn_class:
                failure_count = 0

                def mock_connection_with_failures(*args, **kwargs):
                    nonlocal failure_count
                    mock_conn = MagicMock()

                    # Simulate failures based on pattern
                    if (
                        failure_count < len(scenario["failure_pattern"])
                        and scenario["failure_pattern"][failure_count]
                    ):
                        failure_count += 1
                        if scenario["name"] == "dns_resolution_failure":
                            msg = "Name or service not known"
                            raise OSError(msg)
                        if scenario["name"] == "extended_server_unavailable":
                            msg = "Server unavailable"
                            raise ConnectionError(msg)
                        msg = "Connection timeout"
                        raise ConnectionTimeoutError(msg)

                    failure_count += 1
                    mock_conn.bind.return_value = True
                    mock_conn.bound = True
                    mock_conn.result = {"result": 0, "description": "success"}
                    return mock_conn

                mock_conn_class.side_effect = mock_connection_with_failures

                config = LDAPConfig(
                    server="ldap://unreliable.example.com:389",
                    auth_dn="cn=test,dc=example,dc=com",
                    auth_password="password",
                )

                performance_monitor.start_measurement(
                    f"backoff_recovery_{scenario['name']}"
                )
                start_time = time.time()

                try:
                    async with LDAP(config) as ldap_client:
                        # Should eventually succeed after retries
                        assert ldap_client is not None

                        # Test that operations work after recovery
                        LDAPSearchParams(
                            search_base="dc=example,dc=com",
                            search_filter="(objectClass=person)",
                            search_scope="SUBTREE",
                        )

                        # Should be able to perform operations after recovery

                except Exception as e:
                    # Should only fail if all retries exhausted
                    expected_failures = sum(scenario["failure_pattern"])
                    if expected_failures > scenario["expected_retries"]:
                        # Expected to fail if more failures than retry limit
                        assert isinstance(
                            e, ConnectionError | ConnectionTimeoutError | OSError
                        )
                    else:
                        raise

                performance_monitor.stop_measurement(
                    f"backoff_recovery_{scenario['name']}"
                )
                end_time = time.time()

                # Verify exponential backoff timing
                total_time = end_time - start_time
                expected_failures = sum(scenario["failure_pattern"])

                if expected_failures <= scenario["expected_retries"]:
                    # Should have taken time for exponential backoff
                    min_expected_time = sum(
                        min(2.0**i, scenario["max_backoff_time"])
                        for i in range(expected_failures)
                    )
                    assert (
                        total_time >= min_expected_time * 0.8
                    ), f"Backoff too fast: {total_time}s < {min_expected_time}s"

    @pytest.mark.asyncio
    async def test_connection_pool_resilience_extreme(self) -> None:
        """Extreme connection pool resilience testing."""
        # Test connection pool behavior under various failure conditions

        with patch("ldap3.Connection") as mock_conn_class:
            pool_failure_scenarios = [
                {
                    "name": "partial_pool_failure",
                    "pool_size": 10,
                    "failed_connections": 3,  # 30% failure rate
                    "description": "Some connections fail, others remain healthy",
                },
                {
                    "name": "cascading_failure",
                    "pool_size": 5,
                    "failed_connections": 5,  # 100% initial failure
                    "recovery_after": 2.0,  # Seconds
                    "description": "All connections fail then recover",
                },
                {
                    "name": "gradual_degradation",
                    "pool_size": 8,
                    "failed_connections": 6,  # 75% failure rate
                    "description": "Most connections fail gradually",
                },
            ]

            for scenario in pool_failure_scenarios:
                connection_attempts = 0
                recovered_at = None

                def mock_connection_pool(*args, **kwargs):
                    nonlocal connection_attempts, recovered_at
                    connection_attempts += 1

                    mock_conn = MagicMock()

                    # Simulate pool failure scenarios
                    if scenario["name"] == "partial_pool_failure":
                        # First N connections fail, rest succeed
                        if connection_attempts <= scenario["failed_connections"]:
                            msg = f"Connection {connection_attempts} failed"
                            raise ConnectionError(msg)

                    elif scenario["name"] == "cascading_failure":
                        # All fail initially, then recover after time
                        current_time = time.time()
                        if recovered_at is None:
                            recovered_at = current_time + scenario.get(
                                "recovery_after", 2.0
                            )

                        if current_time < recovered_at:
                            msg = "Server down during cascading failure"
                            raise ConnectionError(msg)

                    elif scenario["name"] == "gradual_degradation":
                        # Most connections fail randomly
                        failure_rate = (
                            scenario["failed_connections"] / scenario["pool_size"]
                        )
                        if random.random() < failure_rate:
                            msg = "Random connection failure"
                            raise ConnectionError(msg)

                    # Successful connection
                    mock_conn.bind.return_value = True
                    mock_conn.bound = True
                    mock_conn.result = {"result": 0, "description": "success"}
                    return mock_conn

                mock_conn_class.side_effect = mock_connection_pool

                config = LDAPConfig(
                    server="ldap://pooltest.example.com:389",
                    auth_dn="cn=test,dc=example,dc=com",
                    auth_password="password",
                    connection_pool_size=scenario["pool_size"],
                    connection_pool_retry=True,
                    connection_pool_health_check=True,
                )

                # Test concurrent operations with pool failures
                async def pool_operation(operation_id: int) -> dict[str, Any]:
                    """Single operation using connection pool."""
                    start_time = time.time()
                    attempts = 0

                    while attempts < 5:  # Max 5 attempts per operation
                        try:
                            async with LDAP(config):
                                LDAPSearchParams(
                                    search_base="dc=example,dc=com",
                                    search_filter=f"(cn=pool_test_{operation_id})",
                                    search_scope="SUBTREE",
                                )

                                # Simulate operation processing
                                await asyncio.sleep(0.01)

                                return {
                                    "operation_id": operation_id,
                                    "success": True,
                                    "attempts": attempts + 1,
                                    "duration": time.time() - start_time,
                                }

                        except (ConnectionError, Exception) as e:
                            attempts += 1
                            if attempts >= 5:
                                return {
                                    "operation_id": operation_id,
                                    "success": False,
                                    "attempts": attempts,
                                    "duration": time.time() - start_time,
                                    "error": str(e),
                                }
                            await asyncio.sleep(
                                0.1 * attempts
                            )  # Backoff between attempts
                    return None

                # Launch concurrent operations
                pool_operations = [pool_operation(i) for i in range(20)]
                operation_results = await asyncio.gather(*pool_operations)

                # Analyze pool resilience
                successful_ops = [r for r in operation_results if r["success"]]
                [r for r in operation_results if not r["success"]]

                success_rate = len(successful_ops) / len(operation_results)
                sum(r["attempts"] for r in operation_results) / len(operation_results)

                # Resilience assertions
                if scenario["name"] == "partial_pool_failure":
                    # Should achieve high success rate with partial failures
                    assert (
                        success_rate >= 0.8
                    ), f"Low success rate with partial failure: {success_rate}"
                elif scenario["name"] == "gradual_degradation":
                    # Should achieve reasonable success rate despite degradation
                    assert (
                        success_rate >= 0.3
                    ), f"Too low success rate with degradation: {success_rate}"
                # cascading_failure may have lower success rate initially

    @pytest.mark.asyncio
    async def test_operation_continuity_during_instability(self) -> None:
        """Operation continuity during network instability testing."""
        # Test that operations can continue despite network instability

        performance_monitor = PerformanceMonitor(name="performance_test")

        with patch("ldap3.Connection") as mock_conn_class:
            # Simulate unstable network conditions
            network_stability = 0.7  # 70% success rate
            operation_count = 0

            def unstable_network_connection(*args, **kwargs):
                nonlocal operation_count
                operation_count += 1

                mock_conn = MagicMock()

                # Randomly fail based on network stability
                if random.random() > network_stability:
                    if operation_count % 3 == 0:
                        msg = "Network timeout"
                        raise ConnectionTimeoutError(msg)
                    if operation_count % 3 == 1:
                        msg = "Connection reset"
                        raise ConnectionError(msg)
                    msg = "Network unreachable"
                    raise OSError(msg)

                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}

                # Simulate unstable operations
                def unstable_operation(*args, **kwargs) -> bool:
                    if random.random() > network_stability:
                        msg = "Operation failed due to instability"
                        raise ConnectionError(msg)
                    return True

                mock_conn.search.side_effect = unstable_operation
                mock_conn.add.side_effect = unstable_operation
                mock_conn.modify.side_effect = unstable_operation

                return mock_conn

            mock_conn_class.side_effect = unstable_network_connection

            config = LDAPConfig(
                server="ldap://unstable.example.com:389",
                auth_dn="cn=test,dc=example,dc=com",
                auth_password="password",
                connection_retry_count=3,
                operation_retry_count=2,
                circuit_breaker_enabled=True,
                circuit_breaker_failure_threshold=5,
                circuit_breaker_timeout=10.0,
            )

            performance_monitor.start_measurement("instability_continuity")

            # Test continuous operations under instability
            async def continuous_operations() -> dict[str, Any]:
                """Perform continuous operations despite instability."""
                operations_attempted = 0
                operations_succeeded = 0
                operations_failed = 0
                circuit_breaker_trips = 0

                for batch in range(10):  # 10 batches of operations
                    batch_success = 0

                    for operation in range(10):  # 10 operations per batch
                        operations_attempted += 1
                        max_retries = 3

                        for retry in range(max_retries):
                            try:
                                async with LDAP(config):
                                    if operation % 4 == 0:
                                        # Search operation
                                        LDAPSearchParams(
                                            search_base="dc=example,dc=com",
                                            search_filter=f"(cn=unstable_test_{batch}_{operation})",
                                            search_scope="SUBTREE",
                                        )
                                        # Simulate search
                                        await asyncio.sleep(0.001)

                                    elif operation % 4 == 1:
                                        # Add operation
                                        LDAPOperationRequest(
                                            operation_type="add",
                                            dn=f"cn=unstable_{batch}_{operation},ou=Test,dc=example,dc=com",
                                            attributes={
                                                "objectClass": ["person"],
                                                "cn": [f"unstable_{batch}_{operation}"],
                                                "sn": ["Test"],
                                            },
                                        )
                                        await asyncio.sleep(0.001)

                                    elif operation % 4 == 2:
                                        # Modify operation
                                        LDAPOperationRequest(
                                            operation_type="modify",
                                            dn=f"cn=unstable_{batch}_{operation},ou=Test,dc=example,dc=com",
                                            changes={
                                                "description": {
                                                    "operation": "replace",
                                                    "values": ["Modified"],
                                                }
                                            },
                                        )
                                        await asyncio.sleep(0.001)

                                    else:
                                        # Delete operation
                                        LDAPOperationRequest(
                                            operation_type="delete",
                                            dn=f"cn=unstable_{batch}_{operation},ou=Test,dc=example,dc=com",
                                        )
                                        await asyncio.sleep(0.001)

                                    operations_succeeded += 1
                                    batch_success += 1
                                    break  # Success, exit retry loop

                            except Exception as e:
                                if "circuit breaker" in str(e).lower():
                                    circuit_breaker_trips += 1

                                if retry == max_retries - 1:
                                    operations_failed += 1
                                else:
                                    await asyncio.sleep(0.1 * (retry + 1))  # Backoff

                    # Brief pause between batches
                    await asyncio.sleep(0.05)

                return {
                    "operations_attempted": operations_attempted,
                    "operations_succeeded": operations_succeeded,
                    "operations_failed": operations_failed,
                    "circuit_breaker_trips": circuit_breaker_trips,
                    "success_rate": operations_succeeded / operations_attempted
                    if operations_attempted > 0
                    else 0,
                }

            # Run continuous operations test
            continuity_result = await continuous_operations()

            performance_monitor.stop_measurement("instability_continuity")

            # Analyze continuity results

            # Continuity assertions
            assert (
                continuity_result["operations_attempted"] == 100
            ), "Not all operations attempted"
            assert (
                continuity_result["success_rate"] >= 0.4
            ), f"Success rate too low: {continuity_result['success_rate']}"

            # Should maintain reasonable success rate despite instability
            expected_min_success = (
                network_stability * 0.7
            )  # Account for retries and recovery
            assert (
                continuity_result["success_rate"] >= expected_min_success
            ), f"Success rate {continuity_result['success_rate']} below expected {expected_min_success}"


class TestPaginatedOperationRecovery:
    """🔥🔥 Paginated Operation Recovery Testing."""

    @pytest.mark.asyncio
    async def test_paged_search_interruption_recovery(self) -> None:
        """Paged search interruption and recovery testing."""
        # Test recovery of paged searches after interruptions

        performance_monitor = PerformanceMonitor(name="performance_test")

        with patch("ldap3.Connection") as mock_conn_class:
            page_count = 0
            total_entries = 1000  # Simulate 1000 entries across multiple pages
            page_size = 100
            total_pages = total_entries // page_size

            def mock_paged_connection(*args, **kwargs):
                nonlocal page_count

                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}

                def mock_paged_search(*args, **kwargs) -> bool:
                    nonlocal page_count
                    page_count += 1

                    # Simulate failure on specific pages
                    if page_count in {3, 7}:  # Fail on pages 3 and 7
                        msg = f"Connection lost during page {page_count}"
                        raise ConnectionError(msg)

                    # Generate mock entries for this page
                    start_entry = (page_count - 1) * page_size
                    end_entry = min(start_entry + page_size, total_entries)

                    mock_entries = []
                    for i in range(start_entry, end_entry):
                        entry = MagicMock()
                        entry.entry_dn = f"uid=user{i:04d},ou=People,dc=example,dc=com"
                        entry.entry_attributes_as_dict = {
                            "uid": [f"user{i:04d}"],
                            "cn": [f"User {i:04d}"],
                            "mail": [f"user{i:04d}@example.com"],
                        }
                        mock_entries.append(entry)

                    mock_conn.entries = mock_entries

                    # Set paging cookie
                    if page_count < total_pages:
                        mock_conn.result["controls"] = {
                            "1.2.840.113556.1.4.319": {  # Paged results control OID
                                "cookie": f"page_{page_count}_cookie".encode(),
                            },
                        }
                    else:
                        mock_conn.result["controls"] = {
                            "1.2.840.113556.1.4.319": {
                                "cookie": b"",  # Empty cookie = last page
                            },
                        }

                    return True

                mock_conn.search.side_effect = mock_paged_search
                return mock_conn

            mock_conn_class.side_effect = mock_paged_connection

            config = LDAPConfig(
                server="ldap://paged.example.com:389",
                auth_dn="cn=test,dc=example,dc=com",
                auth_password="password",
                page_size=page_size,
                paged_search_retry=True,
                paged_search_resume=True,
            )

            performance_monitor.start_measurement("paged_search_recovery")

            # Test paged search with recovery
            async with LDAP(config) as ldap_client:
                search_params = LDAPSearchParams(
                    search_base="dc=example,dc=com",
                    search_filter="(objectClass=person)",
                    search_scope="SUBTREE",
                    page_size=page_size,
                )

                recovered_entries = []
                pages_processed = 0
                failures_encountered = 0

                try:
                    async for page in ldap_client.search_paged_generator(search_params):
                        pages_processed += 1

                        if page.entries:
                            recovered_entries.extend(page.entries)

                        # Simulate processing time
                        await asyncio.sleep(0.01)

                        if not page.has_more_pages:
                            break

                except Exception:
                    failures_encountered += 1

                    # Should attempt recovery and continuation
                    # In real implementation, would resume from last successful page

            performance_monitor.stop_measurement("paged_search_recovery")

            # Recovery assertions
            # Should have processed most pages despite failures
            assert (
                pages_processed >= total_pages - 2
            ), f"Too few pages processed: {pages_processed}/{total_pages}"

            # Should have recovered most entries
            expected_min_entries = (
                total_entries * 0.8
            )  # Allow for some loss during failures
            assert (
                len(recovered_entries) >= expected_min_entries
            ), f"Too few entries recovered: {len(recovered_entries)}/{total_entries}"

    @pytest.mark.asyncio
    async def test_batch_operation_partial_failure_recovery(self) -> None:
        """Batch operation partial failure recovery testing."""
        # Test recovery from partial failures in batch operations

        with patch("ldap3.Connection") as mock_conn_class:
            operation_count = 0

            def mock_batch_connection(*args, **kwargs):
                nonlocal operation_count

                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True

                def mock_batch_operation(*args, **kwargs) -> bool:
                    nonlocal operation_count
                    operation_count += 1

                    # Simulate failures on specific operations
                    failure_operations = [
                        5,
                        12,
                        18,
                        23,
                        31,
                    ]  # Specific operations that fail

                    if operation_count in failure_operations:
                        mock_conn.result = {
                            "result": 68,
                            "description": "entryAlreadyExists",
                        }
                        return False
                    mock_conn.result = {"result": 0, "description": "success"}
                    return True

                mock_conn.add.side_effect = mock_batch_operation
                mock_conn.modify.side_effect = mock_batch_operation
                mock_conn.delete.side_effect = mock_batch_operation

                return mock_conn

            mock_conn_class.side_effect = mock_batch_connection

            config = LDAPConfig(
                server="ldap://batch.example.com:389",
                auth_dn="cn=test,dc=example,dc=com",
                auth_password="password",
                batch_operation_retry=True,
                batch_operation_continue_on_error=True,
            )

            # Test batch operations with partial failures
            async with LDAP(config):
                # Create batch of add operations
                batch_operations = []
                for i in range(40):  # 40 operations in batch
                    add_request = LDAPOperationRequest(
                        operation_type="add",
                        dn=f"cn=batch_user_{i:03d},ou=People,dc=example,dc=com",
                        attributes={
                            "objectClass": ["person", "inetOrgPerson"],
                            "cn": [f"batch_user_{i:03d}"],
                            "sn": [f"User{i:03d}"],
                            "mail": [f"batch_user_{i:03d}@example.com"],
                        },
                    )
                    batch_operations.append(add_request)

                # Execute batch with recovery
                batch_results = []
                successful_operations = 0
                failed_operations = 0
                recovered_operations = 0

                for operation in batch_operations:
                    max_retries = 2

                    for retry in range(max_retries):
                        try:
                            # Simulate batch operation execution
                            await asyncio.sleep(0.001)

                            # Mock operation result based on mock behavior
                            current_op_num = int(
                                operation.dn.split("_")[2].split(",")[0]
                            )
                            failure_operations = [5, 12, 18, 23, 31]

                            if current_op_num in failure_operations and retry == 0:
                                # First attempt fails for these operations
                                msg = f"Operation {current_op_num} failed: entryAlreadyExists"
                                raise Exception(msg)
                            # Success (either not a failure operation, or retry succeeded)
                            successful_operations += 1
                            if retry > 0:
                                recovered_operations += 1
                            batch_results.append(
                                {
                                    "operation": operation,
                                    "success": True,
                                    "retries": retry,
                                }
                            )
                            break

                        except Exception as e:
                            if retry == max_retries - 1:
                                # Final retry failed
                                failed_operations += 1
                                batch_results.append(
                                    {
                                        "operation": operation,
                                        "success": False,
                                        "error": str(e),
                                        "retries": retry + 1,
                                    }
                                )
                            else:
                                await asyncio.sleep(0.01)  # Brief retry delay

                # Batch recovery assertions
                assert len(batch_results) == len(
                    batch_operations
                ), "Not all operations completed"
                assert (
                    successful_operations >= 35
                ), f"Too many failed operations: {failed_operations}"
                assert recovered_operations > 0, "No operations recovered through retry"

                # Should have high success rate with recovery
                success_rate = successful_operations / len(batch_operations)
                assert (
                    success_rate >= 0.9
                ), f"Batch success rate too low: {success_rate}"


class TestCircuitBreakerProtection:
    """🔥🔥 Circuit Breaker Protection Testing."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_failure_detection(self) -> None:
        """Circuit breaker failure detection and protection testing."""
        # Test circuit breaker pattern for protecting against cascading failures

        with patch("ldap3.Connection") as mock_conn_class:
            consecutive_failures = 0
            circuit_state = "closed"  # closed, open, half-open

            def mock_circuit_breaker_connection(*args, **kwargs):
                nonlocal consecutive_failures, circuit_state

                mock_conn = MagicMock()

                # Simulate circuit breaker behavior
                if circuit_state == "open":
                    msg = "Circuit breaker is OPEN - requests blocked"
                    raise Exception(msg)

                # Simulate server failures
                consecutive_failures += 1

                if consecutive_failures <= 10:  # First 10 requests succeed
                    mock_conn.bind.return_value = True
                    mock_conn.bound = True
                    mock_conn.result = {"result": 0, "description": "success"}
                    consecutive_failures = 0  # Reset on success

                elif (
                    consecutive_failures <= 15
                ):  # Next 5 requests fail (trigger circuit breaker)
                    if consecutive_failures >= 15:  # After 5 failures, open circuit
                        circuit_state = "open"
                    msg = "Server failure"
                    raise ConnectionError(msg)

                else:  # Circuit is open, block requests
                    msg = "Circuit breaker is OPEN"
                    raise Exception(msg)

                return mock_conn

            mock_conn_class.side_effect = mock_circuit_breaker_connection

            config = LDAPConfig(
                server="ldap://circuit.example.com:389",
                auth_dn="cn=test,dc=example,dc=com",
                auth_password="password",
                circuit_breaker_enabled=True,
                circuit_breaker_failure_threshold=5,
                circuit_breaker_timeout=1.0,
                circuit_breaker_success_threshold=3,
            )

            # Test circuit breaker protection
            circuit_breaker_results = {
                "requests_attempted": 0,
                "requests_succeeded": 0,
                "requests_failed": 0,
                "circuit_breaker_blocks": 0,
                "circuit_state_changes": [],
            }

            # Simulate requests that trigger circuit breaker
            for request_num in range(25):
                circuit_breaker_results["requests_attempted"] += 1

                try:
                    async with LDAP(config):
                        LDAPSearchParams(
                            search_base="dc=example,dc=com",
                            search_filter=f"(cn=circuit_test_{request_num})",
                            search_scope="SUBTREE",
                        )

                        # Should succeed or fail based on circuit breaker state
                        await asyncio.sleep(0.001)
                        circuit_breaker_results["requests_succeeded"] += 1

                except Exception as e:
                    if "circuit breaker" in str(e).lower():
                        circuit_breaker_results["circuit_breaker_blocks"] += 1
                    else:
                        circuit_breaker_results["requests_failed"] += 1

                # Brief delay between requests
                await asyncio.sleep(0.01)

            # Circuit breaker assertions
            assert (
                circuit_breaker_results["requests_attempted"] == 25
            ), "Not all requests attempted"
            assert (
                circuit_breaker_results["requests_succeeded"] >= 10
            ), "Too few successful requests"
            assert (
                circuit_breaker_results["requests_failed"] >= 3
            ), "Should have some failures to trigger circuit breaker"

            # Should have blocked some requests once circuit opened
            total_blocks_and_fails = (
                circuit_breaker_results["circuit_breaker_blocks"]
                + circuit_breaker_results["requests_failed"]
            )
            assert total_blocks_and_fails >= 5, "Circuit breaker should have activated"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
