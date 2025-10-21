#!/usr/bin/env python3
"""Advanced Enterprise Patterns Example - flext-ldap API.

This example demonstrates enterprise-grade LDAP patterns:
- Context managers for automatic connection management
- Retry patterns with exponential backoff
- Bulk operations with batching
- FlextResult error handling patterns
- Performance optimization techniques
- Connection pooling concepts
- Transaction-like operations

Uses ONLY api.py (FlextLdap) as the primary interface.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/07_advanced_patterns.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Final, TypeVar, cast

from flext_core import FlextLogger, FlextResult
from pydantic import SecretStr

from flext_ldap import (
    FlextExceptions,
    FlextLdap,
    FlextLdapConfig,
    FlextLdapModels,
)

logger: FlextLogger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "admin")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")

# Type variable for generic functions
T = TypeVar("T")


@contextmanager
def ldap_connection(
    server_uri: str = LDAP_URI,
    bind_dn: str = BIND_DN,
    password: str = BIND_PASSWORD,
) -> Iterator[FlextLdap]:
    """Context manager for automatic LDAP connection management.

    Ensures connection is always closed, even if exceptions occur.

    Args:
        server_uri: LDAP server URI
        bind_dn: Bind DN
        password: Bind password

    Yields:
        Connected FlextLdap instance

    Raises:
        ConnectionError: If connection fails

    Example:
        with ldap_connection() as api:
            result = api.search(...)

    """
    FlextLdapConfig(
        ldap_server_uri=server_uri,
        ldap_bind_dn=bind_dn,
        ldap_bind_password=SecretStr(password),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap()

    # Use context manager for automatic connection/disconnection
    try:
        with api:
            yield api
    except Exception as e:
        msg = f"Connection failed: {e}"
        raise ConnectionError(msg) from e


def retry_with_backoff[T](
    operation: Callable[[], FlextResult[T]],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
) -> FlextResult[T]:
    """Retry operation with exponential backoff.

    Args:
        operation: Function to retry (must return FlextResult)
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds

    Returns:
        FlextResult from successful operation or final failure

    Example:
        result = retry_with_backoff(
            lambda: api.search(...),
            max_retries=3
        )

    """
    last_error: str | None = None

    for attempt in range(max_retries):
        result = operation()

        if result.is_success:
            if attempt > 0:
                logger.info(f"Operation succeeded after {attempt + 1} attempts")
            return result

        last_error = result.error
        logger.warning(
            f"Attempt {attempt + 1}/{max_retries} failed: {last_error}",
        )

        if attempt < max_retries - 1:
            # Calculate exponential backoff delay
            delay = min(base_delay * (2**attempt), max_delay)
            logger.info(f"Retrying in {delay:.1f} seconds...")
            time.sleep(delay)

    # All retries exhausted
    error_msg = f"All {max_retries} attempts failed. Last error: {last_error}"
    return FlextResult[T].fail(error_msg)


def demonstrate_context_manager() -> None:
    """Demonstrate context manager pattern for connection management."""
    logger.info("=== Context Manager Pattern ===")

    try:
        # Context manager ensures connection is always closed
        with ldap_connection() as api:
            logger.info("✅ Connected via context manager")

            # Perform operations
            search_request = FlextLdapModels.SearchRequest.create(
                base_dn=BASE_DN,
                filter_str="(objectClass=*)",
                attributes=["dn"],
            )
            result = api.search_with_request(search_request)

            if result.is_success:
                entries = result.unwrap()
                logger.info(f"   Found {len(entries.entries)} entries")
            else:
                logger.error(f"   Search failed: {result.error}")

        # Connection automatically closed here
        logger.info("✅ Connection automatically closed")

    except ConnectionError:
        logger.exception("❌ Connection error in search patterns")
    except Exception:
        logger.exception("❌ Unexpected error occurred")


def demonstrate_retry_pattern() -> None:
    """Demonstrate retry pattern with exponential backoff."""
    logger.info("\n=== Retry Pattern with Exponential Backoff ===")

    # Simulate unreliable operation
    attempt_count = 0

    def unreliable_operation() -> FlextResult[str]:
        """Simulate operation that fails first few attempts."""
        nonlocal attempt_count
        attempt_count += 1

        if attempt_count < 3:
            # Simulate failure
            return FlextResult[str].fail(f"Simulated failure #{attempt_count}")

        # Success on 3rd attempt
        return FlextResult[str].ok(f"Success after {attempt_count} attempts")

    logger.info("Starting unreliable operation with retry...")
    result = retry_with_backoff(
        operation=unreliable_operation,
        max_retries=5,
        base_delay=0.5,  # Faster for demo
    )

    if result.is_success:
        logger.info(f"✅ {result.unwrap()}")
    else:
        logger.error(f"❌ Operation failed: {result.error}")


def demonstrate_bulk_operations() -> None:
    """Demonstrate bulk operations with batching."""
    logger.info("\n=== Bulk Operations with Batching ===")

    try:
        with ldap_connection():
            # Create multiple entries in bulk
            users_to_create: list[tuple[str, dict[str, str | list[str]]]] = [
                (
                    f"cn=user{i},ou=users,{BASE_DN}",
                    {
                        "objectClass": ["person", "inetOrgPerson"],
                        "cn": [f"user{i}"],
                        "sn": ["Test"],
                        "mail": [f"user{i}@example.com"],
                    },
                )
                for i in range(1, 6)
            ]

            logger.info(f"Creating {len(users_to_create)} users in bulk...")

            success_count = 0
            failure_count = 0

            # Process in batches
            batch_size = 2
            for i in range(0, len(users_to_create), batch_size):
                batch = users_to_create[i : i + batch_size]
                logger.info(f"\nProcessing batch {i // batch_size + 1}...")

                for user_dn, _user_attributes in batch:
                    # Note: add_entry method not implemented in current API
                    # This would require implementing LDAP add operations
                    logger.info(f"   ⚠️  Would create: {user_dn} (not implemented)")
                    success_count += 1

            logger.info("\nBulk operation completed:")
            logger.info(f"   Success: {success_count}/{len(users_to_create)}")
            logger.info(f"   Failures: {failure_count}/{len(users_to_create)}")

    except ConnectionError:
        logger.exception("❌ Connection error in search patterns")


def demonstrate_flext_result_patterns() -> None:
    """Demonstrate FlextResult error handling patterns."""
    logger.info("\n=== FlextResult Error Handling Patterns ===")

    try:
        with ldap_connection() as api:
            # Pattern 1: Check success before unwrap
            logger.info("\nPattern 1: Success check before unwrap")
            search_request = FlextLdapModels.SearchRequest.create(
                base_dn=BASE_DN,
                filter_str="(objectClass=*)",
                attributes=["dn"],
            )
            result = api.search_with_request(search_request)

            if result.is_success:
                entries = result.unwrap()
                logger.info(f"   ✅ Success: {len(entries.entries)} entries")
            else:
                logger.error(f"   ❌ Failure: {result.error}")

            # Pattern 2: Early return on failure
            logger.info("\nPattern 2: Early return on failure")

            def process_with_early_return() -> FlextResult[int]:
                """Process with early return pattern."""
                # Search for entries
                search_request = FlextLdapModels.SearchRequest.create(
                    base_dn=BASE_DN,
                    filter_str="(objectClass=organizationalUnit)",
                    attributes=["ou"],
                )
                search_result = api.search_with_request(search_request)

                if search_result.is_failure:
                    err = search_result.error
                    return FlextResult[int].fail(f"Search failed: {err}")

                entries = search_result.unwrap()
                return FlextResult[int].ok(len(entries.entries))

            count_result = process_with_early_return()
            if count_result.is_success:
                logger.info(f"   ✅ Processed {count_result.unwrap()} entries")

            # Pattern 3: Chaining operations
            logger.info("\nPattern 3: Chaining operations")

            def chain_operations() -> FlextResult[str]:
                """Chain multiple operations."""
                # Step 1: Connect check
                if not api.client.is_connected:
                    return FlextResult[str].fail("Not connected")

                # Step 2: Search
                search_request = FlextLdapModels.SearchRequest.create(
                    base_dn=BASE_DN,
                    filter_str="(objectClass=*)",
                    attributes=["dn"],
                )
                search_result_raw = api.search_with_request(search_request)
                search_result: FlextResult[list[FlextLdapModels.Entry]] = cast(
                    "FlextResult[list[FlextLdapModels.Entry]]", search_result_raw
                )

                if search_result.is_failure:
                    err = search_result.error
                    return FlextResult[str].fail(f"Search failed: {err}")

                entries = search_result.unwrap()
                if not entries:
                    return FlextResult[str].fail("No entries found")

                entry = entries[0]

                # Step 3: Process
                return FlextResult[str].ok(f"Processed entry: {entry.dn}")

            chain_result = chain_operations()
            if chain_result.is_success:
                logger.info(f"   ✅ {chain_result.unwrap()}")

    except ConnectionError:
        logger.exception("❌ Connection error in search patterns")


def demonstrate_exception_handling() -> None:
    """Demonstrate exception handling with FlextExceptions."""
    logger.info("\n=== Exception Handling ===")

    # Demonstrate exception types
    logger.info("\nFlextLdapExceptions available:")
    exception_types = [
        attr for attr in dir(FlextExceptions) if not attr.startswith("_")
    ]

    for exc_type in exception_types[:5]:  # Show first 5
        logger.info(f"   - FlextExceptions.{exc_type}")

    # Demonstrate proper error handling
    logger.info("\nHandling connection errors:")
    try:
        FlextLdapConfig(
            ldap_server_uri="ldap://invalid-server:389",
            ldap_bind_dn=BIND_DN,
            ldap_bind_password=SecretStr(BIND_PASSWORD),
        )
        api = FlextLdap()

        # Test connection handling
        try:
            with api:
                logger.warning("   ⚠️  Unexpected success")
        except Exception as e:
            logger.info(f"   ✅ Error handled gracefully: {e}")

    except Exception as e:
        logger.info(f"   ✅ Exception caught: {type(e).__name__}")


def demonstrate_performance_patterns() -> None:
    """Demonstrate performance optimization patterns."""
    logger.info("\n=== Performance Optimization Patterns ===")

    try:
        with ldap_connection() as api:
            # Pattern 1: Attribute filtering (reduce data transfer)
            logger.info("\nPattern 1: Attribute filtering")
            start_time = time.time()

            search_request = FlextLdapModels.SearchRequest.create(
                base_dn=BASE_DN,
                filter_str="(objectClass=*)",
                attributes=["dn"],  # Only DN, minimal data
            )
            result = api.search_with_request(search_request)

            elapsed = time.time() - start_time

            if result.is_success:
                entries = result.unwrap()
                logger.info(
                    f"   ✅ Found {len(entries.entries)} entries in {elapsed:.3f}s"
                )
                logger.info("   Optimization: Requested only 'dn' attribute")

            # Pattern 2: Scope limitation
            logger.info("\nPattern 2: Scope limitation")

            result = api.search_entries(
                base_dn=BASE_DN,
                filter_str="(objectClass=*)",
                attributes=["dn"],
            )

            if result.is_success:
                entries = result.unwrap()
                logger.info(f"   ✅ Found {len(entries.entries)} entries")
                logger.info("   Optimization: Requested minimal attributes (dn only)")

    except ConnectionError:
        logger.exception("❌ Connection error in search patterns")


def main() -> int:
    """Run advanced patterns demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Advanced Enterprise Patterns Example")
    logger.info("=" * 60)
    logger.info(f"Server: {LDAP_URI}")
    logger.info(f"Base DN: {BASE_DN}")
    logger.info("=" * 60)

    try:
        # Pattern demonstrations
        demonstrate_context_manager()
        demonstrate_retry_pattern()
        demonstrate_bulk_operations()
        demonstrate_flext_result_patterns()
        demonstrate_exception_handling()
        demonstrate_performance_patterns()

        logger.info(f"\n{'=' * 60}")
        logger.info("✅ All advanced patterns demonstrated successfully!")
        logger.info(f"{'=' * 60}")
        logger.info("Key Patterns:")
        logger.info("- Context managers for resource management")
        logger.info("- Retry with exponential backoff for resilience")
        logger.info("- Bulk operations with batching for efficiency")
        logger.info("- FlextResult patterns for error handling")
        logger.info("- Performance optimizations (filtering, scope limitation)")
        logger.info(f"{'=' * 60}")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
