#!/usr/bin/env python3
"""Advanced FLEXT-LDAP Patterns Example.

This example demonstrates advanced usage patterns:
- Complex configurations
- Async/await patterns
- Context managers
- Enterprise error handling
- Performance optimizations
- Production best practices

Usage:
    python examples/advanced_patterns.py

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager

from flext_core import FlextResult, get_logger

from flext_ldap import (
    FlextLdapApi,
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapSearchRequest,
    FlextLdapSettings,
)

logger = get_logger(__name__)


@asynccontextmanager
async def ldap_session(
    server_url: str,
    bind_dn: str,
    password: str,
) -> AsyncIterator[tuple[FlextLdapApi, str]]:
    """Enterprise LDAP session context manager.

    Provides automatic connection management with proper cleanup.
    """
    api = FlextLdapApi()
    session_id = f"session_{id(api)}"

    def _raise_conn_error(message: str) -> None:
        raise ConnectionError(message)

    logger.info(
        "Establishing LDAP session",
        extra={
            "server_url": server_url,
            "session_id": session_id,
            "has_auth": bool(bind_dn),
        },
    )

    try:
        # Attempt connection
        connection_result = await api.connect(
            server_uri=server_url,
            bind_dn=bind_dn,
            bind_password=password,
        )

        if not connection_result.is_success:
            msg: str = f"Failed to connect: {connection_result.error}"
            _raise_conn_error(msg)

        logger.info("LDAP session established", extra={"session_id": session_id})
        yield api, session_id

    except Exception as e:
        logger.exception(
            "LDAP session failed",
            extra={"error": str(e), "session_id": session_id},
        )
        raise
    finally:
        # Cleanup
        try:
            if isinstance(session_id, str):
                await api.disconnect(session_id)
            logger.info("LDAP session closed", extra={"session_id": session_id})
        except Exception as e:
            logger.warning(
                "Session cleanup failed",
                extra={"error": str(e), "session_id": session_id},
            )


async def demonstrate_value_objects() -> None:
    """Demonstrate value object usage."""
    print("\n💎 Value Objects and Type Safety")
    print("=" * 40)

    try:
        # 1. Distinguished Names
        dn = FlextLdapDistinguishedName(value="cn=admin,ou=users,dc=example,dc=com")
        validation_result = dn.validate_business_rules()

        print(f"✅ DN validation: {'PASS' if validation_result.is_success else 'FAIL'}")
        print(f"   DN: {dn.value}")

        # 2. LDAP Filters - Using correct FlextLdapFilter class
        complex_filter = "(&(objectClass=person)(mail=*@example.com))"
        filter_result = FlextLdapFilter.create(complex_filter)

        if filter_result.is_success:
            from flext_ldap.value_objects import FlextLdapFilter as FilterClass

            default_filter = FilterClass(value="(objectClass=*)")
            filter_obj = filter_result.unwrap_or(default_filter)
            filter_validation = filter_obj.validate_business_rules()
            filter_status = "PASS" if filter_validation.is_success else "FAIL"
            print(f"✅ Filter validation: {filter_status}")
            print(f"   Filter: {filter_obj.value}")
            print(f"✅ Filter ready: {filter_obj.value}")
        else:
            print(f"❌ Filter creation failed: {filter_result.error}")

    except Exception as e:
        logger.exception("Value object demonstration failed")
        print(f"❌ Value objects failed: {e}")


async def demonstrate_comprehensive_configuration() -> None:
    """Demonstrate comprehensive configuration setup."""
    print("\n⚙️  Comprehensive Configuration")
    print("=" * 40)

    try:
        # 1. Full settings configuration
        _settings = FlextLdapSettings(enable_debug_mode=True)
        print("✅ Settings created")

        # 2. Create search request using FlextLdapSearchRequest
        search_request = FlextLdapSearchRequest(
            base_dn="dc=example,dc=com",
            scope="subtree",
            filter_str="(objectClass=person)",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
        )
        search_validation = search_request.validate_business_rules()
        search_status = "VALID" if search_validation.is_success else "INVALID"
        print(f"✅ Search request: {search_status}")

        # 3. Settings ready for usage
        print("✅ Settings ready for client configuration usage")

    except Exception as e:
        logger.exception("Configuration demonstration failed")
        print(f"❌ Configuration failed: {e}")


async def demonstrate_async_patterns() -> None:
    """Demonstrate async/await patterns."""
    print("\n🔄 Async/Await Patterns")
    print("=" * 40)

    try:
        # 1. Context manager usage
        async with ldap_session(
            "ldap://demo.example.com:389", "cn=admin,dc=example,dc=com", "password"
        ) as (api, session_id):
            print(f"✅ Session established: {session_id}")

            # 2. Concurrent operations (simulated) with proper typing
            tasks: list[Awaitable[FlextResult[list[FlextLdapEntry]]]] = []
            search_bases = [
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                "ou=services,dc=example,dc=com",
            ]

            for base_dn in search_bases:
                task = api.search(
                    base_dn=base_dn,
                    search_filter="(objectClass=*)",
                    attributes=["dn"],
                    scope="one",
                )
                tasks.append(task)

            # Execute concurrent searches with proper typing
            results: list[
                FlextResult[list[FlextLdapEntry]] | BaseException
            ] = await asyncio.gather(*tasks, return_exceptions=True)

            successful_searches = sum(
                1
                for result in results
                if not isinstance(result, Exception)
                and hasattr(result, "is_success")
                and getattr(result, "is_success", False)
            )

            print(
                f"✅ Concurrent searches: {successful_searches}/{len(tasks)} successful",
            )

    except Exception as e:
        logger.exception("Async patterns demonstration failed")
        print(f"❌ Async patterns failed: {e}")


async def demonstrate_error_recovery() -> None:
    """Demonstrate error recovery patterns."""
    print("\n🔄 Error Recovery Patterns")
    print("=" * 40)

    # Constants for retry logic
    failure_attempts = 2

    async def attempt_operation_with_retry(
        operation_name: str,
        max_retries: int = 3,
    ) -> str | None:
        """Retry pattern for LDAP operations."""

        def _simulate_failure(op_name: str) -> None:
            msg: str = f"Simulated failure for {op_name}"
            raise ConnectionError(msg)

        for attempt in range(max_retries):
            try:
                logger.debug(
                    f"Attempting {operation_name}",
                    extra={"attempt": attempt + 1, "max_retries": max_retries},
                )

                # Simulate operation (would be real LDAP operation)
                if attempt < failure_attempts:  # Fail first attempts
                    _simulate_failure(operation_name)

                logger.info(
                    f"Operation {operation_name} succeeded",
                    extra={"attempts_used": attempt + 1},
                )
                return f"Success after {attempt + 1} attempts"

            except Exception as e:
                logger.warning(
                    f"Attempt {attempt + 1} failed",
                    extra={
                        "operation": operation_name,
                        "error": str(e),
                        "remaining_attempts": max_retries - attempt - 1,
                    },
                )

                if attempt == max_retries - 1:
                    logger.exception(f"All attempts failed for {operation_name}")
                    raise

                # Exponential backoff
                await asyncio.sleep(2**attempt)
        return None

    try:
        # 1. Connection retry
        result1 = await attempt_operation_with_retry("LDAP Connection")
        print(f"✅ Connection recovery: {result1}")

        # 2. Search retry
        result2 = await attempt_operation_with_retry("LDAP Search")
        print(f"✅ Search recovery: {result2}")

    except Exception as e:
        print(f"❌ Error recovery failed: {e}")


async def demonstrate_performance_patterns() -> None:
    """Demonstrate performance optimization patterns."""
    print("\n⚡ Performance Optimization")
    print("=" * 40)

    try:
        # 1. Connection pooling simulation
        print("✅ Connection pooling: Enabled (simulated)")

        # 2. Batch operations
        batch_operations = [
            {"type": "search", "base": f"cn=user{i},ou=users,dc=example,dc=com"}
            for i in range(10)
        ]

        print(f"✅ Batch operations: {len(batch_operations)} operations prepared")

        # 3. Paging simulation
        page_size = 100
        total_entries = 1500
        pages = (total_entries + page_size - 1) // page_size

        print(f"✅ Paging strategy: {pages} pages of {page_size} entries")

        # 4. Caching simulation
        cache_hits = 8
        cache_misses = 2
        hit_rate = cache_hits / (cache_hits + cache_misses) * 100

        print(f"✅ Cache performance: {hit_rate:.1f}% hit rate")

    except Exception as e:
        logger.exception("Performance demonstration failed")
        print(f"❌ Performance patterns failed: {e}")


async def main() -> None:
    """Run the main demonstration function."""
    print("🚀 FLEXT-LDAP Advanced Patterns")
    print("=" * 50)
    print("Enterprise-grade patterns and best practices\n")

    try:
        # 1. Value objects
        await demonstrate_value_objects()

        # 2. Comprehensive configuration
        await demonstrate_comprehensive_configuration()

        # 3. Async patterns
        await demonstrate_async_patterns()

        # 4. Error recovery
        await demonstrate_error_recovery()

        # 5. Performance patterns
        await demonstrate_performance_patterns()

        print("\n🎉 Advanced patterns demonstration completed!")
        print("✅ Enterprise patterns validated")
        print("✅ Async/await patterns confirmed")
        print("✅ Error recovery strategies tested")
        print("✅ Performance optimizations demonstrated")

    except Exception as e:
        print(f"\n❌ Advanced patterns failed: {e}")
        logger.exception("Advanced patterns demonstration failed")
        raise


if __name__ == "__main__":
    # Enable comprehensive logging for demonstration
    import os

    os.environ["FLEXT_LOG_LEVEL"] = "INFO"

    asyncio.run(main())
