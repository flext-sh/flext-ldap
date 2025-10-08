#!/usr/bin/env python3
"""Connection Management Example - flext-ldap API.

This example demonstrates advanced LDAP connection management patterns:
- Connection lifecycle management
- Health checks and automatic reconnection
- Connection state monitoring
- Graceful connection handling
- Resource cleanup patterns
- Connection configuration management

Uses api.py (FlextLdap) as the primary interface.

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: REDACTED_LDAP_BIND_PASSWORD)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/10_connection_management.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import sys
import time
from typing import Final

from flext_core import FlextLogger
from pydantic import SecretStr

from flext_ldap import FlextLdap, FlextLdapConfig

logger: FlextLogger = FlextLogger(__name__)

# Configuration from environment
LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:389")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")
BIND_PASSWORD: Final[str] = os.getenv("LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD")
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def demonstrate_basic_connection_lifecycle() -> None:
    """Demonstrate basic connection lifecycle management.

    Shows proper connection, usage, and disconnection patterns.

    """
    logger.info("=== Basic Connection Lifecycle ===")

    # Create configuration
    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )

    # Create API instance
    api = FlextLdap(config=config)

    logger.info("\n1. Connecting to LDAP server...")
    connect_result = api.connect()

    if connect_result.is_failure:
        logger.error(f"   ❌ Connection failed: {connect_result.error}")
        return

    logger.info("   ✅ Connected successfully")

    # Use connection
    logger.info("\n2. Using connection...")
    try:
        # Perform operation to verify connection
        search_result = api.search(
            search_base=BASE_DN, filter_str="(objectClass=*)", attributes=["dn"]
        )

        if search_result.is_success:
            entries = search_result.unwrap()
            logger.info(f"   ✅ Connection active - found {len(entries)} entries")
        else:
            logger.warning(f"   ⚠️  Search failed: {search_result.error}")

    finally:
        # Always disconnect (resource cleanup)
        logger.info("\n3. Disconnecting...")
        if api.is_connected():
            api.unbind()
            logger.info("   ✅ Disconnected successfully")
        else:
            logger.info("   ℹ Already disconnected")


def demonstrate_connection_state_monitoring() -> None:
    """Demonstrate connection state monitoring and validation."""
    logger.info("\n=== Connection State Monitoring ===")

    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap(config=config)

    logger.info("\n1. Initial state (before connection):")
    logger.info(f"   Is connected: {api.is_connected()}")

    logger.info("\n2. Connecting...")
    connect_result = api.connect()

    if connect_result.is_success:
        logger.info("   ✅ Connection established")
        logger.info(f"   Is connected: {api.is_connected()}")

        logger.info("\n3. Performing health check...")
        # Simple health check - try to search root DSE
        health_result = api.search(
            search_base="", filter_str="(objectClass=*)", attributes=["*"]
        )

        if health_result.is_success:
            logger.info("   ✅ Health check passed - connection is healthy")
        else:
            logger.warning(f"   ⚠️  Health check failed: {health_result.error}")

        logger.info("\n4. Disconnecting...")
        api.unbind()
        logger.info(f"   Is connected: {api.is_connected()}")

    else:
        logger.error(f"   ❌ Connection failed: {connect_result.error}")


def demonstrate_connection_error_handling() -> None:
    """Demonstrate connection error handling patterns."""
    logger.info("\n=== Connection Error Handling ===")

    logger.info("\n1. Invalid server URI:")
    invalid_config = FlextLdapConfig(
        ldap_server_uri="ldap://invalid-server:389",
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap(config=invalid_config)

    connect_result = api.connect()
    if connect_result.is_failure:
        logger.info(f"   ✅ Error handled correctly: {connect_result.error}")
    else:
        logger.warning("   ⚠️  Expected connection to fail")

    logger.info("\n2. Invalid credentials:")
    invalid_creds = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr("wrong_password"),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap(config=invalid_creds)

    connect_result = api.connect()
    if connect_result.is_failure:
        logger.info(f"   ✅ Authentication error handled: {connect_result.error}")
    else:
        logger.warning("   ⚠️  Expected authentication to fail")

    logger.info("\n3. Connection timeout handling:")
    timeout_config = FlextLdapConfig(
        ldap_server_uri="ldap://192.0.2.1:389",  # TEST-NET-1 (non-routable)
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap(config=timeout_config)

    logger.info("   Attempting connection (will timeout)...")
    start_time = time.time()
    connect_result = api.connect()
    elapsed = time.time() - start_time

    if connect_result.is_failure:
        logger.info(f"   ✅ Timeout handled ({elapsed:.2f}s): {connect_result.error}")
    else:
        logger.warning("   ⚠️  Expected connection to timeout")


def demonstrate_connection_context_manager() -> None:
    """Demonstrate connection management using context manager pattern."""
    logger.info("\n=== Connection Context Manager Pattern ===")

    logger.info("\n1. Using connection as context manager (recommended):")

    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )

    # Note: FlextLdap doesn't implement __enter__/__exit__ yet,
    # so we demonstrate the pattern manually
    api = FlextLdap(config=config)

    try:
        logger.info("   Connecting...")
        connect_result = api.connect()

        if connect_result.is_failure:
            logger.error(f"   ❌ Connection failed: {connect_result.error}")
            return

        logger.info("   ✅ Connected (context entered)")

        # Perform operations
        search_result = api.search(
            search_base=BASE_DN, filter_str="(objectClass=*)", attributes=["dn"]
        )

        if search_result.is_success:
            entries = search_result.unwrap()
            logger.info(f"   ✅ Operations completed - {len(entries)} entries")

    finally:
        # Cleanup guaranteed even if exception occurs
        if api.is_connected():
            api.unbind()
            logger.info("   ✅ Disconnected (context exited)")


def demonstrate_connection_retry_pattern() -> None:
    """Demonstrate connection retry pattern with exponential backoff."""
    logger.info("\n=== Connection Retry Pattern ===")

    config = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )

    max_retries = 3
    base_delay = 1.0  # seconds

    logger.info(f"\n1. Attempting connection with retry (max {max_retries} attempts):")

    api = FlextLdap(config=config)
    connected = False

    for attempt in range(1, max_retries + 1):
        logger.info(f"   Attempt {attempt}/{max_retries}...")

        connect_result = api.connect()

        if connect_result.is_success:
            logger.info("   ✅ Connected successfully")
            connected = True
            break

        logger.warning(f"   ⚠️  Attempt {attempt} failed: {connect_result.error}")

        if attempt < max_retries:
            delay = base_delay * (2 ** (attempt - 1))  # Exponential backoff
            logger.info(f"   Waiting {delay:.1f}s before retry...")
            time.sleep(delay)

    if connected:
        logger.info("\n2. Connection established - performing cleanup:")
        if api.is_connected():
            api.unbind()
            logger.info("   ✅ Disconnected")
    else:
        logger.error(f"\n❌ Failed to connect after {max_retries} attempts")


def demonstrate_multiple_connections() -> None:
    """Demonstrate managing multiple LDAP connections."""
    logger.info("\n=== Multiple Connections Management ===")

    # Create two different connection configurations
    config1 = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )

    config2 = FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=SecretStr(BIND_PASSWORD),
        ldap_base_dn=BASE_DN,
    )

    logger.info("\n1. Creating multiple API instances:")
    api1 = FlextLdap(config=config1)
    api2 = FlextLdap(config=config2)

    logger.info("   ✅ Two independent API instances created")

    logger.info("\n2. Connecting both instances:")
    result1 = api1.connect()
    result2 = api2.connect()

    if result1.is_success and result2.is_success:
        logger.info("   ✅ Both connections established")

        logger.info("\n3. Using connections independently:")
        logger.info(f"   Connection 1 active: {api1.is_connected()}")
        logger.info(f"   Connection 2 active: {api2.is_connected()}")

        logger.info("\n4. Cleanup - disconnecting both:")
        if api1.is_connected():
            api1.unbind()
            logger.info("   ✅ Connection 1 closed")

        if api2.is_connected():
            api2.unbind()
            logger.info("   ✅ Connection 2 closed")

    else:
        logger.error("   ❌ One or both connections failed")
        if api1.is_connected():
            api1.unbind()
        if api2.is_connected():
            api2.unbind()


def demonstrate_async_connection_patterns() -> None:
    """Demonstrate asynchronous connection patterns (future implementation)."""
    logger.info("\n=== Async Connection Patterns (Conceptual) ===")

    logger.info("\n1. Async connection pattern structure:")
    logger.info("   • Connection establishment in background")
    logger.info("   • Non-blocking LDAP operations")
    logger.info("   • Concurrent connection management")
    logger.info("   • Async health checks and monitoring")

    logger.info("\n2. Benefits of async patterns:")
    logger.info("   • Better resource utilization")
    logger.info("   • Improved application responsiveness")
    logger.info("   • Efficient connection pooling")
    logger.info("   • Scalable LDAP operations")

    logger.info("\n   ℹ Full async support planned for future releases")


def demonstrate_connection_pooling_concept() -> None:
    """Demonstrate connection pooling concept (educational)."""
    logger.info("\n=== Connection Pooling Concept ===")

    logger.info("\n1. Connection pooling benefits:")
    logger.info("   • Reduced connection overhead")
    logger.info("   • Better resource management")
    logger.info("   • Improved application performance")
    logger.info("   • Connection reuse across operations")

    logger.info("\n2. Pool configuration considerations:")
    logger.info("   • Minimum pool size (always available connections)")
    logger.info("   • Maximum pool size (prevent resource exhaustion)")
    logger.info("   • Connection timeout (idle connection cleanup)")
    logger.info("   • Validation on borrow (health check)")

    logger.info("\n3. Current implementation:")
    logger.info("   • FlextLdap manages single connection per instance")
    logger.info("   • Multiple instances can be used for pooling effect")
    logger.info("   • Proper lifecycle management is essential")

    logger.info("\n   ℹ Dedicated connection pool implementation planned")


def main() -> int:
    """Run connection management demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 70)
    logger.info("FLEXT-LDAP Connection Management Example")
    logger.info("=" * 70)
    logger.info("Demonstrates: Connection lifecycle, monitoring, error handling")
    logger.info("Modules: connection_manager.py (conceptual), api.py")
    logger.info("=" * 70)

    try:
        # 1. Basic lifecycle
        demonstrate_basic_connection_lifecycle()

        # 2. State monitoring
        demonstrate_connection_state_monitoring()

        # 3. Error handling
        demonstrate_connection_error_handling()

        # 4. Context manager pattern
        demonstrate_connection_context_manager()

        # 5. Retry pattern
        demonstrate_connection_retry_pattern()

        # 6. Multiple connections
        demonstrate_multiple_connections()

        # 7. Async patterns (conceptual)
        demonstrate_async_connection_patterns()

        # 8. Pooling concept
        demonstrate_connection_pooling_concept()

        logger.info(f"\n{'=' * 70}")
        logger.info("✅ Connection management demonstration completed!")
        logger.info("=" * 70)

        logger.info("\nKey Takeaways:")
        logger.info("  • Always disconnect connections (resource cleanup)")
        logger.info("  • Use is_connected() to monitor connection state")
        logger.info("  • Handle connection errors explicitly with FlextResult")
        logger.info("  • Implement retry logic for resilient connections")
        logger.info("  • Proper lifecycle management prevents resource leaks")

        logger.info("\nConnection Lifecycle Best Practices:")
        logger.info("  1. Create FlextLdapConfig with connection parameters")
        logger.info("  2. Initialize FlextLdap with config")
        logger.info("  3. Call connect() and check FlextResult")
        logger.info("  4. Perform LDAP operations")
        logger.info("  5. Always call unbind() in finally block")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
