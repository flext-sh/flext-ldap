#!/usr/bin/env python3
"""Advanced FLEXT-LDAP Patterns Example.

This example demonstrates advanced usage patterns:
- Complex configurations
- /patterns
- Context managers
- Enterprise error handling
- Performance optimizations
- Production best practices

Usage:
    python examples/06_advanced_patterns.py

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from flext_ldap.clients import FlextLDAPClient
from flext_ldap.config import FlextLDAPConfig
from flext_ldap.models import FlextLDAPModels

from flext_core import FlextLogger, FlextResult

logger = FlextLogger(__name__)


@contextmanager
def ldap_session(
    server_url: str,
    bind_dn: str,
    password: str,
) -> Iterator[tuple[FlextLDAPClient, str]]:
    """Enterprise LDAP session context manager.

    Provides automatic connection management with proper cleanup.

    Yields:
        tuple[FlextLDAPClient, str]: A tuple containing the LDAP API instance and session ID.

    """
    api = FlextLDAPClient()
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
        connection_result: FlextResult[bool] = api.connect(
            server_uri=server_url,
            bind_dn=bind_dn,
            password=password,
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
            api.unbind()
            logger.info("LDAP session closed", extra={"session_id": session_id})
        except Exception as e:
            logger.warning(
                "Session cleanup failed",
                extra={"error": str(e), "session_id": session_id},
            )


def demonstrate_value_objects() -> None:
    """Demonstrate value object usage."""
    try:
        # 1. Distinguished Names
        dn = FlextLDAPModels.DistinguishedName(
            value="cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example,dc=com",
        )
        # DistinguishedName doesn't have validate_business_rules method
        logger.debug(f"Created DN: {dn.value}")

        # 2. LDAP Filters - Using correct FlextLDAPFilter class
        complex_filter = "(&(objectClass=person)(mail=*@example.com))"
        try:
            filter_obj = FlextLDAPModels.Filter(expression=complex_filter)
            logger.debug(f"Using filter: {filter_obj.expression}")
        except ValueError as e:
            logger.warning(f"Invalid filter: {e}")
            filter_obj = FlextLDAPModels.Filter(expression="(objectClass=*)")

    except Exception:
        logger.exception("Value object demonstration failed")


def demonstrate_comprehensive_configuration() -> None:
    """Demonstrate comprehensive configuration setup."""
    try:
        # 1. Full settings configuration
        _settings = FlextLDAPConfig()

        # 2. Create search request using FlextLDAPSearchRequest
        search_request = FlextLDAPModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "mail"],
            size_limit=100,
            time_limit=30,
            page_size=None,
            paged_cookie=None,
        )
        # SearchRequest uses Pydantic field validation automatically
        logger.debug(f"Search configured for {search_request.base_dn}")

        # 3. Settings ready for usage

    except Exception:
        logger.exception("Configuration demonstration failed")


def demonstrate_patterns() -> None:
    """Demonstrate /patterns."""
    try:
        # 1. Context manager usage
        with ldap_session(
            "ldap://demo.example.com:389",
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "password",
        ) as (api, _session_id):
            # 2. Concurrent operations (simulated) with proper typing
            tasks: list[FlextResult[list[FlextLDAPModels.Entry]]] = []
            search_bases = [
                "ou=users,dc=example,dc=com",
                "ou=groups,dc=example,dc=com",
                "ou=services,dc=example,dc=com",
            ]

            for base_dn in search_bases:
                task = api.search(
                    base_dn=base_dn,
                    filter_str="(objectClass=*)",
                    attributes=["dn"],
                )
                tasks.append(task)

            # Execute concurrent searches synchronously
            results = tasks

            sum(
                1
                for result in results
                if not isinstance(result, Exception)
                and hasattr(result, "success")
                and getattr(result, "success", False)
            )

    except Exception:
        logger.exception("patterns demonstration failed")


def demonstrate_error_recovery() -> None:
    """Demonstrate error recovery patterns."""
    # Constants for retry logic
    failure_attempts = 2

    def attempt_operation_with_retry(
        operation_name: str,
        max_retries: int = 3,
    ) -> str | None:
        """Retry pattern for LDAP operations.

        Returns:
            Union[str, None]: Success message or None if all retries failed.

        """

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
                import time

                time.sleep(2**attempt)
        return None

    try:
        # 1. Connection retry
        attempt_operation_with_retry("LDAP Connection")

        # 2. Search retry
        attempt_operation_with_retry("LDAP Search")

    except Exception:
        logger.exception("Error handling patterns demonstration failed")


def demonstrate_performance_patterns() -> None:
    """Demonstrate performance optimization patterns."""
    try:
        # 1. Connection pooling simulation

        # 2. Batch operations
        [
            {"type": "search", "base": f"cn=user{i},ou=users,dc=example,dc=com"}
            for i in range(10)
        ]

        # 3. Paging simulation
        page_size = 100
        total_entries = 1500
        total_pages = (total_entries + page_size - 1) // page_size
        logger.debug(f"Pagination: {total_pages} pages for {total_entries} entries")

        # 4. Caching simulation
        cache_hits = 8
        cache_misses = 2
        cache_hit_rate = cache_hits / (cache_hits + cache_misses) * 100
        logger.debug(f"Cache performance: {cache_hit_rate:.1f}% hit rate")

    except Exception:
        logger.exception("Performance demonstration failed")


def main() -> None:
    """Run the main demonstration function."""
    try:
        # 1. Value objects
        demonstrate_value_objects()

        # 2. Comprehensive configuration
        demonstrate_comprehensive_configuration()

        # 3. patterns
        demonstrate_patterns()

        # 4. Error recovery
        demonstrate_error_recovery()

        # 5. Performance patterns
        demonstrate_performance_patterns()

    except Exception:
        logger.exception("Advanced patterns demonstration failed")
        raise


if __name__ == "__main__":
    # Enable comprehensive logging for demonstration
    import os

    os.environ["FLEXT_LOG_LEVEL"] = "INFO"

    main()
