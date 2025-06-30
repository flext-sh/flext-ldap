"""LDAP Async Operations Module.

This module provides comprehensive asynchronous LDAP operations following
perl-ldap async patterns with enterprise-grade non-blocking operations,
callback handling, and high-performance concurrent processing.

Async operations enable non-blocking LDAP operations with callbacks and
futures, essential for high-performance applications and concurrent
processing without blocking the main thread.

Architecture:
    - AsyncLDAPOperations: Main async operations manager
    - AsyncResult: Future-like result objects for async operations
    - CallbackManager: Callback handling and event dispatching
    - ConcurrentProcessor: High-performance concurrent operation processing

Usage Example:
    >>> from flext_ldap.async_ops import AsyncLDAPOperations
    >>>
    >>> # Async operations with callbacks
    >>> async_ops = AsyncLDAPOperations(connection)
    >>>
    >>> # Non-blocking search with callback
    >>> def search_callback(result):
    ...     print(f"Search completed: {len(result.entries)} entries found")
    >>>
    >>> search_future = async_ops.search_async(
    ...     "ou=users,dc=example,dc=com",
    ...     "(objectClass=person)",
    ...     callback=search_callback
    ... )
    >>>
    >>> # Continue with other work while search executes
    >>> # ... other operations ...
    >>>
    >>> # Wait for completion if needed
    >>> result = await search_future

References:
    - perl-ldap: lib/Net/LDAP.pod (async mode, lines 123-125, 891-895)
    - asyncio: Python asynchronous I/O framework
    - Enterprise async processing patterns
"""

from typing import TYPE_CHECKING

from flext_ldapallbacks import CallbackManager, CallbackRegistry

# Import async operation components
from flext_ldap.domain.results import Result

__all__ = [
    # Core async operations
    "AsyncLDAPOperations",
    "AsyncResult",
    "CallbackManager",
    "CallbackRegistry",
]
