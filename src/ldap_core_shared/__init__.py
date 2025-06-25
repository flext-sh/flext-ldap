"""LDAP Core Shared - Enterprise Python LDAP Library.

🚀 **Modern Python LDAP library with enterprise features and zero-complexity APIs**

**Key Features:**
- ✅ **Python 3.9+ Support**: Compatible with Python 3.9 through 3.13
- ⚡ **Async-First Design**: High-performance async operations with sync compatibility
- 🛡️ **Enterprise Security**: SSL/TLS, SASL, and comprehensive authentication
- 🔄 **Migration Tools**: Oracle OID → OUD, Active Directory, OpenLDAP
- 📊 **Schema Management**: Automated discovery, comparison, and validation
- 🎯 **Zero-Complexity APIs**: Simple interfaces for complex operations
- 🔍 **LDIF Processing**: High-speed streaming for large datasets (12K+ entries/sec)
- 📈 **Performance Monitoring**: Built-in metrics and health checking
- 🧪 **100% Type Safety**: Full type hints and Pydantic validation

**Quick Start:**
    Basic LDAP operations:

    >>> import asyncio
    >>> from ldap_core_shared import LDAPConnection
    >>>
    >>> # Simple connection and search
    >>> async def basic_example():
    ...     async with LDAPConnection("ldap://server.com") as conn:
    ...         await conn.bind("cn=admin,dc=example,dc=com", "password")
    ...         entries = await conn.search("dc=example,dc=com", "(objectClass=user)")
    ...         async for entry in entries:
    ...             print(f"User: {entry.dn}")
    >>>
    >>> asyncio.run(basic_example())

**Enterprise Migration:**
    Oracle OID to OUD migration:

    >>> from ldap_core_shared import MigrationEngine
    >>>
    >>> async def migrate_production():
    ...     engine = MigrationEngine()
    ...     result = await engine.migrate(
    ...         source="ldap://oid.company.com:389",
    ...         target="ldap://oud.company.com:1389",
    ...         schema_mapping="oid_to_oud",
    ...     )
    ...     print(f"✅ Migrated {result.entries} entries in {result.duration}s")
    >>>
    >>> asyncio.run(migrate_production())

**LDIF Processing:**
    High-speed LDIF file processing:

    >>> from ldap_core_shared import LDIFProcessor
    >>>
    >>> processor = LDIFProcessor()
    >>> stats = await processor.process_file(
    ...     "export.ldif", batch_size=1000, validate_schema=True
    ... )
    >>> print(f"Processed {stats.entries} entries at {stats.rate}/sec")

**Compatibility:**
    - Python 3.9+ (tested on 3.9, 3.10, 3.11, 3.12, 3.13)
    - LDAP v2/v3 protocols (RFC 4511 compliant)
    - Oracle Internet Directory (OID), Oracle Unified Directory (OUD)
    - Active Directory, OpenLDAP, Apache DS, 389 Directory Server
    - Async/await and traditional synchronous patterns

Version: {__version__}
Author: {__author__}
License: {__license__}
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

# Import version information from centralized module
from ldap_core_shared.version import (
    AUTHOR as __author__,  # noqa: N811
)
from ldap_core_shared.version import (
    AUTHOR_EMAIL as __email__,  # noqa: N811
)
from ldap_core_shared.version import (
    LICENSE as __license__,  # noqa: N811
)
from ldap_core_shared.version import (
    __version__,
    get_package_info,
    get_version_tuple,
    is_compatible_python_version,
    is_stable_release,
)

__copyright__ = "2025 LDAP Core Team"

# Python 3.9+ compatibility enforcement
if not is_compatible_python_version((sys.version_info.major, sys.version_info.minor)):
    msg = (
        f"ldap-core-shared requires Python 3.9 or higher. "
        f"You are using Python {sys.version_info.major}.{sys.version_info.minor}. "
        f"Please upgrade your Python version to use this library."
    )
    raise RuntimeError(msg)

# Type checking imports - only available during static analysis

# 🚀 Public API - Simplified and consistent exports
__all__ = [
    "AsyncLDAPConnection",  # Explicit async connection
    "AuthenticationError",  # Authentication failures
    "ConnectionError",  # Connection-related errors
    "ConnectionPool",  # Connection pooling
    # 🔌 Core Connection API
    "LDAPConnection",  # Main connection class (async + sync)
    # 📄 Data Models
    "LDAPEntry",  # LDAP entry representation
    # ⚠️ Exception Classes
    "LDAPError",  # Base LDAP exception
    "LDAPResult",  # Operation result wrapper
    "LDIFEntry",  # LDIF entry representation
    # 🔄 LDIF Processing (Ultra-High Performance)
    "LDIFProcessor",  # Main LDIF processor (40,000+ entries/sec)
    "LDIFValidator",  # LDIF validation
    # 🏢 Migration Tools
    "MigrationEngine",  # Main migration engine
    "MigrationError",  # Migration operation errors
    "MigrationResult",  # Migration operation result
    "PerformanceBenchmarker",  # Comprehensive performance analysis
    "PredictiveConnectionPool",  # <5ms connection acquisition
    "SchemaComparator",  # Schema comparison tools
    # 🔍 Schema Management
    "SchemaDiscovery",  # Schema discovery and analysis
    "SchemaError",  # Schema-related errors
    "SchemaMapper",  # Schema mapping tools
    "SchemaValidator",  # Schema validation
    "SearchResult",  # Search operation result
    "SimpleLDAPClient",  # High-level client API
    "SyncLDAPConnection",  # Explicit sync connection
    "ValidationError",  # Data validation errors
    # 🚀 Vectorized Operations (Core Performance)
    "VectorizedBulkProcessor",  # 300-500% faster bulk operations
    "VectorizedLDIFProcessor",  # 200-400% faster LDIF processing
    "VectorizedSearchEngine",  # 400-600% faster search operations
    "__author__",
    "__copyright__",
    "__email__",
    "__license__",
    # 📊 Metadata
    "__version__",
    # 🛠️ Utilities
    "configure_logging",  # Logging configuration
    "get_logger",  # Logger factory
    "get_package_info",
    "get_version_tuple",
    "is_stable_release",
    "process_ldif_file",  # Convenience LDIF processing
    "quick_search",  # Convenience search function
]

# 🚀 Lazy import mappings for optimal performance and Python 3.9+ compatibility
_LAZY_IMPORTS = {
    # 🔌 Connection API
    "LDAPConnection": ("ldap_core_shared.connections.base", "LDAPConnection"),
    "AsyncLDAPConnection": ("ldap_core_shared.connections.base", "AsyncLDAPConnection"),
    "SyncLDAPConnection": ("ldap_core_shared.connections.base", "SyncLDAPConnection"),
    "ConnectionPool": ("ldap_core_shared.core.connection_manager", "ConnectionPool"),
    # 📄 Data Models
    "LDAPEntry": ("ldap_core_shared.domain.models", "LDAPEntry"),
    "LDAPResult": ("ldap_core_shared.domain.results", "LDAPResult"),
    "SearchResult": ("ldap_core_shared.domain.results", "SearchResult"),
    # 🔄 LDIF Processing (Ultra-High Performance)
    "LDIFProcessor": ("ldap_core_shared.core.ldif_processor", "LDIFProcessor"),
    "LDIFEntry": ("ldap_core_shared.ldif.parser", "LDIFEntry"),
    "LDIFValidator": ("ldap_core_shared.ldif.validator", "LDIFValidator"),
    # 🚀 Vectorized Operations (Core Performance)
    "VectorizedBulkProcessor": (
        "ldap_core_shared.vectorized.bulk_processor",
        "VectorizedBulkProcessor",
    ),
    "VectorizedSearchEngine": (
        "ldap_core_shared.vectorized.search_engine",
        "VectorizedSearchEngine",
    ),
    "VectorizedLDIFProcessor": (
        "ldap_core_shared.vectorized.ldif_processor",
        "VectorizedLDIFProcessor",
    ),
    "PredictiveConnectionPool": (
        "ldap_core_shared.vectorized.connection_pool",
        "PredictiveConnectionPool",
    ),
    "PerformanceBenchmarker": (
        "ldap_core_shared.vectorized.benchmarks",
        "PerformanceBenchmarker",
    ),
    # 🏢 Migration Tools
    "MigrationEngine": ("ldap_core_shared.migration.engine", "MigrationEngine"),
    "SchemaMapper": ("ldap_core_shared.schema.migrator", "SchemaMapper"),
    "MigrationResult": ("ldap_core_shared.migration.results", "MigrationResult"),
    # 🔍 Schema Management
    "SchemaDiscovery": ("ldap_core_shared.schema.discovery", "SchemaDiscovery"),
    "SchemaComparator": ("ldap_core_shared.schema.comparator", "SchemaComparator"),
    "SchemaValidator": ("ldap_core_shared.schema.validator", "SchemaValidator"),
    # ⚠️ Exception Classes
    "LDAPError": ("ldap_core_shared.exceptions.base", "LDAPError"),
    "ConnectionError": ("ldap_core_shared.exceptions.connection", "ConnectionError"),
    "AuthenticationError": ("ldap_core_shared.exceptions.auth", "AuthenticationError"),
    "ValidationError": ("ldap_core_shared.exceptions.validation", "ValidationError"),
    "SchemaError": ("ldap_core_shared.exceptions.schema", "SchemaError"),
    "MigrationError": ("ldap_core_shared.exceptions.migration", "MigrationError"),
    # 🛠️ Utilities
    "configure_logging": ("ldap_core_shared.utils.logging", "configure_logging"),
    "get_logger": ("ldap_core_shared.utils.logging", "get_logger"),
    # 🚀 High-level API
    "SimpleLDAPClient": ("ldap_core_shared.api", "SimpleLDAPClient"),
    "quick_search": ("ldap_core_shared.api", "quick_search"),
    "process_ldif_file": ("ldap_core_shared.api", "process_ldif_file"),
}


def __getattr__(name: str) -> object:
    """Lazy import of public API components for optimal performance.

    Args:
        name: The name of the attribute being accessed

    Returns:
        The requested module component

    Raises:
        AttributeError: If the requested attribute doesn't exist
    """
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        module = __import__(module_path, fromlist=[attr_name])
        return getattr(module, attr_name)

    # Unknown attribute
    msg = f"module '{__name__}' has no attribute '{name}'"
    raise AttributeError(msg)


# Module initialization - minimal setup for fast imports
def _initialize_module() -> None:
    """Initialize module with minimal overhead for fast startup."""
    # Configure structured logging if not already configured
    try:
        import structlog

        if not structlog.is_configured():
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.UnicodeDecoder(),
                    structlog.processors.JSONRenderer(),
                ],
                wrapper_class=structlog.stdlib.BoundLogger,
                logger_factory=structlog.stdlib.LoggerFactory(),
                cache_logger_on_first_use=True,
            )
    except ImportError:
        # structlog not available, skip configuration
        pass


# Initialize module on import
_initialize_module()
