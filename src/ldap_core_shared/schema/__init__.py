from ldap_core_shared.utils.constants import LDAP_DEFAULT_PORT

"""LDAP Schema Management Module.

# Constants for magic values

This module provides comprehensive LDAP schema management capabilities including
schema discovery, validation, comparison, and migration support.

Key Features:
    - Schema discovery from LDAP servers
    - RFC 2252 compliant schema parsing
    - Schema validation and compatibility checking
    - Schema comparison and difference analysis
    - Migration planning and LDIF generation
    - Schema transformation and optimization

Components:
    - SchemaDiscovery: Discover schemas from LDAP servers
    - SchemaParser: Parse and validate schema definitions
    - SchemaValidator: Comprehensive schema validation
    - SchemaComparator: Compare schemas and find differences
    - SchemaMigrator: Generate migration plans and LDIF
    - SchemaAnalyzer: Advanced schema analysis and optimization

Example:
    ```python
    from ldap_core_shared.schema import SchemaDiscovery, SchemaComparator

    # Discover schema from server
    discovery = SchemaDiscovery()
    schema = discovery.discover_from_server("ldap://server:LDAP_DEFAULT_PORT")

    # Compare with target schema
    comparator = SchemaComparator()
    differences = comparator.compare_schemas(source_schema, target_schema)
    ```
"""

# Import classes that are actually implemented
try:
    from ldap_core_shared.schema.analyzer import SchemaAnalyzer
    from ldap_core_shared.schema.comparator import SchemaComparator
    from ldap_core_shared.schema.discovery import SchemaDiscovery
    from ldap_core_shared.schema.migrator import SchemaMigrator
    from ldap_core_shared.schema.parser import SchemaParser
    from ldap_core_shared.schema.validator import SchemaValidator

    __all__ = [
        "SchemaAnalyzer",
        "SchemaComparator",
        "SchemaDiscovery",
        "SchemaMigrator",
        "SchemaParser",
        "SchemaValidator",
    ]
except ImportError:
    # If modules are not yet implemented, provide empty list
    __all__ = []
