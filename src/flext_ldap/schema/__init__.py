from flext_ldap.utils.constants import LDAP_DEFAULT_PORT

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
    from flext_ldaprt SchemaDiscovery, SchemaComparator

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
    from flext_ldaparator import SchemaComparator
    from flext_ldapator import SchemaMigrator
    from flext_ldapdator import SchemaValidator
    from flext_ldaper import SchemaParser
    from flext_ldapovery import SchemaDiscovery
    from flext_ldapyzer import SchemaAnalyzer

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
