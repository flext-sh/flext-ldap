"""LDAP Schema Management Module.

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
    schema = discovery.discover_from_server("ldap://server:389")
    
    # Compare with target schema
    comparator = SchemaComparator()
    differences = comparator.compare_schemas(source_schema, target_schema)
    ```
"""

# Import classes that are actually implemented
try:
    from .discovery import SchemaDiscovery
    from .parser import SchemaParser
    from .validator import SchemaValidator
    from .comparator import SchemaComparator
    from .migrator import SchemaMigrator
    from .analyzer import SchemaAnalyzer
    
    __all__ = [
        "SchemaDiscovery",
        "SchemaParser",
        "SchemaValidator", 
        "SchemaComparator",
        "SchemaMigrator",
        "SchemaAnalyzer",
    ]
except ImportError:
    # If modules are not yet implemented, provide empty list
    __all__ = [] 
