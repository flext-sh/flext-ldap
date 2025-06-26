"""LDAP API Package - True Facade Pattern Implementation.

This package implements a proper Facade pattern by breaking down the monolithic
api.py into specialized modules, each with single responsibility.

ARCHITECTURE:
- api/config.py → LDAPConfig Value Object ✅
- api/results.py → Result[T] pattern ✅
- api/query.py → Query Builder pattern ✅
- api/operations.py → LDAP operations (delegates to existing subsystems) ✅
- api/validation.py → Schema validation (delegates to existing modules) ✅
- api/facade.py → True Facade (~400 lines, pure delegation) ✅

PRINCIPLES:
- Each module has single responsibility ✅
- Facade only delegates, no business logic ✅
- Maintains 100% API compatibility ✅
- Uses existing subsystem modules (connections, domain, etc.) ✅

REFACTORING COMPLETED:
- Phase 1: Extract config, results, query ✅
- Phase 2: Extract operations and validation ✅
- Phase 3: Create thin facade that delegates ✅
- Phase 4: Ready to replace monolithic api.py ✅
"""

# Re-export the extracted components for full compatibility
from ldap_core_shared.api.config import LDAPConfig

# Import the true facade
from ldap_core_shared.api.facade import (
    LDAP,
    connect,
    ldap_session,
    validate_ldap_config,
)
from ldap_core_shared.api.query import Query
from ldap_core_shared.api.results import Result

# Import migration-related API components for algar-oud-mig compatibility
from ldap_core_shared.ldif.processor import LDIFProcessor, LDIFProcessingConfig
from ldap_core_shared.ldif.writer import LDIFWriter, LDIFWriterConfig, LDIFHeaderConfig
from ldap_core_shared.schema.migrator import SchemaMigrator, MigrationPlan
from ldap_core_shared.exceptions.migration import (
    MigrationError,
    SchemaValidationError,
    DataIntegrityError,
)
# Import connection and utility modules for compatibility
from ldap_core_shared.connections.manager import ConnectionManager
from ldap_core_shared.utils.dn_utils import normalize_dn, parse_dn, is_child_dn, get_parent_dn, validate_dn_format
from ldap_core_shared.utils.performance import PerformanceMonitor
from ldap_core_shared.utils.ldap_validation import (
    validate_and_normalize_ldap_entry,
    validate_and_normalize_attribute_name,
    validate_and_normalize_attribute_value,
    validate_dn,
    validate_and_normalize_file_path,
    validate_configuration_value,
    PathValidationError,
    ConfigValidationError,
)

__all__ = [
    # Main facade and convenience functions
    "LDAP",                 # True Facade (pure delegation)
    # Core components
    "LDAPConfig",           # Value Object for configuration
    "Query",                # Builder Pattern for queries
    "Result",               # Value Object for results
    "connect",              # Factory method for quick connections
    "ldap_session",         # Context manager factory
    "validate_ldap_config", # Configuration validation
    # Migration API for algar-oud-mig compatibility
    "LDIFProcessor",        # LDIF processing functionality
    "LDIFProcessingConfig", # LDIF processor configuration
    "LDIFWriter",           # LDIF writing functionality
    "LDIFWriterConfig",     # LDIF writer configuration
    "LDIFHeaderConfig",     # LDIF header configuration
    "SchemaMigrator",       # Schema migration functionality
    "MigrationPlan",        # Migration planning
    "MigrationError",       # Migration exceptions
    "SchemaValidationError", # Schema validation exceptions
    "DataIntegrityError",   # Data integrity exceptions
    # Connection and utility API
    "ConnectionManager",     # Connection management
    "normalize_dn",         # DN normalization
    "parse_dn",             # DN parsing
    "is_child_dn",          # DN hierarchy checking
    "get_parent_dn",        # DN parent extraction
    "validate_dn_format",   # DN validation
    "PerformanceMonitor",   # Performance monitoring
    # LDAP validation utilities
    "validate_and_normalize_ldap_entry",     # Complete entry validation
    "validate_and_normalize_attribute_name", # Attribute name validation
    "validate_and_normalize_attribute_value", # Attribute value validation
    "validate_dn",          # DN validation with normalization
    "validate_and_normalize_file_path",      # File path validation
    "validate_configuration_value",          # Configuration validation
    "PathValidationError",  # Path validation exception
    "ConfigValidationError", # Config validation exception
]
