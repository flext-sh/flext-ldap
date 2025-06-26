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
from ldap_core_shared.api.config import LDAPConfig, MigrationConfig, validate_configuration_value, load_migration_config_from_env

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
from ldap_core_shared.ldif.transformer import TransformationRule, AttributeTransformRule
from ldap_core_shared.schema.migrator import SchemaMigrator, MigrationPlan
from ldap_core_shared.exceptions.migration import (
    MigrationError,
    SchemaValidationError,
    DataIntegrityError,
)

# Import new generic migration API components
from ldap_core_shared.api.processors import (
    BaseProcessor,
    LDIFProcessorBase,
    HierarchyProcessorBase,
    ACLProcessorBase,
    SchemaProcessorBase,
    create_processor_performance_monitor,
    finalize_processor_performance,
)

# Import generic migration orchestration
from ldap_core_shared.api.migration import (
    MigrationProcessor,
    GenericMigrationOrchestrator,
    GenericEntryProcessor,
    create_migration_config_from_env,
    validate_migration_setup,
)

# Import generic rules engine
from ldap_core_shared.api.rules_engine import (
    GenericRule,
    RuleExecutionContext,
    RuleProcessor,
    GenericRulesEngine,
    GenericRuleProcessor,
    create_rules_engine,
    validate_rules_file,
)
from ldap_core_shared.api.exceptions import (
    LDAPMigrationError,
    LDAPConnectionError,
    LDAPSchemaError,
    LDIFProcessingError,
    MigrationConfigurationError,
    MigrationValidationError,
    ProcessorError,
    HierarchyError,
    ACLProcessingError,
    PathValidationError,
    ConfigValidationError,
    create_detailed_error,
    log_migration_error,
    handle_migration_exception,
)
from ldap_core_shared.api.rules_manager import (
    BaseRulesManager,
    GenericRulesManager,
    CategoryRule,
    TransformationRule,
    create_rules_manager,
    validate_rules_file,
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
    "MigrationConfig",      # Generic migration configuration
    "Query",                # Builder Pattern for queries
    "Result",               # Value Object for results
    "connect",              # Factory method for quick connections
    "ldap_session",         # Context manager factory
    "validate_ldap_config", # Configuration validation
    "validate_configuration_value", # Generic configuration validation
    "load_migration_config_from_env", # Load config from environment
    # Migration API for algar-oud-mig compatibility
    "LDIFProcessor",        # LDIF processing functionality
    "LDIFProcessingConfig", # LDIF processor configuration
    "LDIFWriter",           # LDIF writing functionality
    "LDIFWriterConfig",     # LDIF writer configuration
    "LDIFHeaderConfig",     # LDIF header configuration
    "TransformationRule",   # LDIF transformation rules
    "AttributeTransformRule", # LDIF attribute transformation rules
    "SchemaMigrator",       # Schema migration functionality
    "MigrationPlan",        # Migration planning
    "MigrationError",       # Migration exceptions
    "SchemaValidationError", # Schema validation exceptions
    "DataIntegrityError",   # Data integrity exceptions
    # Generic processor framework
    "BaseProcessor",        # Base processor for migration projects
    "LDIFProcessorBase",    # Base LDIF processor
    "HierarchyProcessorBase", # Base hierarchy processor
    "ACLProcessorBase",     # Base ACL processor
    "SchemaProcessorBase",  # Base schema processor
    "create_processor_performance_monitor", # Performance monitoring
    "finalize_processor_performance", # Performance finalization
    # Generic migration orchestration
    "MigrationProcessor",   # Protocol for migration processors
    "GenericMigrationOrchestrator", # Generic migration orchestrator
    "GenericEntryProcessor", # Generic entry processor base
    "create_migration_config_from_env", # Create config from environment
    "validate_migration_setup", # Validate migration setup
    # Generic rules engine
    "GenericRule",          # Generic rule data class
    "RuleExecutionContext", # Rule execution context
    "RuleProcessor",        # Rule processor protocol
    "GenericRulesEngine",   # Generic rules engine
    "GenericRuleProcessor", # Generic rule processor base
    "create_rules_engine",  # Rules engine factory
    "validate_rules_file",  # Rules file validation
    # Generic exception framework
    "LDAPMigrationError",   # Base migration error
    "LDAPConnectionError",  # Connection errors
    "LDAPSchemaError",      # Schema errors
    "LDIFProcessingError",  # LDIF processing errors
    "MigrationConfigurationError", # Configuration errors
    "MigrationValidationError", # Validation errors
    "ProcessorError",       # Processor errors
    "HierarchyError",       # Hierarchy errors
    "ACLProcessingError",   # ACL processing errors
    "PathValidationError",  # Path validation errors
    "ConfigValidationError", # Config validation errors
    "create_detailed_error", # Error creation utility
    "log_migration_error",  # Error logging utility
    "handle_migration_exception", # Exception handling utility
    # Generic rules management framework
    "BaseRulesManager",     # Base rules manager
    "GenericRulesManager",  # Generic rules manager implementation
    "CategoryRule",         # Category rule data class
    "TransformationRule",   # Transformation rule data class
    "create_rules_manager", # Rules manager factory
    "validate_rules_file",  # Rules file validation
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
]
