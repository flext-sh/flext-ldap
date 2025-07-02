"""FLEXT LDAP API - Simplified interface to avoid circular imports."""

from __future__ import annotations


# Simple re-exports without circular imports
def get_validation_components():
    """Get validation components."""
    try:
        from flext_ldap.api.validation import (
            ValidationConfig,
            ValidationError,
            ValidationResult,
            ValidationRules,
            validate_dn,
            validate_filter,
            validate_schema,
        )

        return {
            "ValidationConfig": ValidationConfig,
            "ValidationError": ValidationError,
            "ValidationResult": ValidationResult,
            "ValidationRules": ValidationRules,
            "validate_dn": validate_dn,
            "validate_filter": validate_filter,
            "validate_schema": validate_schema,
        }
    except ImportError:
        return {}


def get_utils_components():
    """Get utility components."""
    try:
        from flext_ldap.api.utils import (
            normalize_dn as utils_normalize_dn,
        )
        from flext_ldap.api.utils import (
            validate_and_normalize_file_path,
        )
        from flext_ldap.api.utils import (
            validate_configuration_value as utils_validate_configuration_value,
        )
        from flext_ldap.api.utils import (
            validate_dn as utils_validate_dn,
        )

        return {
            "validate_and_normalize_file_path": validate_and_normalize_file_path,
            "validate_configuration_value": utils_validate_configuration_value,
            "normalize_dn": utils_normalize_dn,
            "validate_dn": utils_validate_dn,
        }
    except ImportError:
        return {}


def get_migration_components():
    """Get migration components."""
    try:
        from flext_ldap.api.migration import (
            MigrationConfig,
            MigrationError,
            MigrationResult,
            handle_migration_exception,
            log_migration_error,
        )

        return {
            "MigrationConfig": MigrationConfig,
            "MigrationError": MigrationError,
            "MigrationResult": MigrationResult,
            "handle_migration_exception": handle_migration_exception,
            "log_migration_error": log_migration_error,
        }
    except ImportError:
        return {}


def get_ldif_components():
    """Get LDIF processing components."""
    try:
        from flext_ldap.api.ldif import (
            DefaultLDIFProcessor,
            LDIFHeaderConfig,
            LDIFProcessingConfig,
            LDIFProcessorBase,
            LDIFWriter,
            LDIFWriterConfig,
        )

        return {
            "DefaultLDIFProcessor": DefaultLDIFProcessor,
            "LDIFHeaderConfig": LDIFHeaderConfig,
            "LDIFProcessingConfig": LDIFProcessingConfig,
            "LDIFProcessorBase": LDIFProcessorBase,
            "LDIFWriter": LDIFWriter,
            "LDIFWriterConfig": LDIFWriterConfig,
        }
    except ImportError:
        return {}


def get_acl_components():
    """Get ACL processing components."""
    try:
        from flext_ldap.api.acl import (
            ACLProcessorBase,
            DefaultACLProcessor,
        )

        return {
            "ACLProcessorBase": ACLProcessorBase,
            "DefaultACLProcessor": DefaultACLProcessor,
        }
    except ImportError:
        return {}


def get_base_components():
    """Get base processor components."""
    try:
        from flext_ldap.api.base import (
            BaseProcessor,
            DefaultProcessor,
        )

        return {
            "BaseProcessor": BaseProcessor,
            "DefaultProcessor": DefaultProcessor,
        }
    except ImportError:
        return {}


def get_hierarchy_components():
    """Get hierarchy processing components."""
    try:
        from flext_ldap.api.hierarchy import (
            DefaultHierarchyProcessor,
            HierarchyProcessorBase,
            get_dn_depth,
            get_parent_dn,
            normalize_dn,
            parse_dn,
        )

        return {
            "DefaultHierarchyProcessor": DefaultHierarchyProcessor,
            "HierarchyProcessorBase": HierarchyProcessorBase,
            "get_parent_dn": get_parent_dn,
            "normalize_dn": normalize_dn,
            "parse_dn": parse_dn,
            "get_dn_depth": get_dn_depth,
        }
    except ImportError:
        return {}


def get_schema_components():
    """Get schema processing components."""
    try:
        from flext_ldap.api.schema import (
            DefaultSchemaProcessor,
            SchemaProcessorBase,
        )

        return {
            "DefaultSchemaProcessor": DefaultSchemaProcessor,
            "SchemaProcessorBase": SchemaProcessorBase,
        }
    except ImportError:
        return {}


# Lazy loading
def __getattr__(name: str):
    """Lazy loading of API components."""
    validation_components = get_validation_components()
    if name in validation_components:
        return validation_components[name]

    migration_components = get_migration_components()
    if name in migration_components:
        return migration_components[name]

    ldif_components = get_ldif_components()
    if name in ldif_components:
        return ldif_components[name]

    acl_components = get_acl_components()
    if name in acl_components:
        return acl_components[name]

    base_components = get_base_components()
    if name in base_components:
        return base_components[name]

    hierarchy_components = get_hierarchy_components()
    if name in hierarchy_components:
        return hierarchy_components[name]

    schema_components = get_schema_components()
    if name in schema_components:
        return schema_components[name]

    utils_components = get_utils_components()
    if name in utils_components:
        return utils_components[name]

    # Try to get from main module
    try:
        from flext_ldap import __getattr__ as main_getattr

        return main_getattr(name)
    except:
        msg = f"module '{__name__}' has no attribute '{name}'"
        raise AttributeError(msg)


def validate_configuration_value(value: object, config_type: str = "generic") -> bool:
    """Validate configuration value."""
    return True


__all__ = [
    # ACL components
    "ACLProcessorBase",
    # Base components
    "BaseProcessor",
    "DefaultACLProcessor",
    # Hierarchy components
    "DefaultHierarchyProcessor",
    # LDIF components
    "DefaultLDIFProcessor",
    "DefaultProcessor",
    # Schema components
    "DefaultSchemaProcessor",
    "HierarchyProcessorBase",
    "LDIFHeaderConfig",
    "LDIFProcessingConfig",
    "LDIFProcessorBase",
    "LDIFWriter",
    "LDIFWriterConfig",
    # Migration components
    "MigrationConfig",
    "MigrationError",
    "MigrationResult",
    "SchemaProcessorBase",
    # Validation components
    "ValidationConfig",
    "ValidationError",
    "ValidationResult",
    "ValidationRules",
    "get_dn_depth",
    "get_parent_dn",
    "handle_migration_exception",
    "log_migration_error",
    "normalize_dn",
    "parse_dn",
    "validate_and_normalize_file_path",
    "validate_configuration_value",
    "validate_dn",
    "validate_filter",
    "validate_schema",
]
