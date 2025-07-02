"""Configuration management for LDAP Core Shared.

UNIFIED CONFIGURATION SYSTEM - Use api.LDAPConfig for new code.
This module provides legacy configurations with migration utilities.

PREFERRED PATTERN:
    from flext_ldap.core.config import ApplicationConfig as Config

    config = LDAPConfig(
        server="ldaps://ldap.company.com:636",
        auth_dn="cn=admin,dc=company,dc=com",
        auth_password="secret",
        base_dn="dc=company,dc=com"
    )

LEGACY PATTERNS (deprecated):
    from flext_ldap.core.config import ApplicationConfig as Config

    config = load_ldap_config()  # Use load_ldap_config_unified() for migration
"""

from __future__ import annotations

# Import unified configuration (PREFERRED)
try:
    from flext_ldap.core.config import ApplicationConfig as Config
except ImportError:
    # Handle import order issues
    LDAPConfig = None  # type: ignore[misc]

# Import legacy configurations (DEPRECATED)
from flext_ldap_config import (
    BaseConfig,
    ConfigurationManager,
    LDAPServerConfig,  # DEPRECATED: Use api.LDAPConfig instead
    LoggingConfig,
    ProcessingConfig,
    SecurityConfig,
    auto_detect_and_migrate_config,
    config_manager,
    create_unified_config_from_legacy_manager,
    # Legacy loaders (DEPRECATED)
    load_ldap_config,
    load_ldap_config_unified,
    load_logging_config,
    load_processing_config,
    load_security_config,
    # Migration utilities
    migrate_ldap_server_config_to_unified,
)

__all__ = [
    # LEGACY: Base configurations (deprecated for LDAP, but still valid for other uses)
    "BaseConfig",
    # Configuration management
    "ConfigurationManager",
    # PREFERRED: Unified configuration
    "LDAPConfig",  # Main unified LDAP config
    "LDAPServerConfig",  # DEPRECATED: Use LDAPConfig instead
    "LoggingConfig",  # Still valid for logging configuration
    "ProcessingConfig",  # Still valid for processing configuration
    "SecurityConfig",  # Still valid for security configuration
    "auto_detect_and_migrate_config",
    "config_manager",
    "create_unified_config_from_legacy_manager",
    # LEGACY: Loaders (deprecated for LDAP)
    "load_ldap_config",  # DEPRECATED: Use LDAPConfig constructor
    "load_ldap_config_unified",
    "load_logging_config",  # Still valid
    "load_processing_config",  # Still valid
    "load_security_config",  # Still valid
    # Migration utilities
    "migrate_ldap_server_config_to_unified",
]
