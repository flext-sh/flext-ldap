"""LDAP Connection Management.

This package provides enterprise-grade LDAP connection management with
advanced features including connection pooling, failover, and monitoring.

UNIFIED INTEGRATION: Use create_unified_connection_manager() for easy setup
with api.LDAPConfig instead of the legacy ConnectionConfig approach.

PREFERRED PATTERN:
    from flext_ldap.core.config import ApplicationConfig as Config
    from flext_ldap import create_unified_connection_manager

    config = LDAPConfig(
        server="ldaps://ldap.company.com:636",
        auth_dn="cn=admin,dc=company,dc=com",
        auth_password="secret",
        base_dn="dc=company,dc=com"
    )

    manager = create_unified_connection_manager(config, pool_size=20)

    with manager.get_connection() as conn:
        result = conn.search("dc=company,dc=com", "(objectClass=*)")

LEGACY PATTERN (deprecated):
    from flext_ldap.connections.base import Connection

    config = ConnectionConfig(
        servers=["ldaps://ldap.company.com:636"],
        bind_dn="cn=admin,dc=company,dc=com",
        bind_password="secret"
    )

    manager = ConnectionManager(config)
"""

from flext_ldap.manager import (
    ConnectionConfig,
    ConnectionManager,
    ConnectionMetrics,
    ConnectionState,
    ConnectionStrategy,
    ServerHealth,
    ServerInfo,
    create_connection_config_from_unified,
    create_unified_connection_manager,
    migrate_legacy_connection_setup,
)

__all__ = [
    "ConnectionConfig",  # Legacy configuration class
    # LEGACY: Core connection management (still valid but less preferred)
    "ConnectionManager",  # Legacy connection manager
    "ConnectionMetrics",  # Performance metrics
    # Connection state and monitoring
    "ConnectionState",  # Connection state tracking
    "ConnectionStrategy",  # Connection strategies enum
    "ServerHealth",  # Server health status
    "ServerInfo",  # Server information
    "create_connection_config_from_unified",  # Config conversion helper
    # PREFERRED: Unified integration
    "create_unified_connection_manager",  # Main function for unified config
    "migrate_legacy_connection_setup",  # Migration helper
]
