"""LDAP Core Shared - Connections Module.

This module provides enterprise-grade LDAP connection management extracted and
enhanced from the algar-oud-mig project. It implements connection pooling,
automatic reconnection, health monitoring, and SSH tunnel support.

Architecture:
    Connection management using Repository pattern with connection pooling
    for optimal resource utilization and enterprise-grade reliability.

Extracted Components:
    - LDAPConnectionInfo: From algar-oud-mig.ldap_operations
    - RealLDAPConnection: Enhanced from algar-oud-mig.ldap_operations
    - LDAPConnectionPool: From algar-oud-mig.connection_pool
    - SSH Tunnel Support: From algar-oud-mig.ssh

Integration Points:
    - Used by algar-oud-mig for migration operations
    - Provides shared connection management for all LDAP tools
    - Implements enterprise patterns for production use

Version: 1.0.0-extracted
"""

from ldap_core_shared.connections.base import (
    LDAPConnectionInfo,
    LDAPConnectionOptions,
    LDAPSearchConfig,
)
from ldap_core_shared.connections.manager import ConnectionStats, LDAPConnectionManager

__all__ = [
    "ConnectionStats",
    "LDAPConnectionInfo",
    "LDAPConnectionManager",
    "LDAPConnectionOptions",
    "LDAPSearchConfig",
]
