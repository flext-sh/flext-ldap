"""Core LDAP functionality package.

This package provides the core LDAP functionality including connection management,
operations, search engine, and security features.
"""

# Main connection manager - the primary interface
from ldap_core_shared.core.connection_manager import LDAPConnectionManager

__all__ = [
    "LDAPConnectionManager",
]
