"""FLEXT-LDAP Infrastructure - Compatibility re-export layer.

This module maintains backward compatibility by re-exporting
infrastructure classes from their specialized modules.

ARCHITECTURE: Facade pattern providing single import point
while actual implementations follow SOLID principles in
focused modules (clients, repositories, container).
"""

from __future__ import annotations

# FLEXT-CORE INTEGRATION: Use flext-core protocols instead of local interfaces
from flext_core import FlextProtocols

# Re-export client implementations
from flext_ldap.clients import FlextLdapClient

# Re-export container and DI infrastructure
from flext_ldap.container import (
    configure_ldap_container,
    get_ldap_container,
    reset_ldap_container,
)

# Re-export repository implementations
from flext_ldap.repositories import (
    FlextLdapGroupRepository,
    FlextLdapRepository,
    FlextLdapUserRepository,
)

# Client exports - after FLEXT compliance migration
__all__ = [
    "FlextLdapClient",
    # FlextLdapContainer eliminated - use get_ldap_container() instead
    "FlextLdapGroupRepository",
    "FlextLdapRepository",
    "FlextLdapUserRepository",
    "FlextProtocols",  # Export flext-core protocols instead of local interfaces
    "configure_ldap_container",
    "get_ldap_container",
    "reset_ldap_container",
]
