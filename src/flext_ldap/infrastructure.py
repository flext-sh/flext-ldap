"""FLEXT-LDAP Infrastructure - Compatibility re-export layer.

This module maintains backward compatibility by re-exporting
infrastructure classes from their specialized modules.

ARCHITECTURE: Facade pattern providing single import point
while actual implementations follow SOLID principles in
focused modules (clients, repositories, container).
"""

from __future__ import annotations

# Re-export client implementations
from flext_ldap.clients import FlextLdapClient

# Re-export container and DI infrastructure
from flext_ldap.container import (
    FlextLdapContainer,
    configure_ldap_container,
    get_ldap_container,
    reset_ldap_container,
)

# Re-export interfaces for type checking
from flext_ldap.interfaces import (
    IFlextLdapClient,
    IFlextLdapConfiguration,
    IFlextLdapRepository,
)

# Re-export repository implementations
from flext_ldap.repositories import (
    FlextLdapGroupRepository,
    FlextLdapRepository,
    FlextLdapUserRepository,
)

# Client exports
__all__ = [
    "FlextLdapClient",
    "FlextLdapContainer",
    "FlextLdapGroupRepository",
    "FlextLdapRepository",
    "FlextLdapUserRepository",
    "IFlextLdapClient",
    "IFlextLdapConfiguration",
    "IFlextLdapRepository",
    "configure_ldap_container",
    "get_ldap_container",
    "reset_ldap_container",
]
