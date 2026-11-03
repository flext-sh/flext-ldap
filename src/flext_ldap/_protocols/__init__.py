# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._protocols.client_protocols import FlextLdapProtocolsClient
    from flext_ldap._protocols.config import FlextLdapProtocolsConfig
    from flext_ldap._protocols.ldap import FlextLdapProtocolsLdap
    from flext_ldap._protocols.search_protocols import FlextLdapProtocolsSearch
    from flext_ldap._protocols.service_protocols import FlextLdapProtocolsService
    from flext_ldap._protocols.settings_protocols import FlextLdapProtocolsSettings
    from flext_ldap._protocols.structural_protocols import FlextLdapProtocolsStructural


__all__: tuple[str, ...] = (
    "FlextLdapProtocolsClient",
    "FlextLdapProtocolsConfig",
    "FlextLdapProtocolsLdap",
    "FlextLdapProtocolsSearch",
    "FlextLdapProtocolsService",
    "FlextLdapProtocolsSettings",
    "FlextLdapProtocolsStructural",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdapProtocolsClient": ".client_protocols",
        "FlextLdapProtocolsConfig": ".config",
        "FlextLdapProtocolsLdap": ".ldap",
        "FlextLdapProtocolsSearch": ".search_protocols",
        "FlextLdapProtocolsService": ".service_protocols",
        "FlextLdapProtocolsSettings": ".settings_protocols",
        "FlextLdapProtocolsStructural": ".structural_protocols",
    },
    public_exports=__all__,
)
