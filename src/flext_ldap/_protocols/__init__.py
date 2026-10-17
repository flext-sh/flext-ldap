# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._protocols.client_protocols import (
        FlextLdapProtocolsClient,
        LdapAdapter,
        LdapClient,
    )
    from flext_ldap._protocols.search_protocols import (
        ConnectionConfig,
        FlextLdapProtocolsSearch,
        LdapBatchStats,
        OperationResult,
        PhaseSyncResult,
        SearchOptions,
        SearchResult,
        SearchScope,
    )
    from flext_ldap._protocols.service_protocols import (
        FlextLdapProtocolsService,
        Ldap3Connection,
        LdapConnection,
        LdapOperations,
    )
    from flext_ldap._protocols.settings_protocols import (
        FlextLdapProtocolsSettings,
        LdapSettings,
        Settings,
    )
    from flext_ldap._protocols.structural_protocols import (
        FlextLdapProtocolsStructural,
        HasAttributesProperty,
        HasConfigAttribute,
        HasDynamicAttribute,
        HasItemsMethod,
    )


__all__: tuple[str, ...] = (
    "ConnectionConfig",
    "FlextLdapProtocolsClient",
    "FlextLdapProtocolsSearch",
    "FlextLdapProtocolsService",
    "FlextLdapProtocolsSettings",
    "FlextLdapProtocolsStructural",
    "HasAttributesProperty",
    "HasConfigAttribute",
    "HasDynamicAttribute",
    "HasItemsMethod",
    "Ldap3Connection",
    "LdapAdapter",
    "LdapBatchStats",
    "LdapClient",
    "LdapConnection",
    "LdapOperations",
    "LdapSettings",
    "OperationResult",
    "PhaseSyncResult",
    "SearchOptions",
    "SearchResult",
    "SearchScope",
    "Settings",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "ConnectionConfig": ".search_protocols",
        "FlextLdapProtocolsClient": ".client_protocols",
        "FlextLdapProtocolsSearch": ".search_protocols",
        "FlextLdapProtocolsService": ".service_protocols",
        "FlextLdapProtocolsSettings": ".settings_protocols",
        "FlextLdapProtocolsStructural": ".structural_protocols",
        "HasAttributesProperty": ".structural_protocols",
        "HasConfigAttribute": ".structural_protocols",
        "HasDynamicAttribute": ".structural_protocols",
        "HasItemsMethod": ".structural_protocols",
        "Ldap3Connection": ".service_protocols",
        "LdapAdapter": ".client_protocols",
        "LdapBatchStats": ".search_protocols",
        "LdapClient": ".client_protocols",
        "LdapConnection": ".service_protocols",
        "LdapOperations": ".service_protocols",
        "LdapSettings": ".settings_protocols",
        "OperationResult": ".search_protocols",
        "PhaseSyncResult": ".search_protocols",
        "SearchOptions": ".search_protocols",
        "SearchResult": ".search_protocols",
        "SearchScope": ".search_protocols",
        "Settings": ".settings_protocols",
    }),
    public_exports=__all__,
)
