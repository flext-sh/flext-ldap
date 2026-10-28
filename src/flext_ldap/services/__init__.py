# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.services package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.services._subtree import FlextLdapServicesSubtreeDelete
    from flext_ldap.services._upsert import FlextLdapServicesUpsertHandler
    from flext_ldap.services.api_runtime import FlextLdapApiRuntime
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSync


__all__: tuple[str, ...] = (
    "FlextLdapApiRuntime",
    "FlextLdapConnection",
    "FlextLdapOperations",
    "FlextLdapServerDetector",
    "FlextLdapServicesSubtreeDelete",
    "FlextLdapServicesUpsertHandler",
    "FlextLdapSync",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdapApiRuntime": ".api_runtime",
        "FlextLdapConnection": ".connection",
        "FlextLdapOperations": ".operations",
        "FlextLdapServerDetector": ".detection",
        "FlextLdapServicesSubtreeDelete": "._subtree_delete",
        "FlextLdapSync": ".sync",
        "FlextLdapServicesUpsertHandler": "._upsert_handler",
    }),
    public_exports=__all__,
)
