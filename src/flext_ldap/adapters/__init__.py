# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.adapters package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.host import FlextLdapAdapterHost
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter


__all__: tuple[str, ...] = (
    "FlextLdapAdapterHost",
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdapAdapterHost": ".host",
        "FlextLdapEntryAdapter": ".entry",
        "FlextLdapLdap3Adapter": ".ldap3",
    }),
    public_exports=__all__,
)
