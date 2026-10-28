# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for upsert.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.services._upsert.handler import FlextLdapServicesUpsertHandler

__all__: tuple[str, ...] = ("FlextLdapServicesUpsertHandler",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdapServicesUpsertHandler": ".handler",
    }),
    public_exports=__all__,
)
