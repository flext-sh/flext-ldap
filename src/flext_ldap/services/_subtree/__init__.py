# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap.services. Subtree package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.services._subtree.delete import FlextLdapServicesSubtreeDelete


__all__: tuple[str, ...] = ("FlextLdapServicesSubtreeDelete",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"FlextLdapServicesSubtreeDelete": ".delete"}),
    public_exports=__all__,
)
