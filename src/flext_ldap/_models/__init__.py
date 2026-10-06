# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._models._ldap_namespace import FlextLdapModelsLdapNamespace
    from flext_ldap._models.base import FlextLdapModelsBase
    from flext_ldap._models.config import FlextLdapConfigModels
    from flext_ldap._models.ldap import FlextLdapFlextModelsLdap


__all__: tuple[str, ...] = (
    "FlextLdapConfigModels",
    "FlextLdapFlextModelsLdap",
    "FlextLdapModelsBase",
    "FlextLdapModelsLdapNamespace",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdapConfigModels": ".config",
        "FlextLdapFlextModelsLdap": ".ldap",
        "FlextLdapModelsBase": ".base",
        "FlextLdapModelsLdapNamespace": "._ldap_namespace",
    }),
    public_exports=__all__,
)
