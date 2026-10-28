# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._models.base import FlextLdapModelsBase
    from flext_ldap._models.config import FlextLdapModelsConfig
    from flext_ldap._models.ldap import FlextLdapModelsFlextLdap


__all__: tuple[str, ...] = (
    "FlextLdapModelsBase",
    "FlextLdapModelsConfig",
    "FlextLdapModelsFlextLdap",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdapModelsBase": ".base",
        "FlextLdapModelsConfig": ".config",
        "FlextLdapModelsFlextLdap": ".ldap",
    }),
    public_exports=__all__,
)
