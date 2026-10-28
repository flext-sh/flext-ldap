# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Typings package.

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
    from flext_ldap._typings.ldap import FlextLdapTypesLdap


__all__: tuple[str, ...] = ("FlextLdapTypesLdap",)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"FlextLdapTypesLdap": ".ldap"}),
    public_exports=__all__,
)
