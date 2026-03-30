# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""LDAP adapters package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.adapters import entry as entry, ldap3 as ldap3
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter as FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import (
        FlextLdapLdap3Adapter as FlextLdapLdap3Adapter,
        FlextLdapLdap3Wrappers as FlextLdapLdap3Wrappers,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdapEntryAdapter": ["flext_ldap.adapters.entry", "FlextLdapEntryAdapter"],
    "FlextLdapLdap3Adapter": ["flext_ldap.adapters.ldap3", "FlextLdapLdap3Adapter"],
    "FlextLdapLdap3Wrappers": ["flext_ldap.adapters.ldap3", "FlextLdapLdap3Wrappers"],
    "entry": ["flext_ldap.adapters.entry", ""],
    "ldap3": ["flext_ldap.adapters.ldap3", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "entry",
    "ldap3",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
