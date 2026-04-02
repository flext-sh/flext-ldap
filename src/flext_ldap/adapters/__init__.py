# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""LDAP adapters package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldap.adapters import entry, ldap3
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter, FlextLdapLdap3Wrappers

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdapEntryAdapter": "flext_ldap.adapters.entry",
    "FlextLdapLdap3Adapter": "flext_ldap.adapters.ldap3",
    "FlextLdapLdap3Wrappers": "flext_ldap.adapters.ldap3",
    "entry": "flext_ldap.adapters.entry",
    "ldap3": "flext_ldap.adapters.ldap3",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
