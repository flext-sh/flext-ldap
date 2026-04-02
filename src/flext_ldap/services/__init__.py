# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""LDAP services package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldap.services import connection, detection, operations, sync
    from flext_ldap.services.connection import FlextLdapConnection
    from flext_ldap.services.detection import FlextLdapServerDetector
    from flext_ldap.services.operations import FlextLdapOperations
    from flext_ldap.services.sync import FlextLdapSync, FlextLdapSyncCallbacks

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdapConnection": "flext_ldap.services.connection",
    "FlextLdapOperations": "flext_ldap.services.operations",
    "FlextLdapServerDetector": "flext_ldap.services.detection",
    "FlextLdapSync": "flext_ldap.services.sync",
    "FlextLdapSyncCallbacks": "flext_ldap.services.sync",
    "connection": "flext_ldap.services.connection",
    "detection": "flext_ldap.services.detection",
    "operations": "flext_ldap.services.operations",
    "sync": "flext_ldap.services.sync",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
