# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""LDAP services package.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap.services import (
        connection as connection,
        detection as detection,
        operations as operations,
        sync as sync,
    )
    from flext_ldap.services.connection import (
        FlextLdapConnection as FlextLdapConnection,
    )
    from flext_ldap.services.detection import (
        FlextLdapServerDetector as FlextLdapServerDetector,
    )
    from flext_ldap.services.operations import (
        FlextLdapOperations as FlextLdapOperations,
    )
    from flext_ldap.services.sync import (
        FlextLdapSync as FlextLdapSync,
        FlextLdapSyncCallbacks as FlextLdapSyncCallbacks,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdapConnection": ["flext_ldap.services.connection", "FlextLdapConnection"],
    "FlextLdapOperations": ["flext_ldap.services.operations", "FlextLdapOperations"],
    "FlextLdapServerDetector": [
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ],
    "FlextLdapSync": ["flext_ldap.services.sync", "FlextLdapSync"],
    "FlextLdapSyncCallbacks": ["flext_ldap.services.sync", "FlextLdapSyncCallbacks"],
    "connection": ["flext_ldap.services.connection", ""],
    "detection": ["flext_ldap.services.detection", ""],
    "operations": ["flext_ldap.services.operations", ""],
    "sync": ["flext_ldap.services.sync", ""],
}

_EXPORTS: Sequence[str] = [
    "FlextLdapConnection",
    "FlextLdapOperations",
    "FlextLdapServerDetector",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "connection",
    "detection",
    "operations",
    "sync",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
