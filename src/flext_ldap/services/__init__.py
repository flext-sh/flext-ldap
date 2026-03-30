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
    from flext_ldap.services import connection, detection, operations, sync
    from flext_ldap.services.connection import *
    from flext_ldap.services.detection import *
    from flext_ldap.services.operations import *
    from flext_ldap.services.sync import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
