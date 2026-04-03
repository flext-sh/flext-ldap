# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
    from flext_ldap import connection, detection, operations, sync
    from flext_ldap.connection import FlextLdapConnection
    from flext_ldap.detection import FlextLdapServerDetector
    from flext_ldap.operations import FlextLdapOperations
    from flext_ldap.sync import FlextLdapSync, FlextLdapSyncCallbacks

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextLdapConnection": "flext_ldap.connection",
    "FlextLdapOperations": "flext_ldap.operations",
    "FlextLdapServerDetector": "flext_ldap.detection",
    "FlextLdapSync": "flext_ldap.sync",
    "FlextLdapSyncCallbacks": "flext_ldap.sync",
    "c": ("flext_core.constants", "FlextConstants"),
    "connection": "flext_ldap.connection",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "detection": "flext_ldap.detection",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "operations": "flext_ldap.operations",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "sync": "flext_ldap.sync",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
