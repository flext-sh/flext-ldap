# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Services package."""

from __future__ import annotations

import typing as _t

from flext_core.constants import FlextConstants as c
from flext_core.decorators import FlextDecorators as d
from flext_core.exceptions import FlextExceptions as e
from flext_core.handlers import FlextHandlers as h
from flext_core.lazy import install_lazy_exports
from flext_core.mixins import FlextMixins as x
from flext_core.models import FlextModels as m
from flext_core.protocols import FlextProtocols as p
from flext_core.result import FlextResult as r
from flext_core.service import FlextService as s
from flext_core.typings import FlextTypes as t
from flext_core.utilities import FlextUtilities as u

if _t.TYPE_CHECKING:
    import flext_ldap.services.connection as _flext_ldap_services_connection

    connection = _flext_ldap_services_connection
    import flext_ldap.services.detection as _flext_ldap_services_detection

    detection = _flext_ldap_services_detection
    import flext_ldap.services.operations as _flext_ldap_services_operations

    operations = _flext_ldap_services_operations
    import flext_ldap.services.sync as _flext_ldap_services_sync

    sync = _flext_ldap_services_sync

    _ = (
        FlextLdapConnection,
        FlextLdapOperations,
        FlextLdapServerDetector,
        FlextLdapSync,
        FlextLdapSyncCallbacks,
        c,
        connection,
        d,
        detection,
        e,
        h,
        m,
        operations,
        p,
        r,
        s,
        sync,
        t,
        u,
        x,
    )
_LAZY_IMPORTS = {
    "FlextLdapConnection": "flext_ldap.services.connection",
    "FlextLdapOperations": "flext_ldap.services.operations",
    "FlextLdapServerDetector": "flext_ldap.services.detection",
    "FlextLdapSync": "flext_ldap.services.sync",
    "FlextLdapSyncCallbacks": "flext_ldap.services.sync",
    "c": ("flext_core.constants", "FlextConstants"),
    "connection": "flext_ldap.services.connection",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "detection": "flext_ldap.services.detection",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "operations": "flext_ldap.services.operations",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "sync": "flext_ldap.services.sync",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "FlextLdapConnection",
    "FlextLdapOperations",
    "FlextLdapServerDetector",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "c",
    "connection",
    "d",
    "detection",
    "e",
    "h",
    "m",
    "operations",
    "p",
    "r",
    "s",
    "sync",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
