# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Adapters package."""

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
    import flext_ldap.adapters.entry as _flext_ldap_adapters_entry

    entry = _flext_ldap_adapters_entry
    import flext_ldap.adapters.ldap3 as _flext_ldap_adapters_ldap3

    ldap3 = _flext_ldap_adapters_ldap3

    _ = (
        FlextLdapEntryAdapter,
        FlextLdapLdap3Adapter,
        FlextLdapLdap3Wrappers,
        c,
        d,
        e,
        entry,
        h,
        ldap3,
        m,
        p,
        r,
        s,
        t,
        u,
        x,
    )
_LAZY_IMPORTS = {
    "FlextLdapEntryAdapter": "flext_ldap.adapters.entry",
    "FlextLdapLdap3Adapter": "flext_ldap.adapters.ldap3",
    "FlextLdapLdap3Wrappers": "flext_ldap.adapters.ldap3",
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "entry": "flext_ldap.adapters.entry",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "ldap3": "flext_ldap.adapters.ldap3",
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "FlextLdapEntryAdapter",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "c",
    "d",
    "e",
    "entry",
    "h",
    "ldap3",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
