# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldap package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_ldap.__version__ import (
    __all__,
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_ldap import (
        _models,
        adapters,
        api,
        base,
        connection,
        constants,
        detection,
        entry,
        ldap3,
        models,
        operations,
        protocols,
        services,
        settings,
        sync,
        typings,
        utilities,
    )
    from flext_ldap._models import FlextLdapModelsLdap
    from flext_ldap.adapters import FlextLdapEntryAdapter, FlextLdapLdap3Wrappers
    from flext_ldap.api import FlextLdap, ldap
    from flext_ldap.base import FlextLdapServiceBase, s
    from flext_ldap.constants import FlextLdapConstants, FlextLdapConstants as c
    from flext_ldap.models import FlextLdapModels, FlextLdapModels as m
    from flext_ldap.protocols import FlextLdapProtocols, FlextLdapProtocols as p
    from flext_ldap.services import (
        FlextLdapConnection,
        FlextLdapOperations,
        FlextLdapServerDetector,
        FlextLdapSync,
        FlextLdapSyncCallbacks,
    )
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes, FlextLdapTypes as t
    from flext_ldap.utilities import FlextLdapUtilities, FlextLdapUtilities as u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = merge_lazy_imports(
    (
        "flext_ldap._models",
        "flext_ldap.adapters",
        "flext_ldap.services",
    ),
    {
        "FlextLdap": "flext_ldap.api",
        "FlextLdapConstants": "flext_ldap.constants",
        "FlextLdapModels": "flext_ldap.models",
        "FlextLdapProtocols": "flext_ldap.protocols",
        "FlextLdapServiceBase": "flext_ldap.base",
        "FlextLdapSettings": "flext_ldap.settings",
        "FlextLdapTypes": "flext_ldap.typings",
        "FlextLdapUtilities": "flext_ldap.utilities",
        "_models": "flext_ldap._models",
        "adapters": "flext_ldap.adapters",
        "api": "flext_ldap.api",
        "base": "flext_ldap.base",
        "c": ("flext_ldap.constants", "FlextLdapConstants"),
        "connection": "flext_ldap.connection",
        "constants": "flext_ldap.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "detection": "flext_ldap.detection",
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "entry": "flext_ldap.entry",
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldap": "flext_ldap.api",
        "ldap3": "flext_ldap.ldap3",
        "m": ("flext_ldap.models", "FlextLdapModels"),
        "models": "flext_ldap.models",
        "operations": "flext_ldap.operations",
        "p": ("flext_ldap.protocols", "FlextLdapProtocols"),
        "protocols": "flext_ldap.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": "flext_ldap.base",
        "services": "flext_ldap.services",
        "settings": "flext_ldap.settings",
        "sync": "flext_ldap.sync",
        "t": ("flext_ldap.typings", "FlextLdapTypes"),
        "typings": "flext_ldap.typings",
        "u": ("flext_ldap.utilities", "FlextLdapUtilities"),
        "utilities": "flext_ldap.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    [
        "__all__",
        "__author__",
        "__author_email__",
        "__description__",
        "__license__",
        "__title__",
        "__url__",
        "__version__",
    ],
)
