# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldap package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports, merge_lazy_imports

from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)
from flext_ldap.typings import FlextLdapDomainResultT, FlextLdapEntryT

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_ldif import d, e, h, r, x

    from flext_ldap import (
        _models,
        adapters,
        api,
        base,
        constants,
        models,
        protocols,
        services,
        settings,
        typings,
        utilities,
    )
    from flext_ldap._models import FlextLdapModelsLdap
    from flext_ldap.adapters import (
        FlextLdapEntryAdapter,
        FlextLdapLdap3Adapter,
        FlextLdapLdap3Wrappers,
        entry,
        ldap3,
    )
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
        connection,
        detection,
        operations,
        sync,
    )
    from flext_ldap.settings import FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes, FlextLdapTypes as t
    from flext_ldap.utilities import FlextLdapUtilities, FlextLdapUtilities as u

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = merge_lazy_imports(
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
        "constants": "flext_ldap.constants",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "ldap": "flext_ldap.api",
        "m": ("flext_ldap.models", "FlextLdapModels"),
        "models": "flext_ldap.models",
        "p": ("flext_ldap.protocols", "FlextLdapProtocols"),
        "protocols": "flext_ldap.protocols",
        "r": "flext_ldif",
        "s": "flext_ldap.base",
        "services": "flext_ldap.services",
        "settings": "flext_ldap.settings",
        "t": ("flext_ldap.typings", "FlextLdapTypes"),
        "typings": "flext_ldap.typings",
        "u": ("flext_ldap.utilities", "FlextLdapUtilities"),
        "utilities": "flext_ldap.utilities",
        "x": "flext_ldif",
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    [
        "FlextLdapDomainResultT",
        "FlextLdapEntryT",
        "__author__",
        "__author_email__",
        "__description__",
        "__license__",
        "__title__",
        "__url__",
        "__version__",
        "__version_info__",
    ],
)
