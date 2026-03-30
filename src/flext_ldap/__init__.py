# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldap package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

from flext_ldap.__version__ import (
    __author__ as __author__,
    __author_email__ as __author_email__,
    __description__ as __description__,
    __license__ as __license__,
    __title__ as __title__,
    __url__ as __url__,
    __version__ as __version__,
    __version_info__ as __version_info__,
)
from flext_ldap.typings import (
    FlextLdapDomainResultT as FlextLdapDomainResultT,
    FlextLdapEntryT as FlextLdapEntryT,
)

if TYPE_CHECKING:
    from flext_ldap import (
        _models as _models,
        adapters as adapters,
        api as api,
        base as base,
        constants as constants,
        models as models,
        protocols as protocols,
        services as services,
        settings as settings,
        typings as typings,
        utilities as utilities,
    )
    from flext_ldap._models.ldap import FlextLdapModelsLdap as FlextLdapModelsLdap
    from flext_ldap.adapters import entry as entry, ldap3 as ldap3
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter as FlextLdapEntryAdapter
    from flext_ldap.adapters.ldap3 import (
        FlextLdapLdap3Adapter as FlextLdapLdap3Adapter,
        FlextLdapLdap3Wrappers as FlextLdapLdap3Wrappers,
    )
    from flext_ldap.api import FlextLdap as FlextLdap, ldap as ldap
    from flext_ldap.base import FlextLdapServiceBase as FlextLdapServiceBase, s as s
    from flext_ldap.constants import (
        FlextLdapConstants as FlextLdapConstants,
        FlextLdapConstants as c,
    )
    from flext_ldap.models import (
        FlextLdapModels as FlextLdapModels,
        FlextLdapModels as m,
    )
    from flext_ldap.protocols import (
        FlextLdapProtocols as FlextLdapProtocols,
        FlextLdapProtocols as p,
    )
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
    from flext_ldap.settings import FlextLdapSettings as FlextLdapSettings
    from flext_ldap.typings import FlextLdapTypes as FlextLdapTypes, FlextLdapTypes as t
    from flext_ldap.utilities import (
        FlextLdapUtilities as FlextLdapUtilities,
        FlextLdapUtilities as u,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextLdap": ["flext_ldap.api", "FlextLdap"],
    "FlextLdapConnection": ["flext_ldap.services.connection", "FlextLdapConnection"],
    "FlextLdapConstants": ["flext_ldap.constants", "FlextLdapConstants"],
    "FlextLdapEntryAdapter": ["flext_ldap.adapters.entry", "FlextLdapEntryAdapter"],
    "FlextLdapLdap3Adapter": ["flext_ldap.adapters.ldap3", "FlextLdapLdap3Adapter"],
    "FlextLdapLdap3Wrappers": ["flext_ldap.adapters.ldap3", "FlextLdapLdap3Wrappers"],
    "FlextLdapModels": ["flext_ldap.models", "FlextLdapModels"],
    "FlextLdapModelsLdap": ["flext_ldap._models.ldap", "FlextLdapModelsLdap"],
    "FlextLdapOperations": ["flext_ldap.services.operations", "FlextLdapOperations"],
    "FlextLdapProtocols": ["flext_ldap.protocols", "FlextLdapProtocols"],
    "FlextLdapServerDetector": [
        "flext_ldap.services.detection",
        "FlextLdapServerDetector",
    ],
    "FlextLdapServiceBase": ["flext_ldap.base", "FlextLdapServiceBase"],
    "FlextLdapSettings": ["flext_ldap.settings", "FlextLdapSettings"],
    "FlextLdapSync": ["flext_ldap.services.sync", "FlextLdapSync"],
    "FlextLdapSyncCallbacks": ["flext_ldap.services.sync", "FlextLdapSyncCallbacks"],
    "FlextLdapTypes": ["flext_ldap.typings", "FlextLdapTypes"],
    "FlextLdapUtilities": ["flext_ldap.utilities", "FlextLdapUtilities"],
    "_models": ["flext_ldap._models", ""],
    "adapters": ["flext_ldap.adapters", ""],
    "api": ["flext_ldap.api", ""],
    "base": ["flext_ldap.base", ""],
    "c": ["flext_ldap.constants", "FlextLdapConstants"],
    "connection": ["flext_ldap.services.connection", ""],
    "constants": ["flext_ldap.constants", ""],
    "d": ["flext_ldif", "d"],
    "detection": ["flext_ldap.services.detection", ""],
    "e": ["flext_ldif", "e"],
    "entry": ["flext_ldap.adapters.entry", ""],
    "h": ["flext_ldif", "h"],
    "ldap": ["flext_ldap.api", "ldap"],
    "ldap3": ["flext_ldap.adapters.ldap3", ""],
    "m": ["flext_ldap.models", "FlextLdapModels"],
    "models": ["flext_ldap.models", ""],
    "operations": ["flext_ldap.services.operations", ""],
    "p": ["flext_ldap.protocols", "FlextLdapProtocols"],
    "protocols": ["flext_ldap.protocols", ""],
    "r": ["flext_ldif", "r"],
    "s": ["flext_ldap.base", "s"],
    "services": ["flext_ldap.services", ""],
    "settings": ["flext_ldap.settings", ""],
    "sync": ["flext_ldap.services.sync", ""],
    "t": ["flext_ldap.typings", "FlextLdapTypes"],
    "typings": ["flext_ldap.typings", ""],
    "u": ["flext_ldap.utilities", "FlextLdapUtilities"],
    "utilities": ["flext_ldap.utilities", ""],
    "x": ["flext_ldif", "x"],
}

_EXPORTS: Sequence[str] = [
    "FlextLdap",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapDomainResultT",
    "FlextLdapEntryAdapter",
    "FlextLdapEntryT",
    "FlextLdapLdap3Adapter",
    "FlextLdapLdap3Wrappers",
    "FlextLdapModels",
    "FlextLdapModelsLdap",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapServerDetector",
    "FlextLdapServiceBase",
    "FlextLdapSettings",
    "FlextLdapSync",
    "FlextLdapSyncCallbacks",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "_models",
    "adapters",
    "api",
    "base",
    "c",
    "connection",
    "constants",
    "d",
    "detection",
    "e",
    "entry",
    "h",
    "ldap",
    "ldap3",
    "m",
    "models",
    "operations",
    "p",
    "protocols",
    "r",
    "s",
    "services",
    "settings",
    "sync",
    "t",
    "typings",
    "u",
    "utilities",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)
