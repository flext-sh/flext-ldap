# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldap package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports, merge_lazy_imports
from flext_ldap.__version__ import *

if _t.TYPE_CHECKING:
    import flext_ldap._models as _flext_ldap__models

    _models = _flext_ldap__models
    import flext_ldap.adapters as _flext_ldap_adapters
    from flext_ldap._models import FlextLdapModelsLdap

    adapters = _flext_ldap_adapters
    import flext_ldap.api as _flext_ldap_api
    from flext_ldap.adapters import (
        FlextLdapEntryAdapter,
        FlextLdapLdap3Adapter,
        FlextLdapLdap3Wrappers,
        entry,
        ldap3,
    )

    api = _flext_ldap_api
    import flext_ldap.base as _flext_ldap_base
    from flext_ldap.api import FlextLdap, ldap

    base = _flext_ldap_base
    import flext_ldap.constants as _flext_ldap_constants
    from flext_ldap.base import FlextLdapServiceBase, s

    constants = _flext_ldap_constants
    import flext_ldap.models as _flext_ldap_models
    from flext_ldap.constants import FlextLdapConstants, FlextLdapConstants as c

    models = _flext_ldap_models
    import flext_ldap.protocols as _flext_ldap_protocols
    from flext_ldap.models import FlextLdapModels, FlextLdapModels as m

    protocols = _flext_ldap_protocols
    import flext_ldap.services as _flext_ldap_services
    from flext_ldap.protocols import FlextLdapProtocols, FlextLdapProtocols as p

    services = _flext_ldap_services
    import flext_ldap.settings as _flext_ldap_settings
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

    settings = _flext_ldap_settings
    import flext_ldap.typings as _flext_ldap_typings
    from flext_ldap.settings import FlextLdapSettings

    typings = _flext_ldap_typings
    import flext_ldap.utilities as _flext_ldap_utilities
    from flext_ldap.typings import FlextLdapTypes, FlextLdapTypes as t

    utilities = _flext_ldap_utilities
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_ldap.utilities import FlextLdapUtilities, FlextLdapUtilities as u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        "flext_ldap._models",
        "flext_ldap.adapters",
        "flext_ldap.services",
    ),
    {
        "FlextLdap": ("flext_ldap.api", "FlextLdap"),
        "FlextLdapConstants": ("flext_ldap.constants", "FlextLdapConstants"),
        "FlextLdapModels": ("flext_ldap.models", "FlextLdapModels"),
        "FlextLdapProtocols": ("flext_ldap.protocols", "FlextLdapProtocols"),
        "FlextLdapServiceBase": ("flext_ldap.base", "FlextLdapServiceBase"),
        "FlextLdapSettings": ("flext_ldap.settings", "FlextLdapSettings"),
        "FlextLdapTypes": ("flext_ldap.typings", "FlextLdapTypes"),
        "FlextLdapUtilities": ("flext_ldap.utilities", "FlextLdapUtilities"),
        "__author__": ("flext_ldap.__version__", "__author__"),
        "__author_email__": ("flext_ldap.__version__", "__author_email__"),
        "__description__": ("flext_ldap.__version__", "__description__"),
        "__license__": ("flext_ldap.__version__", "__license__"),
        "__title__": ("flext_ldap.__version__", "__title__"),
        "__url__": ("flext_ldap.__version__", "__url__"),
        "__version__": ("flext_ldap.__version__", "__version__"),
        "__version_info__": ("flext_ldap.__version__", "__version_info__"),
        "_models": "flext_ldap._models",
        "adapters": "flext_ldap.adapters",
        "api": "flext_ldap.api",
        "base": "flext_ldap.base",
        "c": ("flext_ldap.constants", "FlextLdapConstants"),
        "constants": "flext_ldap.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldap": ("flext_ldap.api", "ldap"),
        "m": ("flext_ldap.models", "FlextLdapModels"),
        "models": "flext_ldap.models",
        "p": ("flext_ldap.protocols", "FlextLdapProtocols"),
        "protocols": "flext_ldap.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_ldap.base", "s"),
        "services": "flext_ldap.services",
        "settings": "flext_ldap.settings",
        "t": ("flext_ldap.typings", "FlextLdapTypes"),
        "typings": "flext_ldap.typings",
        "u": ("flext_ldap.utilities", "FlextLdapUtilities"),
        "utilities": "flext_ldap.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)
_ = _LAZY_IMPORTS.pop("cleanup_submodule_namespace", None)
_ = _LAZY_IMPORTS.pop("install_lazy_exports", None)
_ = _LAZY_IMPORTS.pop("lazy_getattr", None)
_ = _LAZY_IMPORTS.pop("merge_lazy_imports", None)
_ = _LAZY_IMPORTS.pop("output", None)
_ = _LAZY_IMPORTS.pop("output_reporting", None)

__all__ = [
    "FlextLdap",
    "FlextLdapConnection",
    "FlextLdapConstants",
    "FlextLdapEntryAdapter",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
