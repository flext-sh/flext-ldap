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

    _models = _flext_ldap__models
    import flext_ldap.adapters as _flext_ldap_adapters
    from flext_ldap._models.ldap import FlextLdapModelsLdap

    adapters = _flext_ldap_adapters
    import flext_ldap.adapters.entry as _flext_ldap_adapters_entry

    entry = _flext_ldap_adapters_entry
    import flext_ldap.adapters.ldap3 as _flext_ldap_adapters_ldap3
    from flext_ldap.adapters.entry import FlextLdapEntryAdapter

    ldap3 = _flext_ldap_adapters_ldap3
    import flext_ldap.api as _flext_ldap_api
    from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter, FlextLdapLdap3Wrappers

    api = _flext_ldap_api
    import flext_ldap.base as _flext_ldap_base
    from flext_ldap.api import FlextLdap, ldap

    base = _flext_ldap_base
    import flext_ldap.constants as _flext_ldap_constants
    from flext_ldap.base import FlextLdapServiceBase, FlextLdapServiceBase as s

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
    import flext_ldap.services.connection as _flext_ldap_services_connection

    connection = _flext_ldap_services_connection
    import flext_ldap.services.detection as _flext_ldap_services_detection
    from flext_ldap.services.connection import FlextLdapConnection

    detection = _flext_ldap_services_detection
    import flext_ldap.services.operations as _flext_ldap_services_operations
    from flext_ldap.services.detection import FlextLdapServerDetector

    operations = _flext_ldap_services_operations
    import flext_ldap.services.sync as _flext_ldap_services_sync
    from flext_ldap.services.operations import FlextLdapOperations

    sync = _flext_ldap_services_sync
    import flext_ldap.settings as _flext_ldap_settings
    from flext_ldap.services.sync import FlextLdapSync, FlextLdapSyncCallbacks

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
        "FlextLdap": "flext_ldap.api",
        "FlextLdapConstants": "flext_ldap.constants",
        "FlextLdapModels": "flext_ldap.models",
        "FlextLdapProtocols": "flext_ldap.protocols",
        "FlextLdapServiceBase": "flext_ldap.base",
        "FlextLdapSettings": "flext_ldap.settings",
        "FlextLdapTypes": "flext_ldap.typings",
        "FlextLdapUtilities": "flext_ldap.utilities",
        "__author__": "flext_ldap.__version__",
        "__author_email__": "flext_ldap.__version__",
        "__description__": "flext_ldap.__version__",
        "__license__": "flext_ldap.__version__",
        "__title__": "flext_ldap.__version__",
        "__url__": "flext_ldap.__version__",
        "__version__": "flext_ldap.__version__",
        "__version_info__": "flext_ldap.__version__",
        "_models": "flext_ldap._models",
        "adapters": "flext_ldap.adapters",
        "api": "flext_ldap.api",
        "base": "flext_ldap.base",
        "c": ("flext_ldap.constants", "FlextLdapConstants"),
        "constants": "flext_ldap.constants",
        "d": ("flext_core.decorators", "FlextDecorators"),
        "e": ("flext_core.exceptions", "FlextExceptions"),
        "h": ("flext_core.handlers", "FlextHandlers"),
        "ldap": "flext_ldap.api",
        "m": ("flext_ldap.models", "FlextLdapModels"),
        "models": "flext_ldap.models",
        "p": ("flext_ldap.protocols", "FlextLdapProtocols"),
        "protocols": "flext_ldap.protocols",
        "r": ("flext_core.result", "FlextResult"),
        "s": ("flext_ldap.base", "FlextLdapServiceBase"),
        "services": "flext_ldap.services",
        "settings": "flext_ldap.settings",
        "t": ("flext_ldap.typings", "FlextLdapTypes"),
        "typings": "flext_ldap.typings",
        "u": ("flext_ldap.utilities", "FlextLdapUtilities"),
        "utilities": "flext_ldap.utilities",
        "x": ("flext_core.mixins", "FlextMixins"),
    },
)

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
