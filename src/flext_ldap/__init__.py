# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext ldap package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

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

if TYPE_CHECKING:
    from flext_ldif import *

    from flext_ldap import (
        api,
        base,
        constants,
        models,
        protocols,
        settings,
        typings,
        utilities,
    )
    from flext_ldap._models import *
    from flext_ldap.adapters import *
    from flext_ldap.api import *
    from flext_ldap.base import *
    from flext_ldap.constants import *
    from flext_ldap.models import *
    from flext_ldap.protocols import *
    from flext_ldap.services import *
    from flext_ldap.settings import *
    from flext_ldap.typings import *
    from flext_ldap.utilities import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextLdap": "flext_ldap.api",
    "FlextLdapConnection": "flext_ldap.services.connection",
    "FlextLdapConstants": "flext_ldap.constants",
    "FlextLdapEntryAdapter": "flext_ldap.adapters.entry",
    "FlextLdapLdap3Adapter": "flext_ldap.adapters.ldap3",
    "FlextLdapLdap3Wrappers": "flext_ldap.adapters.ldap3",
    "FlextLdapModels": "flext_ldap.models",
    "FlextLdapModelsLdap": "flext_ldap._models.ldap",
    "FlextLdapOperations": "flext_ldap.services.operations",
    "FlextLdapProtocols": "flext_ldap.protocols",
    "FlextLdapServerDetector": "flext_ldap.services.detection",
    "FlextLdapServiceBase": "flext_ldap.base",
    "FlextLdapSettings": "flext_ldap.settings",
    "FlextLdapSync": "flext_ldap.services.sync",
    "FlextLdapSyncCallbacks": "flext_ldap.services.sync",
    "FlextLdapTypes": "flext_ldap.typings",
    "FlextLdapUtilities": "flext_ldap.utilities",
    "_models": "flext_ldap._models",
    "adapters": "flext_ldap.adapters",
    "api": "flext_ldap.api",
    "base": "flext_ldap.base",
    "c": ["flext_ldap.constants", "FlextLdapConstants"],
    "connection": "flext_ldap.services.connection",
    "constants": "flext_ldap.constants",
    "d": "flext_ldif",
    "detection": "flext_ldap.services.detection",
    "e": "flext_ldif",
    "entry": "flext_ldap.adapters.entry",
    "h": "flext_ldif",
    "ldap": "flext_ldap.api",
    "ldap3": "flext_ldap.adapters.ldap3",
    "m": ["flext_ldap.models", "FlextLdapModels"],
    "models": "flext_ldap.models",
    "operations": "flext_ldap.services.operations",
    "p": ["flext_ldap.protocols", "FlextLdapProtocols"],
    "protocols": "flext_ldap.protocols",
    "r": "flext_ldif",
    "s": "flext_ldap.base",
    "services": "flext_ldap.services",
    "settings": "flext_ldap.settings",
    "sync": "flext_ldap.services.sync",
    "t": ["flext_ldap.typings", "FlextLdapTypes"],
    "typings": "flext_ldap.typings",
    "u": ["flext_ldap.utilities", "FlextLdapUtilities"],
    "utilities": "flext_ldap.utilities",
    "x": "flext_ldif",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))
