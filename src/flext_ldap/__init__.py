"""Enterprise LDAP integration library for FLEXT ecosystem.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib as _importlib

from flext_ldap.adapters import FlextLdapAdapters
from flext_ldap.api import FlextLdapApi
from flext_ldap.clients import SCOPE_MAP, FlextLdapClient, LdapScope
from flext_ldap.config import FlextLdapConfig
from flext_ldap.connection_config import FlextLdapConnectionConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.container import FlextLdapContainer
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.operations import FlextLdapOperations
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.services import FlextLdapServices

# FlextLdapConfig REMOVED: Use FlextLdapConfig directly (no wrappers/aliases)
from flext_ldap.type_guards import FlextLdapTypeGuards
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.value_objects import FlextLdapValueObjects

_vermod = _importlib.import_module("flext_ldap.__version__")
# NO GLOBAL FACTORY FUNCTIONS ALLOWED - Use FlextLdapApi.create() class method instead


def __getattr__(name: str) -> str:  # pragma: no cover
    if name == "__version__":
        return str(_vermod.__version__)
    if name == "__version_info__":
        return str(_vermod.__version_info__)
    raise AttributeError(name)


# Manual __all__ definition for explicit control
__all__ = [
    "SCOPE_MAP",
    "FlextLdapAdapters",
    "FlextLdapApi",
    "FlextLdapClient",
    "FlextLdapConfig",
    "FlextLdapConnectionConfig",
    "FlextLdapConstants",
    "FlextLdapContainer",
    "FlextLdapDomain",
    "FlextLdapExceptions",
    "FlextLdapModels",
    "FlextLdapOperations",
    "FlextLdapProtocols",
    "FlextLdapRepositories",
    "FlextLdapServices",
    "FlextLdapTypeGuards",
    "FlextLdapTypes",
    "FlextLdapValueObjects",
    "LdapScope",
]
