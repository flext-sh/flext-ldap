"""Enterprise LDAP integration library for FLEXT ecosystem.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib as _importlib

from flext_ldap.adapters import FlextLDAPAdapters
from flext_ldap.api import FlextLDAPApi, get_flext_ldap_api
from flext_ldap.clients import SCOPE_MAP, FlextLDAPClient, LdapScope
from flext_ldap.config import (
    FlextLDAPConfig,
    get_flext_ldap_config,
    set_flext_ldap_config,
)
from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.container import FlextLDAPContainer
from flext_ldap.domain import FlextLDAPDomain
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.exceptions import FlextLDAPExceptions
from flext_ldap.operations import FlextLDAPOperations
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.services import FlextLDAPServices

# FlextLDAPConfig REMOVED: Use FlextLDAPConfig directly (no wrappers/aliases)
from flext_ldap.type_guards import FlextLDAPTypeGuards
from flext_ldap.typings import (
    FlextLDAPTypes,
    LdapAttributeDict,
    LdapAttributeValue,
    LdapSearchResult,
    TLdapAttributes,
    TLdapAttributeValue,
    TLdapEntryData,
    TLdapSearchResult,
)
from flext_ldap.value_objects import FlextLDAPValueObjects

_vermod = _importlib.import_module("flext_ldap.__version__")


def __getattr__(name: str) -> str:  # pragma: no cover
    if name == "__version__":
        return str(_vermod.__version__)
    if name == "__version_info__":
        return str(_vermod.__version_info__)
    raise AttributeError(name)


# Manual __all__ definition for explicit control
__all__ = [
    "SCOPE_MAP",
    "FlextLDAPAdapters",
    "FlextLDAPApi",
    "FlextLDAPClient",
    "FlextLDAPConfig",
    "FlextLDAPConnectionConfig",
    "FlextLDAPConstants",
    "FlextLDAPContainer",
    "FlextLDAPDomain",
    "FlextLDAPEntities",
    "FlextLDAPExceptions",
    "FlextLDAPOperations",
    "FlextLDAPRepositories",
    "FlextLDAPServices",
    # "FlextLDAPConfig" REMOVED: Use FlextLDAPConfig directly
    "FlextLDAPTypeGuards",
    "FlextLDAPTypes",
    "FlextLDAPValueObjects",
    "LdapAttributeDict",
    "LdapAttributeValue",
    "LdapScope",
    "LdapSearchResult",
    "TLdapAttributeValue",
    "TLdapAttributes",
    "TLdapEntryData",
    "TLdapSearchResult",
    "get_flext_ldap_api",
    "get_flext_ldap_config",
    "set_flext_ldap_config",
]
