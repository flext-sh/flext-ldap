"""Copyright (c) 2025 FLEXT Team. All rights reserved.

SPDX-License-Identifier: MIT.
"""

from __future__ import annotations
from flext_core import FlextTypes


"""FLEXT LDAP - Enterprise LDAP operations library built on FLEXT Framework.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


import importlib.metadata


from flext_ldap import constants
from flext_ldap import typings
from flext_ldap import exceptions


from flext_ldap import entities
from flext_ldap import value_objects
from flext_ldap import domain
from flext_ldap import models


from flext_ldap import services
from flext_ldap import operations
from flext_ldap import repositories
from flext_ldap import api


from flext_ldap import clients
from flext_ldap import container

# configuration.py eliminated - using direct imports from settings and connection_config
from flext_ldap import connection_config
from flext_ldap import settings


from flext_ldap import adapters
from flext_ldap import fields
from flext_ldap import type_guards


from contextlib import suppress

# CLI import disabled - using flext-cli directly where needed

# Import all key classes directly for explicit exports
from flext_ldap.api import FlextLDAPApi, get_flext_ldap_api
from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.exceptions import FlextLDAPExceptions
from flext_ldap.models import FlextLDAPModels
from flext_ldap.services import FlextLDAPServices
from flext_ldap.clients import FlextLDAPClient, SCOPE_MAP, LdapScope
from flext_ldap.operations import FlextLDAPOperations
from flext_ldap.repositories import FlextLDAPRepositories
from flext_ldap.value_objects import FlextLDAPValueObjects
from flext_ldap.domain import FlextLDAPDomain
from flext_ldap.container import FlextLDAPContainer
from flext_ldap.settings import FlextLDAPSettings
from flext_ldap.adapters import FlextLDAPAdapters
from flext_ldap.fields import FlextLDAPFields
from flext_ldap.type_guards import FlextLDAPTypeGuards
from flext_ldap.typings import (
    FlextLDAPTypes,
    LdapAttributeDict,
    LdapAttributeValue,
    LdapSearchResult,
    TLdapAttributeValue,
    TLdapAttributes,
    TLdapEntryData,
    TLdapSearchResult,
)

# Version info
__version__ = "0.9.0"
__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())
# Manual __all__ definition for explicit control
__all__ = [
    # Version and metadata
    "__version__",
    "__version_info__",
    # Foundation Layer
    "FlextLDAPConstants",
    "FlextLDAPTypes",
    "LdapAttributeDict",
    "LdapAttributeValue",
    "LdapSearchResult",
    "TLdapAttributeValue",
    "TLdapAttributes",
    "TLdapEntryData",
    "TLdapSearchResult",
    "FlextLDAPExceptions",
    # Domain Layer
    "FlextLDAPEntities",
    "FlextLDAPValueObjects",
    "FlextLDAPDomain",
    "FlextLDAPModels",
    # Application Layer
    "FlextLDAPServices",
    "FlextLDAPOperations",
    "FlextLDAPRepositories",
    "FlextLDAPApi",
    "get_flext_ldap_api",
    # Infrastructure Layer
    "SCOPE_MAP",
    "FlextLDAPClient",
    "LdapScope",
    "FlextLDAPContainer",
    "FlextLDAPConnectionConfig",
    "FlextLDAPSettings",
    # Support Layer
    "FlextLDAPAdapters",
    "FlextLDAPFields",
    "FlextLDAPTypeGuards",
]
