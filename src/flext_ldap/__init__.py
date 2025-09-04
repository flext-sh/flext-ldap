"""FLEXT LDAP - Enterprise LDAP operations library built on FLEXT Framework.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

LDAP-specific functionality extending flext-core with directory services,
authentication, user/group management, and enterprise LDAP operations.

Architecture:
    Foundation: Constants, types, exceptions
    Domain: Entities, value objects, domain logic, models
    Application: Services, operations, repositories, API
    Infrastructure: Clients, containers, configuration
    Support: Adapters, fields, type guards, CLI

Key Components:
    FlextLDAPApi: Main API entry point via get_flext_ldap_api()
    FlextLDAPServices: Service layer for user and group operations
    FlextLDAPSettings: Configuration management with environment variables
    FlextLDAPClient: Infrastructure client for LDAP server communication
    FlextLDAPEntities: Domain entities (User, Group, Entry)
    FlextLDAPConstants: All LDAP constants and defaults

Examples:
    Basic LDAP operations::

        from flext_ldap import get_flext_ldap_api

        api = get_flext_ldap_api()
        result = await api.connect(
            "ldap://server", "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "password"
        )

    User management::

        from flext_ldap import FlextLDAPServices, FlextLDAPCreateUserRequest

        service = FlextLDAPServices()
        request = FlextLDAPCreateUserRequest(dn="cn=user,dc=example,dc=com", uid="user")
        result = await service.create_user(request)

    Configuration::

        from flext_ldap import FlextLDAPSettings

        settings = FlextLDAPSettings.from_env()

Notes:
    - All LDAP operations return FlextResult[T] for type-safe error handling
    - Configuration managed through FlextLDAPSettings with environment variables
    - Uses ldap3 library for real LDAP server communication
    - Follow Clean Architecture patterns with layered imports
    - Built on flext-core foundation patterns

"""

from __future__ import annotations

import importlib.metadata

# =============================================================================
# FOUNDATION LAYER - Import first, no dependencies on other modules
# =============================================================================

from flext_ldap import constants
from flext_ldap import typings
from flext_ldap import exceptions

# =============================================================================
# DOMAIN LAYER - Depends only on Foundation layer
# =============================================================================

from flext_ldap import entities
from flext_ldap import value_objects
from flext_ldap import domain
from flext_ldap import models

# =============================================================================
# APPLICATION LAYER - Depends on Domain + Foundation layers
# =============================================================================

from flext_ldap import services
from flext_ldap import operations
from flext_ldap import repositories
from flext_ldap import api

# =============================================================================
# INFRASTRUCTURE LAYER - Depends on Application + Core + Foundation
# =============================================================================

from flext_ldap import clients
from flext_ldap import container

# configuration.py eliminated - using direct imports from settings and connection_config
from flext_ldap import connection_config
from flext_ldap import settings

# =============================================================================
# SUPPORT LAYER - Depends on layers as needed, imported last
# =============================================================================

from flext_ldap import adapters
from flext_ldap import fields
from flext_ldap import type_guards

# =============================================================================
# CLI ENTRY POINT - Main CLI functionality (optional import)
# =============================================================================

from contextlib import suppress

# CLI import disabled - using flext-cli directly where needed

# =============================================================================
# PUBLIC EXPORTS - Manual definition of all public APIs
# =============================================================================

# Import all key classes directly for explicit exports
from flext_ldap.api import FlextLDAPApi, get_flext_ldap_api
from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.entities import FlextLDAPEntities, DictEntry
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
    TLdapSearchResult
)

# Version info - handle ImportError gracefully
try:
    __version__ = importlib.metadata.version("flext-ldap")
except importlib.metadata.PackageNotFoundError:
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
    "DictEntry",
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
