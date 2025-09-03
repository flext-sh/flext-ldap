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

from flext_ldap.constants import *
from flext_ldap.typings import *
from flext_ldap.exceptions import *

# =============================================================================
# DOMAIN LAYER - Depends only on Foundation layer
# =============================================================================

from flext_ldap.entities import *
from flext_ldap.value_objects import *
from flext_ldap.domain import *
from flext_ldap.models import *

# =============================================================================
# APPLICATION LAYER - Depends on Domain + Foundation layers
# =============================================================================

from flext_ldap.services import *
from flext_ldap.operations import *
from flext_ldap.repositories import *
from flext_ldap.api import *

# =============================================================================
# INFRASTRUCTURE LAYER - Depends on Application + Core + Foundation
# =============================================================================

from flext_ldap.clients import *
from flext_ldap.container import *

# configuration.py eliminated - using direct imports from settings and connection_config
from flext_ldap.connection_config import *
from flext_ldap.settings import *

# =============================================================================
# SUPPORT LAYER - Depends on layers as needed, imported last
# =============================================================================

from flext_ldap.adapters import *
from flext_ldap.fields import *
from flext_ldap.type_guards import *

# =============================================================================
# CLI ENTRY POINT - Main CLI functionality (optional import)
# =============================================================================

from contextlib import suppress

with suppress(ImportError):
    from flext_ldap.cli import *

# =============================================================================
# CONSOLIDATED EXPORTS - Combine all __all__ from modules
# =============================================================================

# Combine all __all__ exports from imported modules
import flext_ldap.adapters as _adapters
import flext_ldap.api as _api
import flext_ldap.clients as _clients

# _configuration removed - using direct module imports
import flext_ldap.connection_config as _connection_config
import flext_ldap.constants as _constants
import flext_ldap.container as _container
import flext_ldap.domain as _domain
import flext_ldap.entities as _entities
import flext_ldap.exceptions as _exceptions
import flext_ldap.fields as _fields
import flext_ldap.models as _models
import flext_ldap.operations as _operations
import flext_ldap.repositories as _repositories
import flext_ldap.services as _services
import flext_ldap.settings as _settings
import flext_ldap.type_guards as _type_guards
import flext_ldap.typings as _typings
import flext_ldap.value_objects as _value_objects

# Collect all __all__ exports from imported modules
_temp_exports: list[str] = []

for module in [
    _constants,
    _typings,
    _exceptions,
    _entities,
    _value_objects,
    _domain,
    _models,
    _services,
    _operations,
    _repositories,
    _api,
    _clients,
    _container,
    # _configuration removed
    _connection_config,
    _settings,
    _adapters,
    _fields,
    _type_guards,
]:
    if hasattr(module, "__all__"):
        _temp_exports.extend(module.__all__)

# Try to include CLI exports if available
try:
    import flext_ldap.cli as _cli

    if hasattr(_cli, "__all__"):
        _temp_exports.extend(_cli.__all__)
except ImportError:
    pass

# Remove duplicates and sort for consistent exports
_seen: set[str] = set()
_final_exports: list[str] = []
for item in _temp_exports:
    if item not in _seen:
        _seen.add(item)
        _final_exports.append(item)
_final_exports.sort()

# Version info - handle ImportError gracefully
try:
    __version__ = importlib.metadata.version("flext-ldap")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.9.0"

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Add version info to exports
_final_exports.extend(["__version__", "__version_info__"])

# Define __all__ as tuple for linter compatibility
__all__ = tuple(sorted(set(_final_exports)))
