"""FLEXT LDAP - Enterprise LDAP Directory Integration Library.

Clean Architecture implementation for LDAP operations with SOLID principles.
Built on flext-core foundation for consistent error handling and service management.

Example:
    >>> from flext_ldap import FlextLdapApi, FlextLdapCreateUserRequest
    >>> api = FlextLdapApi()
    >>> # Use api for LDAP operations

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.api import FlextLdapApi, get_ldap_api
from flext_ldap.constants import FlextLdapScope as _ConstantsLdapScope
from flext_ldap.constants import (
    FlextLdapProtocolConstants,
    FlextLdapConnectionConstants,
    FlextLdapAttributeConstants,
    FlextLdapObjectClassConstants,
)

from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings

from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapGroup,
    FlextLdapUser,
)

from flext_ldap.services import FlextLdapService

from flext_ldap.infrastructure import FlextLdapClient

from flext_ldap.exceptions import FlextLdapException, FlextLdapUserError

from flext_ldap.utils import (
    flext_ldap_validate_dn,
    flext_ldap_validate_attribute_name,
    flext_ldap_validate_attribute_value,
    flext_ldap_sanitize_attribute_name,
)

# Public API
__all__ = [
    # Core API
    "FlextLdapApi",
    "get_ldap_api",
    # Configuration
    "FlextLdapConnectionConfig",
    "FlextLdapSettings",
    # Domain Models
    "FlextLdapEntry",
    "FlextLdapUser",
    "FlextLdapGroup",
    "FlextLdapCreateUserRequest",
    "FlextLdapDistinguishedName",
    "FlextLdapScope",
    # Constants (selective export)
    "FlextLdapProtocolConstants",
    "FlextLdapConnectionConstants",
    "FlextLdapAttributeConstants",
    "FlextLdapObjectClassConstants",
    "FlextLdapFilter",
    # Services
    "FlextLdapService",
    # Infrastructure
    "FlextLdapClient",
    # Exceptions
    "FlextLdapException",
    "FlextLdapUserError",
    # Utilities
    "flext_ldap_validate_dn",
    "flext_ldap_validate_attribute_name",
    "flext_ldap_validate_attribute_value",
    "flext_ldap_sanitize_attribute_name",
]

# Backward-compat exposed scope
FlextLdapScope = _ConstantsLdapScope
