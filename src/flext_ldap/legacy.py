"""Legacy compatibility facade for flext-ldap.

This module provides backward compatibility for APIs that may have been refactored
or renamed during the Pydantic modernization process. It follows the same pattern
as flext-core's legacy.py to ensure consistent facade patterns across the ecosystem.

All imports here should be considered deprecated and may issue warnings.
Modern code should import directly from the appropriate modules.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

# Import modern implementations to re-export under legacy names
from flext_ldap.api import FlextLdapApi, get_ldap_api
from flext_ldap.config import FlextLdapConfig
from flext_ldap.entities import FlextLdapEntry, FlextLdapGroup, FlextLdapUser
from flext_ldap.exceptions import (
    FlextLdapAuthenticationError,
    FlextLdapConnectionError,
    FlextLdapException,
    FlextLdapSearchError,
)


def _deprecation_warning(old_name: str, new_name: str) -> None:
    """Issue a deprecation warning for legacy imports."""
    warnings.warn(
        f"{old_name} is deprecated, use {new_name} instead",
        DeprecationWarning,
        stacklevel=3,
    )


# Legacy aliases for main classes - commonly used names
def LDAPClient(*args: object, **kwargs: object) -> FlextLdapApi:
    """Legacy alias for FlextLdapApi."""
    _deprecation_warning("LDAPClient", "FlextLdapApi")
    return FlextLdapApi(*args, **kwargs)


def LdapClient(*args: object, **kwargs: object) -> FlextLdapApi:
    """Legacy alias for FlextLdapApi."""
    _deprecation_warning("LdapClient", "FlextLdapApi")
    return FlextLdapApi(*args, **kwargs)


def LDAPConfig(*args: object, **kwargs: object) -> FlextLdapConfig:
    """Legacy alias for FlextLdapConfig."""
    _deprecation_warning("LDAPConfig", "FlextLdapConfig")
    return FlextLdapConfig(*args, **kwargs)


def LdapConfig(*args: object, **kwargs: object) -> FlextLdapConfig:
    """Legacy alias for FlextLdapConfig."""
    _deprecation_warning("LdapConfig", "FlextLdapConfig")
    return FlextLdapConfig(*args, **kwargs)


# Legacy aliases for domain entities
def LDAPUser(*args: object, **kwargs: object) -> FlextLdapUser:
    """Legacy alias for FlextLdapUser."""
    _deprecation_warning("LDAPUser", "FlextLdapUser")
    return FlextLdapUser(*args, **kwargs)


def LdapUser(*args: object, **kwargs: object) -> FlextLdapUser:
    """Legacy alias for FlextLdapUser."""
    _deprecation_warning("LdapUser", "FlextLdapUser")
    return FlextLdapUser(*args, **kwargs)


def LDAPGroup(*args: object, **kwargs: object) -> FlextLdapGroup:
    """Legacy alias for FlextLdapGroup."""
    _deprecation_warning("LDAPGroup", "FlextLdapGroup")
    return FlextLdapGroup(*args, **kwargs)


def LdapGroup(*args: object, **kwargs: object) -> FlextLdapGroup:
    """Legacy alias for FlextLdapGroup."""
    _deprecation_warning("LdapGroup", "FlextLdapGroup")
    return FlextLdapGroup(*args, **kwargs)


def LDAPEntry(*args: object, **kwargs: object) -> FlextLdapEntry:
    """Legacy alias for FlextLdapEntry."""
    _deprecation_warning("LDAPEntry", "FlextLdapEntry")
    return FlextLdapEntry(*args, **kwargs)


def LdapEntry(*args: object, **kwargs: object) -> FlextLdapEntry:
    """Legacy alias for FlextLdapEntry."""
    _deprecation_warning("LdapEntry", "FlextLdapEntry")
    return FlextLdapEntry(*args, **kwargs)


# Legacy exception aliases (more concise names that were probably used)
def LDAPException(*args: object, **kwargs: object) -> FlextLdapException:
    """Legacy alias for FlextLdapException."""
    _deprecation_warning("LDAPException", "FlextLdapException")
    return FlextLdapException(*args, **kwargs)


def LdapException(*args: object, **kwargs: object) -> FlextLdapException:
    """Legacy alias for FlextLdapException."""
    _deprecation_warning("LdapException", "FlextLdapException")
    return FlextLdapException(*args, **kwargs)


def ConnectionError(*args: object, **kwargs: object) -> FlextLdapConnectionError:
    """Legacy alias for FlextLdapConnectionError."""
    _deprecation_warning("ConnectionError", "FlextLdapConnectionError")
    return FlextLdapConnectionError(*args, **kwargs)


def AuthenticationError(*args: object, **kwargs: object) -> FlextLdapAuthenticationError:
    """Legacy alias for FlextLdapAuthenticationError."""
    _deprecation_warning("AuthenticationError", "FlextLdapAuthenticationError")
    return FlextLdapAuthenticationError(*args, **kwargs)


def SearchError(*args: object, **kwargs: object) -> FlextLdapSearchError:
    """Legacy alias for FlextLdapSearchError."""
    _deprecation_warning("SearchError", "FlextLdapSearchError")
    return FlextLdapSearchError(*args, **kwargs)


# Legacy function aliases
def get_ldap_client(*args: object, **kwargs: object) -> FlextLdapApi:
    """Legacy alias for get_ldap_api."""
    _deprecation_warning("get_ldap_client", "get_ldap_api")
    return get_ldap_api(*args, **kwargs)


def create_ldap_client(*args: object, **kwargs: object) -> FlextLdapApi:
    """Legacy alias for get_ldap_api."""
    _deprecation_warning("create_ldap_client", "get_ldap_api")
    return get_ldap_api(*args, **kwargs)


# Export legacy aliases for backward compatibility
__all__ = [
    "AuthenticationError",
    "ConnectionError",
    "LDAPClient",
    "LDAPConfig",
    "LDAPEntry",
    "LDAPException",
    "LDAPGroup",
    "LDAPUser",
    "LdapClient",
    "LdapConfig",
    "LdapEntry",
    "LdapException",
    "LdapGroup",
    "LdapUser",
    "SearchError",
    "create_ldap_client",
    "get_ldap_client",
]
