"""LDAP configuration models following flext-core patterns."""

from typing import Final

from flext_core import FlextLogger

from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.settings import (
    FlextLDAPAuthConfig,
    FlextLDAPLoggingConfig,
    FlextLDAPSearchConfig,
    FlextLDAPSettings,
)

logger = FlextLogger(__name__)

# Constants
MAX_PORT: Final[int] = 65535


# All configuration classes moved to settings.py (facade imports above)


# FlextLDAPSettings moved to settings.py (facade import above)


# Factory functions moved to settings.py with FlextLDAPSettings class

# Export all imported classes for backward compatibility
__all__ = [
    "FlextLDAPAuthConfig",
    "FlextLDAPConnectionConfig",
    "FlextLDAPLoggingConfig",
    "FlextLDAPSearchConfig",
    "FlextLDAPSettings",
]
