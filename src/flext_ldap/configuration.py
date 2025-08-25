"""LDAP configuration models following flext-core patterns."""


# Legacy facade imports for backward compatibility
from typing import Final

from flext_core import get_logger

from .connection_config import FlextLdapConnectionConfig
from .settings import (
    FlextLdapAuthConfig,
    FlextLdapLoggingConfig,
    FlextLdapSearchConfig,
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

logger = get_logger(__name__)

# Constants
MAX_PORT: Final[int] = 65535


# All configuration classes moved to settings.py (facade imports above)


# FlextLdapSettings moved to settings.py (facade import above)


# Factory functions moved to settings.py with FlextLdapSettings class

# Export all imported classes for backward compatibility
__all__ = [
    "FlextLdapAuthConfig",
    "FlextLdapConnectionConfig",
    "FlextLdapLoggingConfig",
    "FlextLdapSearchConfig",
    "FlextLdapSettings",
    "create_development_config",
    "create_production_config",
    "create_test_config",
]
