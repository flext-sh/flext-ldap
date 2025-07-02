"""FLEXT LDAP - API PRINCIPAL LIMPA E ORGANIZADA.

Interface unificada e LIMPA seguindo rigorosamente KISS/SOLID/DRY
"""

from __future__ import annotations

from typing import Any

# Version information
try:
    from flext_ldap.__version__ import __version__
except ImportError:
    __version__ = "2.0.0"  # Fallback version

__title__ = "flext-ldap"
__description__ = "Complete LDAP framework with clean organized API"
__author__ = "FLEXT Team"


# Core functionality - lazy imports to avoid circular dependencies
def get_config():
    """Get Config class."""
    try:
        from flext_ldap.config.application_config import ApplicationConfig as Config

        return Config
    except ImportError:
        return None


def get_ldap():
    """Get LDAP client class."""
    try:
        from flext_ldap.connections.base import LDAP

        return LDAP
    except ImportError:
        return None


def connect(*args, **kwargs: Any):
    """Connect to LDAP server."""
    try:
        from flext_ldap.connections.base import connect

        return connect(*args, **kwargs)
    except ImportError:
        msg = "LDAP connection module not available"
        raise ImportError(msg)


# Lazy loading for major components
def __getattr__(name: str):
    """Lazy loading of modules to avoid circular imports."""
    if name == "Config":
        from flext_ldap.config.application_config import ApplicationConfig as Config

        return Config
    if name == "LDAP":
        from flext_ldap.connections.base import LDAP

        return LDAP
    if name == "Query":
        try:
            from flext_ldap.queries import Query

            return Query
        except ImportError:
            return None
    elif name == "Result":
        from flext_ldap.domain.results import Result

        return Result
    else:
        msg = f"module '{__name__}' has no attribute '{name}'"
        raise AttributeError(msg)


# Essential exports for compatibility
__all__ = [
    "LDAP",
    "Config",
    "Query",
    "Result",
    "__version__",
    "connect",
]
